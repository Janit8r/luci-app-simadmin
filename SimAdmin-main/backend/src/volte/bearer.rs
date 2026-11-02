//! IMS PDN（APN=ims）承载：qmicli 优先，裸 QMUX 降级。
//!
//! 两条通道拿到的东西完全一致：本机 IPv6 地址 / 前缀 / 网关 / P-CSCF 候选。
//! 之后的接口配置与主机路由都走 `/sbin/ip`（pcscf::route_commands）。
//!
//! 为什么需要两条：
//! - OpenWrt 上 `qmicli` 通常已随 `qmi-utils` 安装，且能用 `--device-open-proxy`
//!   与 ModemManager 共存，是最省事的一条；
//! - 但精简固件（或 qmicli 版本不认 `--wds-start-network` 的某些参数）时，
//!   自有 QMUX 客户端是唯一退路——设备侧实测过的那套 TLV 序列。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::time::Duration;

use super::qmi_raw::Qmux;
use super::{err, ip_bin, pcscf};

/// 承载建立参数。
#[derive(Debug, Clone)]
pub struct BearerConfig {
    /// IMS APN。留空则用 `ims.epc.mncXXX.mccXXX.gprs`（由 identity 生成）。
    pub apn: String,
    /// QMI profile 索引（0 = 不用 profile，直接下发 APN）。
    pub profile: Option<u8>,
    /// mux 数据口：2 → 与 default-attach（mux1）分开。
    pub mux: u8,
    /// 接口名覆盖（留空自动探测）。
    pub interface: Option<String>,
    /// P-CSCF 覆盖（留空自动发现）。
    pub pcscf: Option<IpAddr>,
}

impl Default for BearerConfig {
    fn default() -> Self {
        Self {
            apn: String::new(),
            profile: None,
            mux: 2,
            interface: None,
            pcscf: None,
        }
    }
}

/// 承载来源，写进日志便于判断走了哪条通道。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerSource {
    Qmicli,
    RawQmux,
}

impl BearerSource {
    pub fn as_str(self) -> &'static str {
        match self {
            BearerSource::Qmicli => "qmicli",
            BearerSource::RawQmux => "raw_qmux",
        }
    }
}

/// 建立好的 IMS 承载。
#[derive(Debug, Clone)]
pub struct ImsBearer {
    pub interface: String,
    pub local: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
    pub pcscf: Vec<IpAddr>,
    pub source: BearerSource,
    pub apn: String,
}

impl ImsBearer {
    pub fn family(&self) -> super::ImsFamily {
        match self.local {
            IpAddr::V4(_) => super::ImsFamily::V4,
            IpAddr::V6(_) => super::ImsFamily::V6,
        }
    }

    /// 供 pcscf::route_commands 使用的地址描述。
    pub fn addressing(&self) -> pcscf::ImsBearerAddressing {
        pcscf::ImsBearerAddressing {
            interface: self.interface.clone(),
            local: self.local,
            prefix: self.prefix,
            gateway: self.gateway,
        }
    }
}

/// 单次承载尝试的中间结果。
#[derive(Debug, Clone, Default)]
pub struct BearerRaw {
    local: Option<IpAddr>,
    prefix: u8,
    gateway: Option<IpAddr>,
    pcscf: Vec<IpAddr>,
    /// qmicli 输出的原始文本（解析 P-CSCF 兜底用）。
    pcscf_hint: Vec<IpAddr>,
}

/// 建立 IMS 承载（阻塞，调用方用 `spawn_blocking` 包起来）。
///
/// 顺序：qmicli → 裸 QMUX。两条都失败时返回汇总错误，便于日志定位。
pub fn bring_up(cfg: &BearerConfig) -> Result<ImsBearer, String> {
    let mut errors: Vec<String> = Vec::new();

    let qmicli = qmicli_bring_up(cfg);
    match qmicli {
        Ok(raw) => {
            if let Some(bearer) = finish(cfg, raw, BearerSource::Qmicli, &mut errors) {
                return Ok(bearer);
            }
        }
        Err(e) => {
            errors.push(format!("qmicli: {e}"));
            tracing::warn!(target: "simadmin::volte", error = %e, "IMS 承载 qmicli 通道失败，降级裸 QMUX");
        }
    }

    match raw_qmux_bring_up(cfg) {
        Ok(raw) => {
            if let Some(bearer) = finish(cfg, raw, BearerSource::RawQmux, &mut errors) {
                return Ok(bearer);
            }
        }
        Err(e) => errors.push(format!("raw_qmux: {e}")),
    }

    Err(format!(
        "{}: {}",
        err::BEARER_UNAVAILABLE,
        errors.join("; ")
    ))
}

fn finish(
    cfg: &BearerConfig,
    raw: BearerRaw,
    source: BearerSource,
    errors: &mut Vec<String>,
) -> Option<ImsBearer> {
    let local = match raw.local {
        Some(addr) => addr,
        None => {
            errors.push(format!("{}: 未拿到本机地址", source.as_str()));
            return None;
        }
    };
    let interface = match detect_interface(cfg, local) {
        Ok(iface) => iface,
        Err(e) => {
            errors.push(format!("{}: {e}", source.as_str()));
            return None;
        }
    };
    // IPv4 承载上默认前缀 64 是非法的，按家族夹一下。
    let prefix = match local {
        IpAddr::V4(_) => raw.prefix.min(32),
        IpAddr::V6(_) => raw.prefix.min(128),
    };
    if let Err(e) = apply_addressing(&interface, local, prefix, raw.gateway) {
        errors.push(format!("{}: {e}", source.as_str()));
        return None;
    }

    let mut candidates = Vec::new();
    if let Some(explicit) = cfg.pcscf {
        candidates.push(explicit);
    }
    for addr in raw.pcscf.iter().chain(raw.pcscf_hint.iter()) {
        if !candidates.contains(addr) {
            candidates.push(*addr);
        }
    }
    for addr in discover_pcscf_via_at(cfg) {
        if !candidates.contains(&addr) {
            candidates.push(addr);
        }
    }
    // 同族过滤：P-CSCF 必须与承载同族，否则路由装不上。
    let family = match local {
        IpAddr::V4(_) => super::ImsFamily::V4,
        IpAddr::V6(_) => super::ImsFamily::V6,
    };
    let filtered: Vec<IpAddr> = candidates
        .into_iter()
        .filter(|addr| matches!((addr, family), (IpAddr::V4(_), super::ImsFamily::V4) | (IpAddr::V6(_), super::ImsFamily::V6)))
        .collect();

    // 运营商经常不在 QMI/AT 里下发 P-CSCF。联通实测：`--wds-get-current-settings`
    // 完全没有 0x1F（P-CSCF）TLV，`AT+CGCONTRDP` 只列默认承载的 cid 1，
    // 于是上面三条来源全是空的。兜底办法是直接在 IMS 承载所在 /24 里探 SIP：
    // 谁回 `SIP/2.0` 就认为谁是 P-CSCF。
    let filtered = if filtered.is_empty() {
        match probe_pcscf(local) {
            Some(addr) => {
                tracing::info!(
                    target: "simadmin::volte",
                    pcscf = %addr,
                    "QMI/AT 未下发 P-CSCF，改由网段探测得到"
                );
                vec![addr]
            }
            None => filtered,
        }
    } else {
        filtered
    };

    Some(ImsBearer {
        interface,
        local,
        prefix,
        gateway: raw.gateway,
        pcscf: filtered,
        source,
        apn: cfg.apn.clone(),
    })
}

// ---------------------------------------------------------------------------
// 通道一：qmicli
// ---------------------------------------------------------------------------

fn qmicli_bring_up(cfg: &BearerConfig) -> Result<BearerRaw, String> {
    // IMS APN 给 IPv6 才谈得上 3GPP IPsec（TS 33.203 假定 IPv6 承载），
    // 但个别省份/省份漫游时只给 IPv4，所以先 6 后 4 各试一次。
    let mut errors = Vec::new();
    for ip_type in ["6", "4"] {
        match qmicli_bring_up_family(cfg, ip_type) {
            Ok(raw) => return Ok(raw),
            Err(e) => errors.push(format!("ip-type={ip_type}: {e}")),
        }
    }
    Err(errors.join("; "))
}

fn qmicli_bring_up_family(cfg: &BearerConfig, ip_type: &str) -> Result<BearerRaw, String> {
    let device = find_qmi_device().ok_or_else(|| err::QMI_DEVICE_MISSING.to_string())?;

    // 1) 拿一个不释放的 WDS 客户端 id。
    let out = run_qmicli(&device, &["--wds-noop", "--client-no-release-cid"])?;
    let cid = parse_qmicli_cid(&out).ok_or_else(|| "qmicli 未返回 CID".to_string())?;

    // 2) 绑定 mux。
    //
    // bam-dmux / qmap 设备上默认数据口已经占用了「未绑定」的通道，此时直接
    // start-network 会被 QMI 以 PolicyMismatch(79) 拒绝（旧实现走 mmcli
    // simple-connect 就是死在这里）。先绑 mux，让 IMS PDN 落到独立数据口。
    //
    // 参数形态随 libqmi 版本不同：
    //   qmicli >= 1.30 只认 `--wds-bind-mux-data-port="mux-id=N,ep-type=...,ep-iface-number=N"`
    //   （实测 1.38 里根本没有 `--wds-bind-mux-id`）
    // 内嵌 modem（bam-dmux）必须带 endpoint 信息，否则驱动不认。
    let bind_variants = [
        format!(
            "--wds-bind-mux-data-port=mux-id={mux},ep-type=bam-dmux,ep-iface-number={mux}",
            mux = cfg.mux
        ),
        format!(
            "--wds-bind-mux-data-port=mux-id={mux},ep-type=embedded,ep-iface-number={mux}",
            mux = cfg.mux
        ),
        format!("--wds-bind-mux-data-port=mux-id={}", cfg.mux),
        format!("--wds-bind-mux-id={}", cfg.mux),
    ];
    let mut bound = false;
    for variant in bind_variants.iter() {
        if run_qmicli(
            &device,
            &[&format!("--client-cid={cid}"), "--client-no-release-cid", variant],
        )
        .is_ok()
        {
            bound = true;
            break;
        }
    }
    if !bound {
        tracing::warn!(
            target: "simadmin::volte",
            mux = cfg.mux,
            "qmicli bind-mux 全部形态都被拒绝，按默认数据口继续"
        );
    }

    // 3) 拉起 PDN。
    let network = format!(
        "apn={},ip-type={ip_type}",
        if cfg.apn.is_empty() { "ims" } else { cfg.apn.as_str() }
    );
    let start = format!("--wds-start-network={network}");
    let out = run_qmicli(
        &device,
        &[&format!("--client-cid={cid}"), "--client-no-release-cid", &start],
    )?;
    if !out.to_ascii_lowercase().contains("network started") {
        return Err(format!("qmicli start-network 未确认: {}", first_line(&out)));
    }

    // 4) 读动态参数。
    let settings = run_qmicli(
        &device,
        &[&format!("--client-cid={cid}"), "--client-no-release-cid", "--wds-get-current-settings"],
    )?;

    let mut raw = parse_qmicli_settings(&settings);
    raw.pcscf_hint = parse_pcscf_lines(&settings);
    if raw.local.is_none() {
        // 拿到了 "network started" 但没地址（家族不匹配），交给上一层换家族重试。
        return Err("qmicli 未拿到本机地址".to_string());
    }
    Ok(raw)
}

fn run_qmicli(device: &str, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new("qmicli");
    command.arg("-d").arg(device).arg("--device-open-proxy");
    for arg in args {
        command.arg(arg);
    }
    let output = command
        .output()
        .map_err(|e| format!("qmicli 不可用: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(format!(
            "qmicli {} 失败: {}",
            args.join(" "),
            first_line(if stderr.trim().is_empty() { &stdout } else { &stderr })
        ));
    }
    Ok(stdout)
}

/// `[/dev/cdc-wdm0] Client ID not released:\n\tService: 'wds'\n\t\tCID: '1'`
pub fn parse_qmicli_cid(output: &str) -> Option<u8> {
    for line in output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("CID:") {
            let value = rest.trim().trim_matches('\'').trim_matches('"');
            if let Ok(cid) = value.parse::<u8>() {
                return Some(cid);
            }
        }
    }
    None
}

/// 解析 `--wds-get-current-settings` 的文本输出。
pub fn parse_qmicli_settings(output: &str) -> BearerRaw {
    let mut raw = BearerRaw {
        prefix: 64,
        ..Default::default()
    };
    for line in output.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().trim_matches('\'');
        match key.as_str() {
            "ipv6 address" => {
                if let Some((addr, prefix)) = split_cidr_v6(value) {
                    raw.local = Some(IpAddr::V6(addr));
                    raw.prefix = prefix;
                }
            }
            "ipv6 gateway address" => {
                if let Some((addr, _)) = split_cidr_v6(value) {
                    raw.gateway = Some(IpAddr::V6(addr));
                }
            }
            "pcscf address" => {
                for part in value.split(',') {
                    if let Some(addr) = parse_any_addr(part.trim()) {
                        if !raw.pcscf.contains(&addr) {
                            raw.pcscf.push(addr);
                        }
                    }
                }
            }
            "ipv4 address" => {
                if raw.local.is_none() {
                    if let Some((addr, _)) = value.split_once('/') {
                        if let Ok(v4) = addr.trim().parse::<Ipv4Addr>() {
                            raw.local = Some(IpAddr::V4(v4));
                        }
                    }
                }
            }
            "ipv4 gateway address" => {
                if raw.gateway.is_none() {
                    if let Ok(v4) = value.trim().parse::<Ipv4Addr>() {
                        raw.gateway = Some(IpAddr::V4(v4));
                    }
                }
            }
            _ => {}
        }
    }
    raw
}

fn parse_pcscf_lines(output: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.to_ascii_lowercase().contains("pcscf") {
            if let Some((_, value)) = line.split_once(':') {
                for part in value.split(',') {
                    if let Some(addr) = parse_any_addr(part.trim().trim_matches('\'')) {
                        if !out.contains(&addr) {
                            out.push(addr);
                        }
                    }
                }
            }
        }
    }
    out
}

fn split_cidr_v6(value: &str) -> Option<(Ipv6Addr, u8)> {
    let value = value.trim().trim_matches('\'');
    let (addr, prefix) = match value.split_once('/') {
        Some((addr, prefix)) => (addr, prefix.trim().parse::<u8>().unwrap_or(64)),
        None => (value, 64u8),
    };
    addr.parse::<Ipv6Addr>().ok().map(|a| (a, prefix))
}

fn parse_any_addr(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('\'').trim_matches('"');
    if value.is_empty() {
        return None;
    }
    if let Ok(addr) = value.parse::<IpAddr>() {
        return Some(addr);
    }
    pcscf::parse_at_addr(value)
}

// ---------------------------------------------------------------------------
// 通道二：裸 QMUX
// ---------------------------------------------------------------------------

fn raw_qmux_bring_up(cfg: &BearerConfig) -> Result<BearerRaw, String> {
    let mut qmux = Qmux::open()?;
    let wds = qmux.allocate_client(super::qmi_raw::SVC_WDS)?;
    let result = (|| -> Result<BearerRaw, String> {
        // 家族 / mux / 订阅这三步在老固件上可能直接回 NOT_SUPPORTED：
        // 缺了它们只是 PDN 可能落在默认 mux 上，不该阻断 IMS 短信。
        if let Err(error) = qmux.wds_set_ip_family_v6(wds) {
            tracing::warn!(
                target: "simadmin::volte",
                error = %error,
                "WDS set-ip-family(6) 被拒绝，按 Modem 默认家族继续"
            );
        }
        if let Err(error) = qmux.wds_bind_mux(wds, cfg.mux) {
            tracing::warn!(
                target: "simadmin::volte",
                error = %error,
                mux = cfg.mux,
                "WDS bind-mux 被拒绝，按默认数据口继续"
            );
        }
        if let Err(error) = qmux.wds_bind_subscription(wds) {
            tracing::warn!(
                target: "simadmin::volte",
                error = %error,
                "WDS bind-subscription 被拒绝，按默认订阅继续"
            );
        }
        let apn = if cfg.apn.is_empty() { "ims" } else { cfg.apn.as_str() };
        qmux.wds_start_network(wds, apn, cfg.profile)?;
        let settings = qmux.wds_current_settings(wds)?;
        let local = settings
            .ipv6
            .map(IpAddr::V6)
            .or_else(|| settings.ipv4.map(IpAddr::V4))
            .ok_or_else(|| "get-current-settings 无地址".to_string())?;
        Ok(BearerRaw {
            local: Some(local),
            prefix: settings.prefix,
            gateway: settings.gateway.map(IpAddr::V6),
            pcscf: Vec::new(),
            pcscf_hint: Vec::new(),
        })
    })();
    // 承载建立后 WDS 客户端要一直持有（释放会拆掉 PDN），所以只在失败时释放。
    if result.is_err() {
        qmux.release_client(super::qmi_raw::SVC_WDS, wds);
    }
    result
}

// ---------------------------------------------------------------------------
// 接口探测与地址配置
// ---------------------------------------------------------------------------

fn find_qmi_device() -> Option<String> {
    for index in 0..4 {
        let path = format!("/dev/cdc-wdm{index}");
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }
    None
}

/// 选择承载对应的网络接口。
///
/// 优先：显式配置 → 已带该地址的接口 → 名字带 mux 后缀（`wwan0.2`）→ wwan/rmnet 首个。
pub fn detect_interface(cfg: &BearerConfig, local: IpAddr) -> Result<String, String> {
    if let Some(iface) = cfg.interface.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(iface.to_string());
    }

    let mut candidates = list_interfaces();
    if candidates.is_empty() {
        return Err("未找到 wwan/rmnet 网络接口".to_string());
    }

    if let Some(found) = candidates.iter().find(|iface| interface_has_address(iface, local)) {
        return Ok(found.clone());
    }

    let mux_suffix = format!(".{}", cfg.mux);
    candidates.sort_by_key(|iface| {
        let muxed = if iface.ends_with(&mux_suffix) { 0 } else { 1 };
        let wireless = if iface.starts_with("wwan") { 0 } else { 1 };
        (muxed, wireless, iface.clone())
    });
    Ok(candidates.remove(0))
}

fn list_interfaces() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("wwan") || name.starts_with("rmnet") || name.starts_with("usb") {
            out.push(name);
        }
    }
    out
}

fn interface_has_address(interface: &str, local: IpAddr) -> bool {
    let Ok(ip) = ip_bin() else {
        return false;
    };
    let family = if local.is_ipv6() { "-6" } else { "-4" };
    let output = Command::new(ip)
        .args([family, "addr", "show", "dev", interface])
        .output();
    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout).contains(&local.to_string()),
        Err(_) => false,
    }
}

/// 配置接口地址（幂等）。`nodad`/`noprefixroute` 在部分 iproute2 上不可用，
/// 失败后自动退回不带这些标志的写法。
pub fn apply_addressing(
    interface: &str,
    local: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
) -> Result<(), String> {
    let ip = ip_bin()?;
    let _ = Command::new(ip).args(["link", "set", interface, "up"]).output();

    let cidr = format!("{local}/{prefix}");
    let v6 = local.is_ipv6();
    let mut args: Vec<String> = Vec::new();
    if v6 {
        args.push("-6".into());
    }
    args.extend(["addr".into(), "replace".into(), cidr.clone(), "dev".into(), interface.to_string()]);
    if v6 {
        args.push("nodad".into());
        args.push("noprefixroute".into());
    }
    if !run_ip(ip, &args)? {
        // 老 iproute2 不认识 nodad/noprefixroute。
        let mut plain: Vec<String> = Vec::new();
        if v6 {
            plain.push("-6".into());
        }
        plain.extend(["addr".into(), "replace".into(), cidr, "dev".into(), interface.to_string()]);
        run_ip(ip, &plain)?;
    }

    // 到网关的默认路由（同族才装）。
    if let Some(gateway) = gateway {
        if gateway.is_ipv6() == v6 {
            let mut route: Vec<String> = Vec::new();
            if v6 {
                route.push("-6".into());
            }
            route.extend([
                "route".into(),
                "replace".into(),
                "default".into(),
                "via".into(),
                gateway.to_string(),
                "dev".into(),
                interface.to_string(),
                "metric".into(),
                "2000".into(),
            ]);
            let _ = run_ip(ip, &route);
        }
    }
    Ok(())
}

/// 为 P-CSCF 装主机路由（走 IMS 承载，别落到 default-attach 上）。
pub fn install_pcscf_route(bearer: &ImsBearer, pcscf: IpAddr) -> Result<(), String> {
    let ip = ip_bin()?;
    let cmds = pcscf::route_commands(&bearer.addressing(), pcscf)?;
    for args in cmds {
        let args: Vec<String> = args.into_iter().skip(1).collect(); // 首个元素是 ip 路径
        let _ = run_ip(ip, &args);
    }
    Ok(())
}

fn run_ip(ip: &str, args: &[String]) -> Result<bool, String> {
    let output = Command::new(ip)
        .args(args)
        .output()
        .map_err(|e| format!("ip 执行失败: {e}"))?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    tracing::debug!(
        target: "simadmin::volte",
        args = %args.join(" "),
        error = %stderr,
        "ip 命令失败"
    );
    Ok(false)
}

/// 通过 ModemManager 的 AT 通道读 `+CGCONTRDP` 里的 P-CSCF（有 MM 时最准）。
fn discover_pcscf_via_at(cfg: &BearerConfig) -> Vec<IpAddr> {
    if cfg.pcscf.is_some() {
        return Vec::new();
    }
    let output = Command::new("mmcli")
        .args(["-m", "any", "--command=AT+CGCONTRDP"])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout).to_string();
            match pcscf::parse_cgcontrdp(&text) {
                Ok((_, _, list)) => list,
                Err(_) => Vec::new(),
            }
        }
        _ => Vec::new(),
    }
}

/// 在 IMS 承载所在 /24 里探测 P-CSCF。
///
/// 做法：从承载自己的地址发出 SIP OPTIONS（源端口临时分配），先把整个 /24
/// 打一遍再统一收包，谁回 `SIP/2.0` 就把它的源地址当作 P-CSCF。
/// 254 个包、6 秒窗口，代价可以接受；IPv6 网段太大，不扫。
fn probe_pcscf(local: IpAddr) -> Option<IpAddr> {
    let candidates = scan_candidates(local);
    if candidates.is_empty() {
        return None;
    }
    let socket = match std::net::UdpSocket::bind(std::net::SocketAddr::new(local, 0)) {
        Ok(socket) => socket,
        Err(e) => {
            tracing::warn!(target: "simadmin::volte", error = %e, "P-CSCF 探测：绑定本地地址失败");
            return None;
        }
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(300)));
    let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    let request = options_request(local, local_port);

    for addr in &candidates {
        let _ = socket.send_to(
            request.as_bytes(),
            std::net::SocketAddr::new(*addr, 5060),
        );
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    let mut buffer = [0u8; 4096];
    while std::time::Instant::now() < deadline {
        match socket.recv_from(&mut buffer) {
            Ok((len, from)) => {
                let text = String::from_utf8_lossy(&buffer[..len]);
                if text.starts_with("SIP/2.0") {
                    return Some(from.ip());
                }
            }
            Err(_) => continue,
        }
    }
    None
}

/// 承载地址所在 /24 的全部主机地址（去掉自己）。
fn scan_candidates(local: IpAddr) -> Vec<IpAddr> {
    let IpAddr::V4(v4) = local else {
        return Vec::new();
    };
    let octets = v4.octets();
    let mut out = Vec::with_capacity(254);
    for host in 1u16..=254 {
        if host as u8 == octets[3] {
            continue;
        }
        out.push(IpAddr::V4(std::net::Ipv4Addr::new(
            octets[0],
            octets[1],
            octets[2],
            host as u8,
        )));
    }
    out
}

fn options_request(local: IpAddr, port: u16) -> String {
    format!(
        "OPTIONS sip:pcscf SIP/2.0\r\n\
         Via: SIP/2.0/UDP {local}:{port};branch=z9hG4bKprobe{port}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:probe@{local}>;tag=probe\r\n\
         To: <sip:pcscf>\r\n\
         Call-ID: probe-{port}@{local}\r\n\
         CSeq: 1 OPTIONS\r\n\
         Content-Length: 0\r\n\r\n"
    )
}

/// 等待承载真正可用（地址出现在接口上）。
pub fn wait_ready(bearer: &ImsBearer, timeout: Duration) -> bool {    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if interface_has_address(&bearer.interface, bearer.local) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_qmicli_cid() {
        let out = "[/dev/cdc-wdm0] Client ID not released:\n\tService: 'wds'\n\t\tCID: '3'\n";
        assert_eq!(parse_qmicli_cid(out), Some(3));
        assert_eq!(parse_qmicli_cid("nothing"), None);
    }

    #[test]
    fn parses_ipv6_current_settings() {
        let out = "[/dev/cdc-wdm0] Current settings retrieved:\n\
                   \tIPv6 address: 2408:8556:450:ccb1:31d6:d59c:3902:3148/64\n\
                   \tIPv6 gateway address: 2408:8556:450:ccb1:c49e:1bd7:12d4:e72d\n\
                   \tPCSCF address: 2408:8142:6001:1::\n";
        let raw = parse_qmicli_settings(out);
        assert_eq!(
            raw.local,
            Some(IpAddr::V6("2408:8556:450:ccb1:31d6:d59c:3902:3148".parse().unwrap()))
        );
        assert_eq!(raw.prefix, 64);
        assert_eq!(raw.pcscf.len(), 1);
        assert_eq!(raw.pcscf[0], "2408:8142:6001:1::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parses_ipv4_settings_when_no_ipv6() {
        let out = "\tIPv4 address: 10.20.30.40/30\n\tIPv4 gateway address: 10.20.30.41\n";
        let raw = parse_qmicli_settings(out);
        assert_eq!(raw.local, Some(IpAddr::V4("10.20.30.40".parse().unwrap())));
        assert_eq!(raw.gateway, Some(IpAddr::V4("10.20.30.41".parse().unwrap())));
    }

    #[test]
    fn at_style_pcscf_is_accepted() {
        assert_eq!(
            parse_any_addr("36.8.129.66.96.1.0.1.0.0.0.0.0.0.0.0"),
            Some("2408:8142:6001:1::".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn scan_covers_whole_slash24_without_self() {
        let local: IpAddr = "10.140.149.124".parse().unwrap();
        let list = scan_candidates(local);
        // /24 里 254 个可用主机地址，去掉自己
        assert_eq!(list.len(), 253);
        assert!(!list.contains(&local), "不能把探测包发给自己");
        assert!(list.contains(&"10.140.149.125".parse::<IpAddr>().unwrap()));
        assert!(list.contains(&"10.140.149.1".parse::<IpAddr>().unwrap()));
        assert!(list.contains(&"10.140.149.254".parse::<IpAddr>().unwrap()));
        // IPv6 承载不扫（网段太大）
        assert!(scan_candidates("2408:8456:435:f02d::1".parse().unwrap()).is_empty());
    }

    #[test]
    fn options_request_is_well_formed() {
        let local: IpAddr = "10.140.149.124".parse().unwrap();
        let text = options_request(local, 47481);
        assert!(text.starts_with("OPTIONS sip:pcscf SIP/2.0\r\n"));
        assert!(text.contains("Via: SIP/2.0/UDP 10.140.149.124:47481;branch="));
        assert!(text.contains("CSeq: 1 OPTIONS"));
        assert!(text.ends_with("Content-Length: 0\r\n\r\n"));
    }
}
