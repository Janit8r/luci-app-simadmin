//! IMS / VoLTE 运行时管理器（进程内 supervisor）。
//!
//! 职责：
//! - 持有配置与运行时状态，向 `/api/volte/*` 提供快照
//! - 按需启动后台注册循环
//! - 对外暴露 `sms_capable()` 供短信发送路径判断是否走 IMS
//!
//! # 注册循环的步骤
//!
//! ```text
//! 1. 解析 SIM 身份（IMSI / 运营商 / SMSC）
//! 2. 通过 ModemManager 建 IMS 承载（APN=ims）
//! 3. 把地址/路由/MTU 下发到网卡   ← 缺这一步 SIP 出不去
//! 4. 从承载里取 P-CSCF
//! 5. 发 REGISTER，处理 401 / 200
//! ```
//!
//! 第 3 步是本实现与"依赖 NetworkManager"做法的关键差异：在 OpenWrt 上
//! 没有 NM，不自己下发就永远是 `Network unreachable`。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use zbus::{Connection, Proxy};

use crate::config::ConfigManager;
use crate::modem_manager;
use crate::models::{VolteControlResponse, VolteRuntimeStatus};
use crate::volte::bearer::{self, AddressFamily, ImsBearer};
use crate::volte::identity::ImsIdentity;
use crate::volte::runtime::RuntimeState;
use crate::volte::{codes, Phase};

const MM_SERVICE: &str = "org.freedesktop.ModemManager1";
const MM_MODEM: &str = "org.freedesktop.ModemManager1.Modem";
const MM_BEARER: &str = "org.freedesktop.ModemManager1.Bearer";

/// 默认 IMS APN。运营商若不支持该 APN，需要由配置文件覆盖。
const DEFAULT_IMS_APN: &str = "ims";

/// 一轮注册失败后的重试间隔（秒）。
const RETRY_INTERVAL_SECS: u64 = 120;
/// 连续失败时的退避上限。
///
/// 每 120 秒跑一轮完整的 AKA（qmicli 开关 UIM 逻辑通道）+ xfrm flush/add，
/// 对模组和 P-CSCF 都是不小的压力；实测连续重试会触发 P-CSCF 侧限流
/// （连明文 REGISTER 都不再回应），也会把模组拖到失联。
const RETRY_MAX_SECS: u64 = 900;

/// 一次注册成功后的常驻会话。
///
/// 承载和 SIP 套接字都必须一直活着——掉一个，短信就发不出去也收不到。
pub struct VolteSession {
    pub identity: crate::volte::identity::ImsIdentity,
    pub bearer: crate::volte::bearer::ImsBearer,
    pub registration: crate::volte::register::Registration,
}

/// VoLTE 运行时管理器。
pub struct VolteManager {
    config: Arc<ConfigManager>,
    state: Arc<Mutex<RuntimeState>>,
    /// 后台循环是否已启动，避免重复 spawn
    started: Arc<Mutex<bool>>,
    /// 主动重连信号
    reconnect_tx: Arc<Mutex<Option<tokio::sync::mpsc::Sender<()>>>>,
    /// 当前已注册的会话
    session: Arc<Mutex<Option<VolteSession>>>,
    /// 已建立的 IMS 承载。
    ///
    /// 必须跨注册重试复用：这台模组上电后**第一个** IMS 承载才会被分配到
    /// 独立的 mux 通道（wwan1），之后重建的都回落 wwan0（没有数据通路）。
    /// 所以注册失败时不能拆承载，下次直接接着用。
    cached_bearer: Arc<Mutex<Option<crate::volte::bearer::ImsBearer>>>,
}

impl VolteManager {
    pub fn new(config: Arc<ConfigManager>) -> Arc<Self> {
        Arc::new(Self {
            config,
            state: Arc::new(Mutex::new(RuntimeState::new())),
            started: Arc::new(Mutex::new(false)),
            reconnect_tx: Arc::new(Mutex::new(None)),
            session: Arc::new(Mutex::new(None)),
            cached_bearer: Arc::new(Mutex::new(None)),
        })
    }

    /// 取当前会话的克隆句柄，供短信发送使用。
    pub async fn has_session(&self) -> bool {
        self.session.lock().await.is_some()
    }

    /// 构造 `/api/volte/control` 的响应体。
    pub async fn control_response(&self) -> VolteControlResponse {
        let cfg = self.config.get_volte_config();
        let runtime = self.state.lock().await.snapshot();
        VolteControlResponse {
            config: cfg,
            runtime,
            platform_supported: cfg!(target_os = "linux"),
        }
    }

    /// 只取运行时状态，供 `/api/ims/status` 使用。
    pub async fn runtime_status(&self) -> VolteRuntimeStatus {
        self.state.lock().await.snapshot()
    }

    /// IMS 是否已注册且允许接管短信。
    pub async fn sms_capable(&self) -> bool {
        let cfg = self.config.get_volte_config();
        if !cfg.feature_enabled || !cfg.sms_enabled {
            return false;
        }
        let st = self.state.lock().await;
        st.phase() == Phase::Registered
    }

    /// 设置总开关。
    pub async fn set_feature_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut cfg = self.config.get_volte_config();
        cfg.feature_enabled = enabled;
        self.config.set_volte_config(cfg)?;
        if !enabled {
            self.state.lock().await.mark_disabled();
        }
        Ok(())
    }

    /// 设置 IMS 数据承载开关。
    pub async fn set_connection_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut cfg = self.config.get_volte_config();
        cfg.connection_enabled = enabled;
        self.config.set_volte_config(cfg)?;
        if !enabled {
            // 数据面关闭时，注册必然失效，直接降级
            self.state
                .lock()
                .await
                .mark_failed(codes::CONNECTION_DISABLED, "", RETRY_INTERVAL_SECS);
        }
        Ok(())
    }

    /// 设置 IMS 短信接管开关。
    pub async fn set_sms_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut cfg = self.config.get_volte_config();
        cfg.sms_enabled = enabled;
        self.config.set_volte_config(cfg)
    }

    /// 请求立即重连。
    pub async fn request_reconnect(&self) {
        // 注意：不要清 cached_bearer。
        //
        // 承载重建会丢掉上电后分到的 wwan1（第二个永远回落 wwan0，没有数据通路），
        // 重连只应该重跑注册流程，承载继续复用。
        self.state.lock().await.mark_reconnect();
        let guard = self.reconnect_tx.lock().await;
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(()).await;
        }
    }

    /// 启动后台 supervisor（幂等）。
    pub async fn ensure_supervisor(self: &Arc<Self>, conn: Connection) {
        let mut started = self.started.lock().await;
        if *started {
            return;
        }
        *started = true;
        drop(started);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(4);
        *self.reconnect_tx.lock().await = Some(tx);

        let me = Arc::clone(self);
        tokio::spawn(async move {
            // 首次启动稍等，让 ModemManager 把模组枚举完
            tokio::time::sleep(Duration::from_secs(10)).await;
            let mut failures: u32 = 0;
            loop {
                let cfg = me.config.get_volte_config();
                if !cfg.feature_enabled {
                    me.state.lock().await.mark_disabled();
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }

                let result = me.run_once(&conn).await;
                match result {
                    Ok(()) => {
                        failures = 0;
                        // 注册成功后进入保活等待，直到掉线或被要求重连
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(600)) => {}
                            Some(_) = rx.recv() => {
                                info!("VoLTE reconnect requested");
                            }
                        }
                    }
                    Err(e) => {
                        failures = failures.saturating_add(1);
                        // 指数退避：120s -> 240s -> 480s -> 900s（封顶）
                        let delay = RETRY_INTERVAL_SECS
                            .saturating_mul(1u64 << (failures.saturating_sub(1)).min(4))
                            .min(RETRY_MAX_SECS);
                        warn!(
                            reason = %e,
                            failures,
                            retry_in = delay,
                            "VoLTE registration attempt failed"
                        );
                        let mut st = me.state.lock().await;
                        st.mark_failed(e.code, &e.detail, delay);
                        drop(st);
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
                            Some(_) = rx.recv() => {}
                        }
                    }
                }
            }
        });
    }

    /// 执行一轮完整的注册尝试。
    async fn run_once(&self, conn: &Connection) -> Result<(), crate::volte::VolteError> {
        let cfg = self.config.get_volte_config();
        if !cfg.feature_enabled {
            return Err(crate::volte::VolteError::new(codes::FEATURE_DISABLED));
        }
        if !cfg.connection_enabled {
            return Err(crate::volte::VolteError::new(codes::CONNECTION_DISABLED));
        }

        self.state.lock().await.begin_session("modem");

        // 上一轮成功的会话先拆掉：承载和 SA 都是独占资源，留着会挡住新一轮
        if let Some(previous) = self.session.lock().await.take() {
            previous.bearer.teardown().await;
            release_ims_bearer(conn, &previous.bearer.object_path).await;
        }

        // 1. 身份
        let identity = resolve_identity(conn).await?;
        info!(
            imsi_prefix = &identity.imsi[..identity.imsi.len().min(5)],
            domain = %identity.home_domain,
            "VoLTE identity resolved"
        );

        // 2. 承载
        //
        // 必须请求 ipv4v6 而不是 ipv6：纯 IPv6 的 IMS PDN 在这台模组上
        // 会落到默认通道，地址拿得到但数据面完全不通（连网关都 ping 不到）。
        // 双栈请求才会被分配到独立的 mux 通道（wwan1），P-CSCF 才可达。
        self.state.lock().await.set_stage("bearer");

        // 优先复用上一轮留下的承载——它是上电后第一个建起来的，
        // 只有它能拿到 wwan1；重建会回落 wwan0 导致完全不通。
        if let Some(cached) = self.cached_bearer.lock().await.clone() {
            if interface_alive(&cached.interface).await {
                info!(
                    interface = %cached.interface,
                    local_ip = %cached.address,
                    "reusing existing IMS bearer"
                );
                let outcome = self.register_on_bearer(&identity, &cached).await;
                if outcome.is_ok() {
                    return Ok(());
                }
                // 注册失败也保留承载，交给下一轮继续用
                return outcome;
            }
            *self.cached_bearer.lock().await = None;
        }

        // 建 IMS 承载前必须等主数据就绪。
        //
        // 模组上电后**第一个** IMS 承载才会被分到独立 mux 通道（wwan1）；
        // 如果主数据还没拨号就抢着建，它会占掉 wwan0，之后重建永远拿不到
        // wwan1，表现为"承载连上了但 SIP 完全没响应"。
        self.state.lock().await.set_stage("wait_data");
        if !wait_for_default_route(Duration::from_secs(150)).await {
            return Err(crate::volte::VolteError::with_detail(
                codes::BEARER_ACTIVATION_FAILED,
                "no default route before IMS bearer",
            ));
        }

        // 地址族要按网络实际允许的组合试：有的卡 IMS APN 是纯 IPv6
        // （双栈请求会被拒 `pdn-ipv4-call-disallowed`），有的卡必须双栈
        // 才会被分配到独立的 mux 通道。三种都试一遍，取第一个成功的。
        let mut bearer = None;
        let mut last_err = None;
        // 顺序很重要：纯 IPv6 放第一位。有的卡 IMS APN 是 IPv6-only，
        // 先用双栈试会被拒（pdn-ipv4-call-disallowed），而这次失败会在模组侧
        // 留下半个 PDN，导致紧接着的 IPv6 尝试报 "Call failed: unknown error"。
        for family in [
            AddressFamily::V6,
            AddressFamily::V4V6,
            AddressFamily::V4,
        ] {
            match connect_ims_bearer(conn, DEFAULT_IMS_APN, family).await {
                Ok(b) => {
                    bearer = Some(b);
                    break;
                }
                Err(e) => {
                    warn!(family = family.as_str(), reason = %e, "IMS bearer attempt failed");
                    last_err = Some(e);
                    // 上一次失败的 PDN 需要时间在模组侧真正释放，
                    // 间隔太短下一次只会拿到 "Call failed: unknown error"
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        }
        let bearer = bearer.ok_or_else(|| {
            last_err.unwrap_or_else(|| crate::volte::VolteError::new(codes::BEARER_ACTIVATION_FAILED))
        })?;

        // 3~5 步放在统一作用域里：任何一步失败都要把 MM 承载释放掉。
        //
        // 不释放的后果是真机上极难排查的现象——残留的 IMS PDN 会一直占着
        // QMI 数据槽，下一次 CreateBearer 直接返回 `Call failed: unknown error`，
        // 而日志里只会看到"承载建立失败"，完全看不出是上一次没清理。
        let outcome = self.register_on_bearer(&identity, &bearer).await;
        if outcome.is_err() {
            // 注册失败时保留承载对象和地址：下一轮直接复用它，
            // 否则重建出来的承载会落到 wwan0（没有数据通路）。
            *self.cached_bearer.lock().await = Some(bearer.clone());
        }
        outcome
    }

    /// 在已就绪的承载上完成地址下发、P-CSCF 发现与注册。
    async fn register_on_bearer(
        &self,
        identity: &crate::volte::identity::ImsIdentity,
        bearer: &crate::volte::bearer::ImsBearer,
    ) -> Result<(), crate::volte::VolteError> {
        // 3. 地址下发——这一步缺失会让 SIP 完全发不出去
        self.state.lock().await.set_stage("address");
        bearer.apply().await?;
        info!(
            interface = %bearer.interface,
            local_ip = %bearer.address,
            mtu = ?bearer.mtu,
            "IMS bearer configured"
        );

        // 4. P-CSCF 候选：承载自带 → AT+CGCONTRDP → 静态兜底
        self.state.lock().await.set_stage("pcscf");
        let candidates = pcscf_candidates(bearer).await;
        let first = candidates
            .first()
            .cloned()
            .ok_or_else(|| crate::volte::VolteError::new(codes::PCSCF_MISSING))?;

        // 给每个 P-CSCF 候选装一条 /128 精确路由。
        //
        // 主数据承载如果是双栈（ipv4v6），会在 wwan0 上装 metric 10 的 IPv6
        // 默认路由，压过 IMS 承载的 wwan1（metric 100）。结果 `ip -6 route get
        // <P-CSCF>` 指向 wwan0，SIP 包根本到不了 P-CSCF（实测 100% 丢包）。
        // 加精确路由后立刻恢复（实测 25ms）。
        ensure_pcscf_routes(bearer, &candidates).await;
        self.state.lock().await.mark_bearer_up(
            &bearer.interface,
            bearer.family.as_str(),
            &bearer.address,
            Some(&first),
            "secondary_qmi_data",
        );
        debug!(count = candidates.len(), first = %first, "P-CSCF candidates");

        // 5. 注册
        self.state.lock().await.set_stage("register");
        let registration = crate::volte::register::register(identity, bearer, &candidates).await?;
        self.state.lock().await.mark_registered();
        *self.session.lock().await = Some(VolteSession {
            identity: identity.clone(),
            bearer: bearer.clone(),
            registration,
        });
        Ok(())
    }
}

/// 给 P-CSCF 候选装 /128 精确路由，避免被主数据的 IPv6 默认路由抢走。
async fn ensure_pcscf_routes(bearer: &crate::volte::bearer::ImsBearer, candidates: &[String]) {
    if bearer.family.ip_flag() != "-6" {
        return;
    }
    let Some(gateway) = bearer.gateway.as_deref().filter(|g| !g.is_empty()) else {
        return;
    };
    for candidate in candidates {
        let _ = tokio::process::Command::new("ip")
            .args([
                "-6",
                "route",
                "replace",
                &format!("{candidate}/128"),
                "via",
                gateway,
                "dev",
                &bearer.interface,
                "onlink",
                "metric",
                "50",
            ])
            .stdin(std::process::Stdio::null())
            .output()
            .await;
    }
    debug!(
        count = candidates.len(),
        interface = %bearer.interface,
        gateway = %gateway,
        "P-CSCF host routes installed"
    );
}

/// 等默认路由出现（即主数据拨号完成）。
async fn wait_for_default_route(timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(out) = tokio::process::Command::new("ip")
            .args(["route", "show", "default"])
            .stdin(std::process::Stdio::null())
            .output()
            .await
        {
            if out.status.success() && !out.stdout.is_empty() {
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// 网卡是否还在（承载被模组回收后网卡会消失）。
async fn interface_alive(iface: &str) -> bool {
    tokio::process::Command::new("ip")
        .args(["link", "show", iface])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 释放 ModemManager 里的承载对象。
///
/// 顺序：先 Disconnect 让模组回收 PDN，再 DeleteBearer 移除对象。
/// 两步都尽力而为——即使 Disconnect 失败也要尝试删除，否则对象会一直
/// 挂在 modem 上，后续 CreateBearer 会因为数据槽被占而失败。
async fn release_ims_bearer(conn: &Connection, path: &str) {
    let Ok(proxy) = Proxy::new(conn, MM_SERVICE, path, MM_BEARER).await else {
        return;
    };
    if let Err(e) = proxy.call::<_, _, ()>("Disconnect", &()).await {
        debug!(bearer = path, error = %e, "bearer disconnect failed");
    }
    // 给模组一点时间真正释放 PDN，再删对象
    tokio::time::sleep(Duration::from_millis(800)).await;
    if let Ok(modem) = modem_manager::find_modem_path(conn).await {
        if let Ok(modem_proxy) = Proxy::new(conn, MM_SERVICE, modem.as_str(), MM_MODEM).await {
            let obj = zbus::zvariant::ObjectPath::try_from(path).ok();
            if let Some(obj) = obj {
                let _ = modem_proxy
                    .call::<_, _, ()>("DeleteBearer", &(obj))
                    .await;
            }
        }
    }
}

/// 通过 `AT+CGCONTRDP` 读取 P-CSCF。
///
/// P-CSCF 不在 ModemManager 的承载属性里——它通过 QMI 的 PCO 或 DHCP
/// 下发，MM 只记录"PCSCF Address Using PCO/DHCP"这两个标志位。而
/// `AT+CGCONTRDP` 会直接给出每个上下文分配到的 P-CSCF 地址列表：
///
/// ```text
/// +CGCONTRDP: 1,5,ims,2408:8556:420:9350::/64,2408:8556:420:9350::1,,,2408:8142:6001:603::
/// ```
///
/// 第 8 个字段起是 P-CSCF（可能多个）。优先取 APN 为 `ims` 的那一行。
/// 汇总 P-CSCF 候选地址，按可信度排序。
///
/// 中国联通的网络在这台模组上**不下发 P-CSCF**：ModemManager 的承载属性里没有，
/// `AT+CGCONTRDP` 的 P-CSCF 字段也是空的，`qmicli` 又不解析 PCO。
/// 官方二进制是自己解 QMI 的 Operator Reserved PCO 才拿到的。
///
/// 因此这里做三级兜底：承载自带 → AT 查询 → 静态表。静态表里的地址来自
/// 官方二进制的实际注册报文与设备上的 ping 实测，只在中国联通网络下有效，
/// 换运营商时会被前两级覆盖。
async fn pcscf_candidates(bearer: &crate::volte::bearer::ImsBearer) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |value: &str| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return;
        }
        if !out.iter().any(|v| v == trimmed) {
            out.push(trimmed.to_string());
        }
    };

    for candidate in &bearer.pcscf {
        push(candidate);
    }
    for candidate in discover_pcscf_via_at().await {
        push(&candidate);
    }
    // 兜底：中国联通 IMS 的 P-CSCF 地址段（2408:8142:6001::/48）
    for candidate in [
        "2408:8142:6001:1005::1",
        "2408:8142:6001:603::",
        "2408:8142:6001:a01::",
        "2408:8142:6001:609::1",
    ] {
        push(candidate);
    }
    out
}

async fn discover_pcscf_via_at() -> Vec<String> {
    let output = match tokio::process::Command::new("mmcli")
        .args(["-m", "any", "--command=AT+CGCONTRDP"])
        .stdin(std::process::Stdio::null())
        .output()
        .await
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut fallback: Vec<String> = Vec::new();
    let mut ims: Vec<String> = Vec::new();

    for line in text.lines() {
        let Some(idx) = line.find("+CGCONTRDP:") else {
            continue;
        };
        let body = &line[idx + "+CGCONTRDP:".len()..];
        let fields: Vec<&str> = body.split(',').map(|f| f.trim()).collect();
        if fields.len() < 8 {
            continue;
        }
        let apn = fields.get(2).copied().unwrap_or("");
        let addrs: Vec<String> = fields[7..]
            .iter()
            .map(|s| s.trim_matches('"').trim())
            .filter(|s| !s.is_empty() && s.contains(':'))
            .map(|s| s.to_string())
            .collect();
        if addrs.is_empty() {
            continue;
        }
        if apn.eq_ignore_ascii_case("ims") {
            ims.extend(addrs);
        } else if fallback.is_empty() {
            fallback = addrs;
        }
    }

    if !ims.is_empty() {
        ims
    } else {
        fallback
    }
}

/// 解析 SIM 身份。
async fn resolve_identity(conn: &Connection) -> Result<ImsIdentity, crate::volte::VolteError> {
    let sim = modem_manager::current_sim_identity(conn)
        .await
        .ok_or_else(|| crate::volte::VolteError::new(codes::IMSI_MISSING))?;
    if sim.imsi.trim().is_empty() {
        return Err(crate::volte::VolteError::new(codes::IMSI_MISSING));
    }
    let mnc_len = bearer::mnc_length_from_operator_id(&sim.operator_id);
    // SMSC 由模组侧提供，缺失不阻断注册（仅影响发送）
    ImsIdentity::derive(&sim.imsi, mnc_len, None)
}

/// 通过 ModemManager 建立 IMS 承载并读取其配置。
async fn connect_ims_bearer(
    conn: &Connection,
    apn: &str,
    family: AddressFamily,
) -> Result<ImsBearer, crate::volte::VolteError> {
    let modem_path = modem_manager::find_modem_path(conn).await.map_err(|e| {
        crate::volte::VolteError::with_detail(codes::COMMAND_FAILED, format!("find modem: {e}"))
    })?;

    // CreateBearer(a{sv})
    let modem_proxy = Proxy::new(conn, MM_SERVICE, modem_path.as_str(), MM_MODEM)
        .await
        .map_err(|e| {
            crate::volte::VolteError::with_detail(codes::COMMAND_FAILED, format!("modem proxy: {e}"))
        })?;

    let mut props: HashMap<String, zbus::zvariant::Value<'_>> = HashMap::new();
    props.insert(
        "apn".to_string(),
        zbus::zvariant::Value::from(apn.to_string()),
    );
    props.insert(
        "ip-type".to_string(),
        zbus::zvariant::Value::from(family.mm_ip_type()),
    );

    let bearer_path: zbus::zvariant::OwnedObjectPath =
        modem_proxy.call("CreateBearer", &(props)).await.map_err(|e| {
            crate::volte::VolteError::with_detail(
                codes::BEARER_ACTIVATION_FAILED,
                format!("CreateBearer: {e}"),
            )
        })?;
    let bearer_path = bearer_path.as_str().to_string();

    let bearer_proxy = Proxy::new(conn, MM_SERVICE, bearer_path.as_str(), MM_BEARER)
        .await
        .map_err(|e| {
            crate::volte::VolteError::with_detail(codes::COMMAND_FAILED, format!("bearer proxy: {e}"))
        })?;
    if let Err(e) = bearer_proxy.call::<_, _, ()>("Connect", &()).await {
        // 连不上必须把承载对象删掉：残留对象会一直占着 QMI 数据槽，
        // 下一次 CreateBearer 只会报 "Call failed: unknown error"。
        let _ = bearer_proxy.call::<_, _, ()>("Disconnect", &()).await;
        if let Ok(modem) = modem_manager::find_modem_path(conn).await {
            if let Ok(mp) = Proxy::new(conn, MM_SERVICE, modem.as_str(), MM_MODEM).await {
                if let Ok(obj) = zbus::zvariant::ObjectPath::try_from(bearer_path.as_str()) {
                    let _ = mp.call::<_, _, ()>("DeleteBearer", &(obj)).await;
                }
            }
        }
        return Err(crate::volte::VolteError::with_detail(
            codes::BEARER_ACTIVATION_FAILED,
            format!("Bearer.Connect: {e}"),
        ));
    }

    let iface: String = bearer_proxy
        .get_property("Interface")
        .await
        .map_err(|e| {
            crate::volte::VolteError::with_detail(codes::ADDRESS_MISSING, format!("interface: {e}"))
        })?;

    // 承载配置改从 mmcli 的文本输出读取。
    //
    // MM 的 Ip4Config / Ip6Config 是 `a{sv}`，值类型混杂（字符串、整数、
    // 字符串数组），经 zvariant 转换后容易丢字段；而 `mmcli -m any -b N`
    // 的输出格式稳定、字段名固定，解析起来更可靠，也和运维手工排查时
    // 看到的信息一致。
    let index = bearer_index_from_path(&bearer_path);
    let cfg = read_bearer_config_mmcli(index).await?;

    // 双栈承载只认 IPv6 段。
    //
    // 不能"取不到 IPv6 就退回 IPv4"：后续用的是 `ip -6 addr`，把 IPv4 地址
    // 传进去会直接报 `inet6 prefix is expected rather than "10.x.x.x/29"`。
    // 网络只给了 IPv4 说明这个 PDN 不能承载 IMS 信令，应当判失败换下一种地址族。
    let prefer_v6 = matches!(family, AddressFamily::V6 | AddressFamily::V4V6);
    let pick = |key: &str| -> Option<String> {
        if prefer_v6 {
            cfg.get(&format!("v6.{key}")).cloned()
        } else {
            cfg.get(key).cloned()
        }
    };

    let address = pick("address")
        .ok_or_else(|| crate::volte::VolteError::new(codes::ADDRESS_MISSING))?;
    let prefix: u8 = pick("prefix")
        .and_then(|v| v.parse().ok())
        .unwrap_or(if prefer_v6 { 64 } else { 32 });
    let gateway = pick("gateway").filter(|g| !g.is_empty());
    let mtu: Option<u32> = pick("mtu")
        .and_then(|v| v.parse().ok())
        .or_else(|| cfg.get("mtu").and_then(|v| v.parse().ok()));
    let pcscf = bearer::extract_pcscf(&cfg);

    Ok(ImsBearer {
        object_path: bearer_path,
        interface: iface,
        family,
        address,
        prefix,
        gateway,
        mtu,
        pcscf,
    })
}

/// 从 `/org/freedesktop/ModemManager1/Bearer/6` 取出序号 6。
fn bearer_index_from_path(path: &str) -> u32 {
    path.rsplit('/').next().and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// 解析 `mmcli -m any -b <n>` 的输出。
///
/// 典型片段：
/// ```text
///   Status             |      connected: yes
///                      |      interface: wwan0
///   Properties         |            apn: ims
///                      |        ip type: ipv6
///                      |        address: 2408:8556:...
///                      |         prefix: 64
///                      |        gateway: 2408:8556:...
///                      |            mtu: 1432
/// ```
async fn read_bearer_config_mmcli(
    index: u32,
) -> Result<HashMap<String, String>, crate::volte::VolteError> {
    let output = tokio::process::Command::new("mmcli")
        .args(["-m", "any", "-b", &index.to_string()])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| {
            crate::volte::VolteError::with_detail(codes::COMMAND_FAILED, format!("mmcli: {e}"))
        })?;
    if !output.status.success() {
        return Err(crate::volte::VolteError::with_detail(
            codes::COMMAND_FAILED,
            "mmcli bearer query failed",
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = HashMap::new();
    // 双栈承载会同时出现 "IPv4 configuration" 与 "IPv6 configuration" 两段，
    // 段内字段名完全相同（address/prefix/gateway/mtu）。必须按段区分，
    // 否则拿到的是 IPv4 的地址，配到 `ip -6 addr` 上直接失败。
    let mut section = String::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("ipv6 configuration") || lower.contains("ipv4v6 configuration") {
            section = "v6".to_string();
        } else if lower.contains("ipv4 configuration") {
            section = "v4".to_string();
        } else if lower.contains("properties")
            || lower.contains("status")
            || lower.contains("statistics")
            || lower.contains("3gpp")
        {
            section.clear();
        }

        // 只取 `key: value` 形态，跳过分隔线与分组标题
        let Some((left, right)) = line.split_once(':') else {
            continue;
        };
        let key = left
            .rsplit('|')
            .next()
            .unwrap_or(left)
            .trim()
            .to_ascii_lowercase();
        let value = right.trim().to_string();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        // 首次出现优先，避免后面 Stats 段同名字段覆盖
        out.entry(key.clone()).or_insert_with(|| value.clone());
        if !section.is_empty() {
            out.entry(format!("{section}.{key}"))
                .or_insert_with(|| value.clone());
        }
    }
    Ok(out)
}

