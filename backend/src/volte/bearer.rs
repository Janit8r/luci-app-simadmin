//! IMS 数据承载（APN=`ims`）的建立、地址下发与回收。
//!
//! # 为什么需要这个模块
//!
//! ModemManager 只负责在 D-Bus 上报告"承载已连接、地址是 X"。它**不会**
//! 把地址配置到网卡——那件事传统上由 NetworkManager 代劳。在没有
//! NetworkManager 的环境（OpenWrt、精简 Debian）里，如果不自己下发，
//! 内核侧接口只有 `fe80::` 链路本地地址、没有默认路由，SIP 报文连协议栈
//! 都出不去，表现为 `sendto: Network unreachable`，最终退化成
//! `volte_udp_recv_timeout`。
//!
//! # 真机验证过的三条约束
//!
//! 1. `wwan` 类接口是 `POINTOPOINT`，按网关加默认路由会被内核以
//!    `RTNETLINK answers: Host is unreachable` 拒绝 → 必须 `onlink`。
//! 2. 承载协商的 MTU（常见 1432）小于内核默认 1500，不对齐会让
//!    IPsec 加密后的 REGISTER 被 IPv6 分片。
//! 3. 接口在承载刚建立时可能仍是 `DOWN`，必须先 `ip link set up`。

use std::process::Stdio;

use crate::volte::{codes, VolteError};

/// 承载地址族。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    V4,
    V6,
    /// 双栈请求，但只使用分配到的 IPv6 地址。
    ///
    /// 必须用这个而不是纯 `V6`：这台模组对纯 IPv6 的 IMS PDN 只会在
    /// 默认通道上建一条"看起来连上了"的 PDN，拿得到地址但数据面完全不通
    /// （连网关都 ping 不到）。请求 `ipv4v6` 时 ModemManager 才会给这个
    /// PDN 分配独立的 mux 通道（wwan1），数据面才真正通。
    V4V6,
}

impl AddressFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            AddressFamily::V4 => "ipv4",
            AddressFamily::V6 => "ipv6",
            AddressFamily::V4V6 => "ipv4v6",
        }
    }

    /// 映射到 ModemManager `BearerProperties.ip-type`。
    ///
    /// MM 的枚举：1=ipv4, 2=ipv6, 3=ipv4v6。
    pub fn mm_ip_type(self) -> u32 {
        match self {
            AddressFamily::V4 => 1,
            AddressFamily::V6 => 2,
            AddressFamily::V4V6 => 3,
        }
    }

    /// `ip` 命令族参数：`-4` / `-6`。
    ///
    /// 双栈也按 IPv6 操作——IMS 信令只走 IPv6。
    pub fn ip_flag(self) -> &'static str {
        match self {
            AddressFamily::V4 => "-4",
            AddressFamily::V6 | AddressFamily::V4V6 => "-6",
        }
    }
}

/// 一个已建立的 IMS 承载在本地视角下的全部信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImsBearer {
    /// ModemManager 里的承载对象路径
    pub object_path: String,
    /// 承载所在网卡，例如 `wwan0`
    pub interface: String,
    pub family: AddressFamily,
    /// 本地地址（不带前缀长度）
    pub address: String,
    /// 前缀长度
    pub prefix: u8,
    /// 网关地址
    pub gateway: Option<String>,
    /// 承载协商的 MTU
    pub mtu: Option<u32>,
    /// P-CSCF 候选
    pub pcscf: Vec<String>,
}

impl ImsBearer {
    /// 生成把地址/路由/MTU 落到接口上的命令序列。
    ///
    /// 拆出来是为了能在不碰系统的情况下单测命令形状——`onlink` 和
    /// `mtu` 这两处一旦写错，现象是"看起来都成功但 SIP 发不出去"，
    /// 极难在真机上定位。
    pub fn apply_commands(&self) -> Vec<Vec<String>> {
        let mut cmds: Vec<Vec<String>> = Vec::new();
        let iface = self.interface.clone();

        // 1. 接口必须是 UP
        cmds.push(vec![
            "ip".into(),
            "link".into(),
            "set".into(),
            iface.clone(),
            "up".into(),
        ]);

        // 2. MTU 对齐承载协商值
        if let Some(mtu) = self.mtu {
            if mtu > 0 {
                cmds.push(vec![
                    "ip".into(),
                    "link".into(),
                    "set".into(),
                    iface.clone(),
                    "mtu".into(),
                    mtu.to_string(),
                ]);
            }
        }

        // 3. 地址
        let cidr = format!("{}/{}", self.address, self.prefix);
        cmds.push(vec![
            "ip".into(),
            self.family.ip_flag().into(),
            "addr".into(),
            "replace".into(),
            cidr,
            "dev".into(),
            iface.clone(),
        ]);

        // 4. 默认路由
        let mut route: Vec<String> = vec![
            "ip".into(),
            self.family.ip_flag().into(),
            "route".into(),
            "replace".into(),
            "default".into(),
        ];
        if let Some(gw) = self.gateway.as_deref().filter(|g| !g.is_empty()) {
            route.push("via".into());
            route.push(gw.to_string());
        }
        route.push("dev".into());
        route.push(iface.clone());
        // 点到点接口必须 onlink，否则内核拒绝经由网关的路由
        route.push("onlink".into());
        route.push("metric".into());
        route.push("100".into());
        cmds.push(route);

        cmds
    }

    /// 生成回收命令：先删路由再删地址，避免残留半配置状态。
    pub fn teardown_commands(&self) -> Vec<Vec<String>> {
        let iface = self.interface.clone();
        let cidr = format!("{}/{}", self.address, self.prefix);
        vec![
            vec![
                "ip".into(),
                self.family.ip_flag().into(),
                "route".into(),
                "del".into(),
                "default".into(),
                "dev".into(),
                iface.clone(),
            ],
            vec![
                "ip".into(),
                self.family.ip_flag().into(),
                "addr".into(),
                "del".into(),
                cidr,
                "dev".into(),
                iface,
            ],
        ]
    }

    /// 依次执行下发命令。
    ///
    /// 单条命令失败不整体回滚：`addr replace` / `route replace` 本身幂等，
    /// 失败通常意味着前置条件不满足（接口不存在等），此时继续也没有意义，
    /// 因此遇到失败立即返回并带上失败的命令行。
    pub async fn apply(&self) -> Result<(), VolteError> {
        for cmd in self.apply_commands() {
            run_ip_command(&cmd).await.map_err(|e| {
                VolteError::with_detail(
                    codes::ADDRESS_APPLY_FAILED,
                    format!("{} -> {}", cmd.join(" "), e),
                )
            })?;
        }
        Ok(())
    }

    /// 尽力回收，忽略单条失败。
    pub async fn teardown(&self) {
        for cmd in self.teardown_commands() {
            let _ = run_ip_command(&cmd).await;
        }
    }
}

async fn run_ip_command(cmd: &[String]) -> Result<(), String> {
    if cmd.is_empty() {
        return Err("empty command".to_string());
    }
    let output = tokio::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| format!("spawn failed: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Err(if stderr.is_empty() { stdout } else { stderr })
}

/// 由运营商标识（MCC+MNC，5 或 6 位）推断 MNC 宽度。
///
/// `46001` → 2 位；`460011` → 3 位。无法判断时退回 2 位，
/// 这是 3GPP 里最常见的形态。
pub fn mnc_length_from_operator_id(operator_id: &str) -> u8 {
    let digits: String = operator_id
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    if digits.len() >= 6 {
        3
    } else {
        2
    }
}

/// 从 ModemManager 的 IpConfig 字典里挑出 P-CSCF。
///
/// MM 不同版本对这个字段的命名不一致（`pcscf` / `p-cscf` / `pcscf_address`），
/// 因此按"键名包含 pcscf"做宽松匹配，值可能是字符串或字符串数组。
pub fn extract_pcscf(config: &std::collections::HashMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for (key, value) in config {
        let normalized: String = key
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if !normalized.contains("pcscf") {
            continue;
        }
        for part in value.split([',', ' ', ';']) {
            let trimmed = part.trim();
            if !trimmed.is_empty() && !out.iter().any(|v| v == trimmed) {
                out.push(trimmed.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn bearer_v6() -> ImsBearer {
        ImsBearer {
            object_path: "/org/freedesktop/ModemManager1/Bearer/6".into(),
            interface: "wwan0".into(),
            family: AddressFamily::V6,
            address: "2408:8556:420:9350:64fe:2120:440f:6132".into(),
            prefix: 64,
            gateway: Some("2408:8556:420:9350:3d25:40aa:e1dd:2ba2".into()),
            mtu: Some(1432),
            pcscf: vec![],
        }
    }

    #[test]
    fn apply_commands_include_link_mtu_addr_and_onlink_route() {
        let cmds = bearer_v6().apply_commands();
        assert_eq!(cmds.len(), 4);

        assert_eq!(cmds[0], vec!["ip", "link", "set", "wwan0", "up"]);

        assert_eq!(
            cmds[1],
            vec!["ip", "link", "set", "wwan0", "mtu", "1432"]
        );

        assert_eq!(
            cmds[2],
            vec![
                "ip",
                "-6",
                "addr",
                "replace",
                "2408:8556:420:9350:64fe:2120:440f:6132/64",
                "dev",
                "wwan0"
            ]
        );

        // 关键：必须有 onlink，否则点到点接口加网关路由会被内核拒绝
        assert_eq!(
            cmds[3],
            vec![
                "ip",
                "-6",
                "route",
                "replace",
                "default",
                "via",
                "2408:8556:420:9350:3d25:40aa:e1dd:2ba2",
                "dev",
                "wwan0",
                "onlink",
                "metric",
                "100"
            ]
        );
    }

    #[test]
    fn apply_commands_skip_mtu_when_absent() {
        let mut b = bearer_v6();
        b.mtu = None;
        let cmds = b.apply_commands();
        assert_eq!(cmds.len(), 3);
        assert!(cmds.iter().all(|c| !c.contains(&"mtu".to_string())));
    }

    #[test]
    fn apply_commands_without_gateway_still_onlink() {
        let mut b = bearer_v6();
        b.gateway = None;
        let cmds = b.apply_commands();
        let route = cmds.last().unwrap();
        assert!(!route.contains(&"via".to_string()));
        assert!(route.contains(&"onlink".to_string()));
    }

    #[test]
    fn teardown_removes_route_then_address() {
        let cmds = bearer_v6().teardown_commands();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0][3], "del");
        assert_eq!(cmds[0][4], "default");
        assert_eq!(cmds[1][3], "del");
        assert_eq!(cmds[1][4], "2408:8556:420:9350:64fe:2120:440f:6132/64");
    }

    #[test]
    fn ipv4_uses_dash_four() {
        let mut b = bearer_v6();
        b.family = AddressFamily::V4;
        b.address = "10.185.14.72".into();
        b.prefix = 28;
        b.gateway = Some("10.185.14.73".into());
        let cmds = b.apply_commands();
        assert_eq!(cmds[2][1], "-4");
        assert_eq!(cmds[3][1], "-4");
        assert_eq!(cmds[2][4], "10.185.14.72/28");
    }

    #[test]
    fn mnc_length_from_operator_id_variants() {
        assert_eq!(mnc_length_from_operator_id("46001"), 2);
        assert_eq!(mnc_length_from_operator_id("460011"), 3);
        assert_eq!(mnc_length_from_operator_id(""), 2);
        assert_eq!(mnc_length_from_operator_id("460 01"), 2);
    }

    #[test]
    fn extract_pcscf_matches_several_key_shapes() {
        let mut cfg = HashMap::new();
        cfg.insert(
            "pcscf".to_string(),
            "2408:8142:6001:603::,2408:8142:6001:a01::".to_string(),
        );
        let got = extract_pcscf(&cfg);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], "2408:8142:6001:603::");

        let mut cfg2 = HashMap::new();
        cfg2.insert("P-CSCF".to_string(), "2408:8142:6001:1005::1".to_string());
        assert_eq!(extract_pcscf(&cfg2), vec!["2408:8142:6001:1005::1"]);

        let mut cfg3 = HashMap::new();
        cfg3.insert("dns".to_string(), "8.8.8.8".to_string());
        assert!(extract_pcscf(&cfg3).is_empty());
    }
}
