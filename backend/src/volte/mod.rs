//! 原生 IMS / VoLTE 运行时。
//!
//! 目标：在嵌入式 Linux（OpenWrt / Debian）上完成 IMS 注册，并接管短信
//! 收发（SMS over IMS，3GPP TS 24.341）。
//!
//! 模块划分：
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`identity`] | 由 IMSI 推导归属域、IMPU、SIP URI |
//! | [`bearer`] | 建立 IMS PDN 并把地址/路由/MTU **真正下发到网卡** |
//! | [`sip`] | SIP 报文构造与解析（REGISTER / MESSAGE） |
//! | [`aka`] | 3GPP AKA：USIM AUTHENTICATE 与 SIP Digest 封装 |
//! | [`ipsec`] | 3GPP TS 33.203 IPsec SA 安装（`hmac-md5-96` + null 加密） |
//! | [`sms`] | SMS over IMS 的 RPDU/TPDU 编解码 |
//! | [`runtime`] | 注册状态机与 MO/MT 短信收发 |
//!
//! # 设计约束（来自真机实测）
//!
//! 1. **承载地址必须自己下发**。ModemManager 只负责把 PDN 拉起来并在
//!    D-Bus 上报告地址，它不会替你配置网卡——在没有 NetworkManager 的
//!    环境里，`ip addr` / `ip route` 必须由本模块执行，否则 SIP 报文
//!    连协议栈都出不去（表现为 `sendto: Network unreachable`）。
//! 2. **点到点接口要 `onlink`**。wwan 类接口是 `POINTOPOINT`，按网关加
//!    默认路由会被内核以 `Host is unreachable` 拒绝，必须显式 `onlink`。
//! 3. **MTU 必须对齐承载协商值**。内核默认 1500 而 IMS 承载通常协商
//!    1432，不对齐会让加密后的 REGISTER 被 IPv6 分片。
//! 4. **IPsec 只接受 `hmac-md5-96`**（96 位截断）配 null 加密，SA 的
//!    SPI/端口必须严格回用 `Security-Server` 头里的值。

pub mod aka;
pub mod bearer;
pub mod identity;
pub mod ipsec;
pub mod runtime;
pub mod sip;
pub mod sms;

/// IMS 运行时状态机的粗粒度阶段。
///
/// 对外序列化为小写字符串，与前端 `runtime.phase` 对应。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// 功能关闭
    Idle,
    /// 正在建立承载 / 发现 P-CSCF / 注册
    Starting,
    /// 已注册（REGISTER 200 OK）
    Registered,
    /// 注册失败或注册后掉线，等待重试
    Degraded,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Starting => "starting",
            Phase::Registered => "registered",
            Phase::Degraded => "degraded",
        }
    }
}

/// 运行时统一的错误载体。
///
/// `code` 是稳定的机器可读原因码（例如 `volte_udp_recv_timeout`），
/// `detail` 是给人看的补充说明。
#[derive(Debug, Clone)]
pub struct VolteError {
    pub code: &'static str,
    pub detail: String,
}

impl VolteError {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            detail: String::new(),
        }
    }

    pub fn with_detail(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// 组合成 `code:detail` 形式，便于写进 `last_error`。
    pub fn render(&self) -> String {
        if self.detail.is_empty() {
            self.code.to_string()
        } else {
            format!("{}:{}", self.code, self.detail)
        }
    }
}

impl std::fmt::Display for VolteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

impl std::error::Error for VolteError {}

/// 常用原因码。
pub mod codes {
    pub const COMMAND_FAILED: &str = "volte_command_failed";
    pub const COMMAND_TIMEOUT: &str = "volte_command_timeout";
    pub const IMSI_MISSING: &str = "volte_imsi_missing";
    pub const SMSC_MISSING: &str = "volte_smsc_missing";
    pub const BEARER_ACTIVATION_FAILED: &str = "volte_primary_data_activation_failed";
    pub const BEARER_RELEASE_TIMEOUT: &str = "volte_mm_ims_bearer_release_timeout";
    pub const ADDRESS_MISSING: &str = "volte_ip_settings_missing";
    pub const ADDRESS_APPLY_FAILED: &str = "volte_data_path_apply_failed";
    pub const PCSCF_MISSING: &str = "volte_pcscf_missing";
    pub const UDP_RECV_TIMEOUT: &str = "volte_udp_recv_timeout";
    pub const REGISTER_REJECTED: &str = "volte_register_rejected";
    pub const REGISTER_AUTH_FAILED: &str = "volte_register_auth_failed";
    pub const IPSEC_INSTALL_FAILED: &str = "volte_ipsec_install_failed";
    pub const IPSEC_AKA_EMPTY: &str = "volte_ipsec_aka_res_empty";
    pub const AKA_MATERIAL_INVALID: &str = "volte_aka_material_invalid";
    pub const SMS_SEND_FAILED: &str = "volte_sms_send_failed";
    pub const FEATURE_DISABLED: &str = "volte_feature_disabled";
    pub const CONNECTION_DISABLED: &str = "volte_connection_disabled";
}
