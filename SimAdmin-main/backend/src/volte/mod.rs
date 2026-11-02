//! 原生 IMS / VoLTE 短信栈（SMS over IMS，TS 24.341）。
//!
//! 本模块移植自设备侧已实测跑通的 `ims/`（mifi44-ims，MIFI-45D8 / MSM8916），
//! 去掉了 Android 专有的裸 QMUX 依赖，改为在 OpenWrt 上双通道自动降级：
//!
//! ```text
//!   承载 (APN=ims PDN)   qmicli 优先  → 失败降级 裸 QMUX /dev/cdc-wdmX
//!   USIM AKA            qmi-proxy (UIM AUTHENTICATE) 优先 → 失败降级 裸 QMUX UIM
//!   SIP 信令            UDP（IPsec 可用则走 ESP，否则纯 UDP 回落）
//! ```
//!
//! 模块划分：
//!   aka      — SIP digest + AKA（AKAv1/AKAv2-MD5）
//!   identity — IMSI → MCC/MNC → home domain / APN / IMPI / IMPU
//!   sip      — SIP/2.0 报文解析、REGISTER / MESSAGE 构造
//!   sms      — RPDU/TPDU 编解码、GSM7/UCS2、分段重组
//!   pcscf    — P-CSCF 发现与主机路由安装
//!   ipsec    — 3GPP IPsec（ip xfrm 无缝换装）
//!   uim      — APDU 构造（裸 QMUX 降级路径用）
//!   qmi_raw  — 裸 QMUX 客户端（cdc-wdm / qmi-proxy socket）
//!   bearer   — IMS PDN 承载（qmicli 优先，裸 QMUX 降级）
//!   usim     — USIM AKA（qmi-proxy 优先，裸 QMUX 降级）
//!   runtime  — 注册/刷新状态机 + SIP socket + MO/MT 短信

// 本模块是设备侧已跑通的协议库整包移植，保留完整 API 面（含当前运行路径
// 尚未调用的常量/工具），便于后续按设备日志逐项比对，因此统一放开 dead_code。
#![allow(dead_code)]

pub mod aka;
pub mod bearer;
pub mod identity;
pub mod ipsec;
pub mod pcscf;
pub mod qmi_raw;
pub mod runtime;
pub mod sip;
pub mod sms;
pub mod uim;
pub mod usim;

use std::time::Duration;

// ---------------------------------------------------------------------------
// 共享常量
// ---------------------------------------------------------------------------

/// 3GPP IMS home-domain 模板：`ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org`
pub const IMS_DOMAIN_PREFIX: &str = "ims.mnc";
pub const IMS_DOMAIN_MID: &str = ".mcc";
pub const IMS_DOMAIN_SUFFIX: &str = ".3gppnetwork.org";

/// `ip` 二进制查找顺序。OpenWrt 在 /sbin/ip，Android 在 /system/bin/ip。
pub const IP_BIN_CANDIDATES: [&str; 5] = [
    "/sbin/ip",
    "/usr/sbin/ip",
    "/bin/ip",
    "/usr/bin/ip",
    "/system/bin/ip",
];

/// SIP 协议版本串。
pub const SIP_VERSION: &str = "SIP/2.0";

/// REGISTER 通告的注册时长（秒）。
pub const REGISTER_EXPIRES_SECS: u32 = 3600;

/// SIP 事务 UDP 收包超时。
pub const SIP_RECV_TIMEOUT: Duration = Duration::from_secs(10);

/// UE 受保护 server 口（Contact 口，收 MT）。
pub const UE_PORT_S_DEFAULT: u16 = 47482;
/// UE 受保护 client 口（发往 P-CSCF 的 port-s）。
pub const UE_PORT_C_DEFAULT: u16 = 47481;

// ---------------------------------------------------------------------------
// 错误码（与设备侧 ims/ 保持一致，便于日志对照）
// ---------------------------------------------------------------------------

/// 错误码常量与设备侧日志一一对应，个别码当前路径尚未使用，保留以便对照。
#[allow(dead_code)]
pub mod err {
    // --- identity / USIM ---
    pub const IMSI_MISSING: &str = "volte_imsi_missing";
    pub const USIM_AID_MISSING: &str = "volte_usim_aid_missing";
    pub const USIM_AID_NOT_USIM: &str = "volte_usim_aid_not_usim";
    pub const USIM_AKA_FAILED: &str = "volte_usim_aka_failed";

    // --- AKA / digest ---
    pub const AKA_MATERIAL_INVALID: &str = "volte_aka_material_invalid";
    pub const AKA_RES_EMPTY: &str = "volte_aka_res_empty";
    pub const IPSEC_AKA_RES_EMPTY: &str = "volte_ipsec_aka_res_empty";
    pub const IPSEC_AKA_RES_EMPTY_WITHOUT_AUTS: &str = "volte_ipsec_aka_res_empty_without_auts";
    pub const DIGEST_CHALLENGE_MISSING: &str = "volte_digest_challenge_missing";
    pub const DIGEST_NONCE_MISSING: &str = "volte_digest_nonce_missing";
    pub const DIGEST_NONCE_DECODE_FAILED: &str = "volte_digest_nonce_decode_failed";
    pub const DIGEST_REALM_MISSING: &str = "volte_digest_realm_missing";
    pub const DIGEST_QOP_UNSUPPORTED: &str = "volte_digest_qop_unsupported";
    pub const DIGEST_ALGORITHM_UNSUPPORTED: &str = "volte_digest_algorithm_unsupported";
    pub const REGISTER_NONCE_NOT_AKA: &str = "volte_register_nonce_not_aka";

    // --- SIP ---
    pub const SIP_STATUS_INVALID: &str = "volte_sip_status_invalid";
    pub const SIP_STATUS_MISSING: &str = "volte_sip_status_missing";
    pub const SIP_HEADER_MISSING: &str = "volte_sip_header_missing";
    pub const SIP_HEADER_NOT_UTF8: &str = "volte_sip_header_not_utf8";

    // --- IPsec ---
    pub const IPSEC_REQUIRES_IPV6: &str = "volte_ipsec_requires_ipv6";
    pub const IPSEC_IK_INVALID: &str = "volte_ipsec_ik_invalid";
    pub const SECURITY_SERVER_MISSING: &str = "volte_security_server_missing";

    // --- bearer / data path ---
    pub const IPV6_GATEWAY_MISSING: &str = "volte_ipv6_gateway_missing";
    pub const CGCONTRDP_IPV6_MISSING: &str = "volte_cgcontrdp_ipv6_missing";
    pub const CGCONTRDP_GATEWAY_MISSING: &str = "volte_cgcontrdp_gateway_missing";

    // --- P-CSCF ---
    pub const PCSCF_FAMILY_MISMATCH: &str = "volte_pcscf_family_mismatch";
    pub const RUNTIME_ALL_PCSCF_FAILED: &str = "volte_runtime_all_pcscf_failed";

    // --- misc parsing ---
    pub const HEX_INVALID: &str = "volte_hex_invalid";
    pub const IP_INVALID: &str = "volte_ip_invalid";

    // --- 本实现新增（运行期） ---
    pub const DISABLED: &str = "volte_disabled";
    pub const RUNTIME_NOT_RUNNING: &str = "volte_runtime_not_running";
    pub const RUNTIME_COMMAND_CLOSED: &str = "volte_runtime_command_closed";
    pub const BEARER_UNAVAILABLE: &str = "volte_bearer_unavailable";
    pub const QMI_DEVICE_MISSING: &str = "volte_qmi_device_missing";
    pub const REGISTER_REJECTED: &str = "volte_register_rejected";
    pub const NOT_REGISTERED: &str = "volte_not_registered";
    pub const SMS_ENCODE_FAILED: &str = "volte_sms_encode_failed";
    pub const SMS_RP_ACK_TIMEOUT: &str = "volte_sms_rp_ack_timeout";
    pub const SMS_DELIVERY_UNKNOWN: &str = "volte_sms_delivery_unknown";
    pub const SMSC_MISSING: &str = "volte_smsc_missing";
}

// ---------------------------------------------------------------------------
// 共享工具
// ---------------------------------------------------------------------------

/// 注册尝试使用的地址族。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImsFamily {
    V4,
    V6,
}

/// 解析 `ip` 二进制路径。
///
/// 固定候选之外允许 `SIMADMIN_IP_BIN` 覆盖（部分固件把 iproute2 装在别处，
/// 单元测试也需要一个可控入口）。解析结果只做一次。
pub fn ip_bin() -> Result<&'static str, String> {
    static RESOLVED: std::sync::OnceLock<Result<&'static str, String>> = std::sync::OnceLock::new();
    RESOLVED.get_or_init(resolve_ip_bin).clone()
}

fn resolve_ip_bin() -> Result<&'static str, String> {
    if let Ok(path) = std::env::var("SIMADMIN_IP_BIN") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Ok(Box::leak(trimmed.to_string().into_boxed_str()));
        }
    }
    for c in IP_BIN_CANDIDATES {
        if std::path::Path::new(c).exists() {
            return Ok(c);
        }
    }
    Err("volte_dependency_missing:ip".to_string())
}

/// 十六进制解码，容忍 `0x` 前缀与空白。
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    let t: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    if t.is_empty() || t.len() % 2 != 0 {
        return Err(err::HEX_INVALID.to_string());
    }
    (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).map_err(|_| err::HEX_INVALID.to_string()))
        .collect()
}

/// MCC/MNC → IMS home domain。MNC 按 TS 23.003 补齐 3 位。
pub fn ims_domain(mcc: &str, mnc: &str) -> String {
    let mnc3 = format!("{:0>3}", mnc);
    format!("{IMS_DOMAIN_PREFIX}{mnc3}{IMS_DOMAIN_MID}{mcc}{IMS_DOMAIN_SUFFIX}")
}

/// EPC 侧 IMS APN：`ims.epc.mnc001.mcc460.gprs`
pub fn ims_apn(mcc: &str, mnc: &str) -> String {
    let mnc3 = format!("{:0>3}", mnc);
    format!("ims.epc.mnc{mnc3}.mcc{mcc}.gprs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn china_unicom_domain_apn() {
        assert_eq!(ims_domain("460", "01"), "ims.mnc001.mcc460.3gppnetwork.org");
        assert_eq!(ims_apn("460", "01"), "ims.epc.mnc001.mcc460.gprs");
    }

    #[test]
    fn hex_tolerant() {
        assert_eq!(parse_hex("0xAB cd").unwrap(), vec![0xAB, 0xCD]);
        assert!(parse_hex("ABC").is_err());
    }
}
