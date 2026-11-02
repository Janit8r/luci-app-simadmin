//! 3GPP TS 33.203 IPsec 信令保护。
//!
//! # 网络实际下发的参数
//!
//! ```text
//! Security-Server: ipsec-3gpp;alg=hmac-md5-96;prot=esp;mod=trans;ealg=null;
//!                  spi-c=2577690597;spi-s=3869536229;port-c=9950;port-s=9900
//! ```
//!
//! 只有 `hmac-md5-96` + `ealg=null` 这一组可用；换成 `hmac-sha-1-96` 或
//! `aes-cbc` 会被对端直接丢弃。
//!
//! # 两个必须写对的细节
//!
//! 1. **完整性必须截断到 96 位**。`ip xfrm` 里对应
//!    `auth-trunc "hmac(md5)" <key> 96`。如果写成 `auth "hmac(md5)" <key>`
//!    （128 位），ICV 长度与对端不一致，报文会被静默丢弃——抓包能看到
//!    ESP 双向都有，但 SIP 永远收不到响应，内核侧表现为
//!    `XfrmInNoStates` / `XfrmInStateProtoError` 增长。
//! 2. **入向 SA 的 SPI 必须回用对端给的值**。`spi-c` 是 P-CSCF 客户端方向
//!    的 SPI，`spi-s` 是服务端方向的 SPI；本端入向 SA 的 SPI 必须等于对端
//!    出向使用的那个，写反或自造都会导致回包找不到 SA。
//!
//! # 四组 SA 的方向
//!
//! ```text
//! UE:port_c  --(spi_ue_c)-->  PCSCF:port_s    出向，用本端 SPI
//! PCSCF:port_s --(spi_pcscf_c)--> UE:port_c   入向，用对端 spi-c
//! UE:port_s  <--(spi_ue_s)--  PCSCF:port_c    出向，用本端 SPI
//! PCSCF:port_c --(spi_pcscf_s)--> UE:port_s   入向，用对端 spi-s
//! ```

use std::process::Stdio;

use crate::volte::{codes, VolteError};

/// IPsec 算法常量。
pub const ALG_HMAC_MD5_96: &str = "hmac-md5-96";
/// `ip xfrm` 里的算法名（与 SIP 头里的名字不同）
pub const XFRM_AUTH_ALG: &str = "hmac(md5)";
/// 完整性截断位数
pub const XFRM_AUTH_TRUNC_BITS: u32 = 96;
/// null 加密在 xfrm 里的写法
pub const XFRM_ENC_ALG: &str = "ecb(cipher_null)";

/// 由 AKA 的 CK/IK 派生 IPsec 密钥。
///
/// TS 33.203 规定完整性密钥为 `CK || IK`（32 字节）。
pub fn derive_ipsec_key(ck: &[u8], ik: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(ck.len() + ik.len());
    key.extend_from_slice(ck);
    key.extend_from_slice(ik);
    key
}

/// 一个方向的 SA 描述。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaSpec {
    pub local_ip: String,
    pub remote_ip: String,
    /// 本端端口
    pub local_port: u16,
    /// 对端端口
    pub remote_port: u16,
    /// 本端 SPI
    pub local_spi: u32,
    /// 对端 SPI
    pub remote_spi: u32,
    /// 完整性密钥
    pub key: Vec<u8>,
}

/// 一次注册所需的完整 SA 集合。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsecContext {
    /// UE 客户端端口（对 P-CSCF 服务端端口）
    pub ue_port_c: u16,
    /// UE 服务端端口（对 P-CSCF 客户端端口）
    pub ue_port_s: u16,
    /// P-CSCF 客户端端口
    pub pcscf_port_c: u16,
    /// P-CSCF 服务端端口
    pub pcscf_port_s: u16,
    pub ue_spi_c: u32,
    pub ue_spi_s: u32,
    pub pcscf_spi_c: u32,
    pub pcscf_spi_s: u32,
    pub key: Vec<u8>,
}

impl IpsecContext {
    /// 出向 SA：UE:port_c → P-CSCF:port_s
    pub fn outbound_client(&self, ue_ip: &str, pcscf_ip: &str) -> SaSpec {
        SaSpec {
            local_ip: ue_ip.to_string(),
            remote_ip: pcscf_ip.to_string(),
            local_port: self.ue_port_c,
            remote_port: self.pcscf_port_s,
            local_spi: self.ue_spi_c,
            remote_spi: self.pcscf_spi_c,
            key: self.key.clone(),
        }
    }

    /// 入向 SA：P-CSCF:port_s → UE:port_c（SPI 用对端的 `spi-c`）
    pub fn inbound_client(&self, ue_ip: &str, pcscf_ip: &str) -> SaSpec {
        SaSpec {
            local_ip: ue_ip.to_string(),
            remote_ip: pcscf_ip.to_string(),
            local_port: self.ue_port_c,
            remote_port: self.pcscf_port_s,
            local_spi: self.pcscf_spi_c,
            remote_spi: self.ue_spi_c,
            key: self.key.clone(),
        }
    }

    /// 出向 SA：UE:port_s → P-CSCF:port_c
    pub fn outbound_server(&self, ue_ip: &str, pcscf_ip: &str) -> SaSpec {
        SaSpec {
            local_ip: ue_ip.to_string(),
            remote_ip: pcscf_ip.to_string(),
            local_port: self.ue_port_s,
            remote_port: self.pcscf_port_c,
            local_spi: self.ue_spi_s,
            remote_spi: self.pcscf_spi_s,
            key: self.key.clone(),
        }
    }

    /// 入向 SA：P-CSCF:port_c → UE:port_s（SPI 用对端的 `spi-s`）
    pub fn inbound_server(&self, ue_ip: &str, pcscf_ip: &str) -> SaSpec {
        SaSpec {
            local_ip: ue_ip.to_string(),
            remote_ip: pcscf_ip.to_string(),
            local_port: self.ue_port_s,
            remote_port: self.pcscf_port_c,
            local_spi: self.pcscf_spi_s,
            remote_spi: self.ue_spi_s,
            key: self.key.clone(),
        }
    }
}

fn hex_key(key: &[u8]) -> String {
    let mut s = String::with_capacity(2 + key.len() * 2);
    s.push_str("0x");
    for b in key {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// 生成 `ip xfrm state add`（出向）。
pub fn build_state_out(sa: &SaSpec, family_flag: &str) -> Vec<String> {
    vec![
        "ip".into(),
        family_flag.into(),
        "xfrm".into(),
        "state".into(),
        "add".into(),
        "src".into(),
        sa.local_ip.clone(),
        "dst".into(),
        sa.remote_ip.clone(),
        "proto".into(),
        "esp".into(),
        "spi".into(),
        format!("0x{:x}", sa.local_spi),
        "mode".into(),
        "transport".into(),
        // 96 位截断——写成 auth 会静默失败
        "auth-trunc".into(),
        XFRM_AUTH_ALG.into(),
        hex_key(&sa.key),
        XFRM_AUTH_TRUNC_BITS.to_string(),
        "enc".into(),
        XFRM_ENC_ALG.into(),
        "".into(),
        "sel".into(),
        "src".into(),
        sa.local_ip.clone(),
        "dst".into(),
        sa.remote_ip.clone(),
        "proto".into(),
        "udp".into(),
        "sport".into(),
        sa.local_port.to_string(),
        "dport".into(),
        sa.remote_port.to_string(),
    ]
}

/// 生成 `ip xfrm state add`（入向）。
pub fn build_state_in(sa: &SaSpec, family_flag: &str) -> Vec<String> {
    vec![
        "ip".into(),
        family_flag.into(),
        "xfrm".into(),
        "state".into(),
        "add".into(),
        "src".into(),
        sa.remote_ip.clone(),
        "dst".into(),
        sa.local_ip.clone(),
        "proto".into(),
        "esp".into(),
        "spi".into(),
        format!("0x{:x}", sa.local_spi),
        "mode".into(),
        "transport".into(),
        "auth-trunc".into(),
        XFRM_AUTH_ALG.into(),
        hex_key(&sa.key),
        XFRM_AUTH_TRUNC_BITS.to_string(),
        "enc".into(),
        XFRM_ENC_ALG.into(),
        "".into(),
    ]
}

/// 生成 `ip xfrm policy add`（出向）。
pub fn build_policy_out(sa: &SaSpec, family_flag: &str) -> Vec<String> {
    vec![
        "ip".into(),
        family_flag.into(),
        "xfrm".into(),
        "policy".into(),
        "add".into(),
        "dir".into(),
        "out".into(),
        "src".into(),
        format!("{}/128", sa.local_ip),
        "dst".into(),
        format!("{}/128", sa.remote_ip),
        "proto".into(),
        "udp".into(),
        "sport".into(),
        sa.local_port.to_string(),
        "dport".into(),
        sa.remote_port.to_string(),
        "tmpl".into(),
        "src".into(),
        sa.local_ip.clone(),
        "dst".into(),
        sa.remote_ip.clone(),
        "proto".into(),
        "esp".into(),
        "mode".into(),
        "transport".into(),
    ]
}

/// 生成 `ip xfrm policy add`（入向）。
pub fn build_policy_in(sa: &SaSpec, family_flag: &str) -> Vec<String> {
    vec![
        "ip".into(),
        family_flag.into(),
        "xfrm".into(),
        "policy".into(),
        "add".into(),
        "dir".into(),
        "in".into(),
        "src".into(),
        format!("{}/128", sa.remote_ip),
        "dst".into(),
        format!("{}/128", sa.local_ip),
        "proto".into(),
        "udp".into(),
        "sport".into(),
        sa.remote_port.to_string(),
        "dport".into(),
        sa.local_port.to_string(),
        "tmpl".into(),
        "src".into(),
        sa.remote_ip.clone(),
        "dst".into(),
        sa.local_ip.clone(),
        "proto".into(),
        "esp".into(),
        "mode".into(),
        "transport".into(),
    ]
}

/// 把 4 组 SA 与策略装上。
///
/// 顺序：先装 state 再装 policy。state 缺失时 policy 也能装成功，但流量会被
/// 内核丢弃；先 state 后 policy 可以让失败尽早暴露。
pub async fn install(
    ctx: &IpsecContext,
    ue_ip: &str,
    pcscf_ip: &str,
    family_flag: &str,
) -> Result<(), VolteError> {
    let pairs = [
        (ctx.outbound_client(ue_ip, pcscf_ip), true),
        (ctx.inbound_client(ue_ip, pcscf_ip), false),
        (ctx.outbound_server(ue_ip, pcscf_ip), true),
        (ctx.inbound_server(ue_ip, pcscf_ip), false),
    ];

    for (sa, outbound) in pairs {
        let state_cmd = if outbound {
            build_state_out(&sa, family_flag)
        } else {
            build_state_in(&sa, family_flag)
        };
        run(&state_cmd).await.map_err(|e| {
            VolteError::with_detail(
                codes::IPSEC_INSTALL_FAILED,
                format!("state: {} -> {e}", state_cmd.join(" ")),
            )
        })?;

        let policy_cmd = if outbound {
            build_policy_out(&sa, family_flag)
        } else {
            build_policy_in(&sa, family_flag)
        };
        run(&policy_cmd).await.map_err(|e| {
            VolteError::with_detail(
                codes::IPSEC_INSTALL_FAILED,
                format!("policy: {} -> {e}", policy_cmd.join(" ")),
            )
        })?;
    }

    Ok(())
}

/// 清理本端安装的全部 SA 与策略（尽力而为）。
pub async fn uninstall(ctx: &IpsecContext, ue_ip: &str, pcscf_ip: &str, family_flag: &str) {
    let pairs = [
        (ctx.outbound_client(ue_ip, pcscf_ip), true),
        (ctx.inbound_client(ue_ip, pcscf_ip), false),
        (ctx.outbound_server(ue_ip, pcscf_ip), true),
        (ctx.inbound_server(ue_ip, pcscf_ip), false),
    ];
    for (sa, outbound) in pairs {
        let mut state = if outbound {
            build_state_out(&sa, family_flag)
        } else {
            build_state_in(&sa, family_flag)
        };
        if let Some(pos) = state.iter().position(|v| v == "add") {
            state[pos] = "delete".into();
        }
        let _ = run(&state).await;

        let mut policy = if outbound {
            build_policy_out(&sa, family_flag)
        } else {
            build_policy_in(&sa, family_flag)
        };
        if let Some(pos) = policy.iter().position(|v| v == "add") {
            policy[pos] = "delete".into();
        }
        let _ = run(&policy).await;
    }
}

async fn run(cmd: &[String]) -> Result<(), String> {
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
    Err(if stderr.is_empty() {
        "command failed".to_string()
    } else {
        stderr
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> IpsecContext {
        IpsecContext {
            ue_port_c: 42484,
            ue_port_s: 48308,
            pcscf_port_c: 9950,
            pcscf_port_s: 9900,
            ue_spi_c: 2691354233,
            ue_spi_s: 21779166,
            pcscf_spi_c: 2574228448,
            pcscf_spi_s: 3866074080,
            key: vec![0xAA; 32],
        }
    }

    #[test]
    fn state_out_truncates_integrity_to_96_bits() {
        let sa = ctx().outbound_client("2408::1", "2408::2");
        let cmd = build_state_out(&sa, "-6");
        let joined = cmd.join(" ");
        assert!(joined.contains("auth-trunc"));
        assert!(joined.contains("hmac(md5)"));
        assert!(joined.contains(" 96 "));
        assert!(!joined.contains("auth hmac(md5) 0x"), "must not use full-length auth");
        // 出向用本端 SPI
        assert!(joined.contains(&format!("spi 0x{:x}", 2691354233u32)));
    }

    #[test]
    fn state_in_uses_peer_spi() {
        let sa = ctx().inbound_client("2408::1", "2408::2");
        let cmd = build_state_in(&sa, "-6");
        let joined = cmd.join(" ");
        // 入向 SPI 必须是 P-CSCF 给的 spi-c
        assert!(joined.contains(&format!("spi 0x{:x}", 2574228448u32)));
        // src/dst 方向反转
        assert_eq!(cmd[6], "2408::2");
        assert_eq!(cmd[8], "2408::1");
    }

    #[test]
    fn inbound_server_uses_peer_spi_s() {
        let sa = ctx().inbound_server("2408::1", "2408::2");
        let cmd = build_state_in(&sa, "-6");
        let joined = cmd.join(" ");
        assert!(joined.contains(&format!("spi 0x{:x}", 3866074080u32)));
    }

    #[test]
    fn key_is_ck_then_ik() {
        let key = derive_ipsec_key(&[1u8; 16], &[2u8; 16]);
        assert_eq!(key.len(), 32);
        assert_eq!(&key[..16], &[1u8; 16]);
        assert_eq!(&key[16..], &[2u8; 16]);
        assert_eq!(hex_key(&key), format!("0x{}{}", "01".repeat(16), "02".repeat(16)));
    }

    #[test]
    fn policy_out_has_selector_ports() {
        let sa = ctx().outbound_client("2408::1", "2408::2");
        let cmd = build_policy_out(&sa, "-6");
        let joined = cmd.join(" ");
        assert!(joined.contains("dir out"));
        assert!(joined.contains("sport 42484"));
        assert!(joined.contains("dport 9900"));
        assert!(joined.contains("tmpl"));
    }

    #[test]
    fn policy_in_swaps_ports() {
        let sa = ctx().inbound_client("2408::1", "2408::2");
        let cmd = build_policy_in(&sa, "-6");
        let joined = cmd.join(" ");
        assert!(joined.contains("dir in"));
        assert!(joined.contains("sport 9900"));
        assert!(joined.contains("dport 42484"));
    }

    #[test]
    fn ipv4_uses_dash_four_flag() {
        let sa = ctx().outbound_client("10.0.0.1", "10.0.0.2");
        let cmd = build_state_out(&sa, "-4");
        assert_eq!(cmd[1], "-4");
        assert!(cmd.join(" ").contains("10.0.0.1"));
    }
}
