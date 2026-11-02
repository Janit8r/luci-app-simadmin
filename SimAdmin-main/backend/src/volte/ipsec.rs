//! 3GPP IPsec for SIP signalling — SA negotiation and `ip xfrm` installation.
//!
//! Recovered from `src/volte.rs` lines ~3440, 3703, 2474-2521, 2604-2687.
//!
//! Evidence (confidence A for literals):
//!   - `mechanism`, `security-server`, `spi-c`, `spi-s`, `port-c`, `port-s`
//!   - `volte_security_server_missing`
//!   - `Require: sec-agree`, `Proxy-Require: sec-agree`
//!   - xfrm vocabulary: `policy`, `dst`, `proto`, `esp`, `spi`, `auth-trunc`,
//!     `hmac(md5)`, `enc`, `udp`, `sport`, `dport`, `out`, `in`
//!   - `local_send_port`, `local_receive_port`, `remote_client_port`,
//!     `pcscf_spi_c`, `pcscf_spi_s`
//!   - `Native VoLTE IPsec xfrm installed`
//!   - `volte_ipsec_requires_ipv6`, `volte_ipsec_udp_bind_failed`,
//!     `volte_ipsec_send_udp_bind_failed`, `volte_ipsec_recv_udp_bind_failed`
//!   - `Native VoLTE IPsec IMS REGISTER 200 OK over IPsec`
//!   - `Native VoLTE IPsec registration failed, falling back to plain UDP SIP`
//!
//! # How the SA is agreed
//!
//! RFC 3329 `sec-agree`. The UE proposes in `Security-Client`, the P-CSCF
//! answers in `Security-Server` with its own SPIs and ports, and the UE echoes
//! the server's parameters back verbatim in `Security-Verify` on the protected
//! request. Four SAs exist in total (two directions × two SPI pairs), all
//! installed into the kernel with `ip xfrm`.
//!
//! # Field-observed constraint
//!
//! The integrity algorithm that is actually accepted is `hmac-md5-96` with
//! **null encryption**; `hmac-sha-1-96` / `aes-cbc` proposals are rejected with
//! 420 Bad Extension on the networks this was tested against. IPv6 is mandatory
//! (`volte_ipsec_requires_ipv6`).

use std::net::{IpAddr, Ipv6Addr};

use super::{err, ip_bin};

/// Integrity algorithm token as sent in `Security-Client`.
pub const ALG_HMAC_MD5_96: &str = "hmac-md5-96";
/// Encryption algorithm token — null, i.e. integrity only.
pub const EALG_NULL: &str = "null";
/// Protocol and mode, always ESP in transport mode.
pub const PROT_ESP: &str = "prot=esp";
pub const MOD_TRANS: &str = "mod=trans";
/// Kernel-side names for the same choices.
const XFRM_AUTH_ALG: &str = "hmac(md5)";
const XFRM_AUTH_TRUNC_BITS: u32 = 96;
const XFRM_ENC_ALG: &str = "ecb(cipher_null)";

/// RFC 3329 mechanism name.
pub const MECHANISM_IPSEC_3GPP: &str = "ipsec-3gpp";

/// Header names.
///
/// Only `Security-Client` and `Security-Verify` exist as *emit* templates in the
/// binary (VA 0x8ee3e9 / 0x8ee1cb, both with the trailing `": "`).
/// `security-server` appears lowercase in the parse-side token cluster at
/// 0x915704 alongside `mechanism`, `spi-c`, `spi-s`, `port-c`, `port-s` —
/// header lookup is case-insensitive, so the parser stores it folded.
pub const H_SECURITY_CLIENT: &str = "Security-Client";
pub const H_SECURITY_VERIFY: &str = "Security-Verify";
pub const H_SECURITY_SERVER: &str = "security-server";
pub const H_REQUIRE: &str = "Require";
pub const H_PROXY_REQUIRE: &str = "Proxy-Require";
pub const SEC_AGREE: &str = "sec-agree";
/// Parse-side parameter keys, verbatim from the 0x915704 cluster.
pub const P_MECHANISM: &str = "mechanism";
pub const P_SPI_C: &str = "spi-c";
pub const P_SPI_S: &str = "spi-s";
pub const P_PORT_C: &str = "port-c";
pub const P_PORT_S: &str = "port-s";

/// Ephemeral port range for the UE's SIP sockets. SPIs and ports are randomly
/// drawn; failures surface as `volte_random_port_invalid` /
/// `volte_random_port_range_invalid` / `volte_random_spi_invalid`.
pub const UE_PORT_MIN: u16 = 40000;
pub const UE_PORT_MAX: u16 = 60000;

/// Parameters the UE proposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityClient {
    /// UE inbound SPI (P-CSCF encrypts to this).
    pub spi_c: u32,
    /// UE outbound SPI.
    pub spi_s: u32,
    /// UE protected **client** port — the UE *sends* protected requests from
    /// here (REGISTER#2, MESSAGE, ...) to the P-CSCF's `port-s`.
    pub port_c: u16,
    /// UE protected **server** port — the UE *receives* protected requests
    /// here. This is the port advertised in `Contact` (production fleet:
    /// 47482).
    pub port_s: u16,
}

impl SecurityClient {
    /// Render the `Security-Client` value.
    ///
    /// Parameter order and spacing are **byte-exact from the binary** — the
    /// format string at VA 0x8edfcd is:
    ///
    /// ```text
    /// ipsec-3gpp;prot=esp;mod=trans;spi-c=..;spi-s=..;port-c=..;port-s=..;alg=hmac-md5-96;ealg=null
    /// ```
    ///
    /// Note: no spaces after the semicolons, `prot`/`mod` come first, and
    /// `alg`/`ealg` come **last**. P-CSCFs have been observed to reject
    /// reordered or space-padded variants with 420 Bad Extension.
    pub fn to_header(&self) -> String {
        format!(
            "{MECHANISM_IPSEC_3GPP};{PROT_ESP};{MOD_TRANS};spi-c={};spi-s={};port-c={};port-s={};alg={ALG_HMAC_MD5_96};ealg={EALG_NULL}",
            self.spi_c, self.spi_s, self.port_c, self.port_s
        )
    }
}

/// Parameters the P-CSCF answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityServer {
    pub mechanism: String,
    pub alg: String,
    pub ealg: String,
    /// P-CSCF inbound SPI.
    pub spi_c: u32,
    /// P-CSCF outbound SPI.
    pub spi_s: u32,
    /// UE port on which UE-directed requests (MESSAGE, ...) arrive. This is
    /// the Contact port.
    pub port_c: u16,
    /// P-CSCF protected **server** port — the UE sends all its requests
    /// (REGISTER#2 and everything else) to this port.
    pub port_s: u16,
    /// Raw header value, kept byte-exact for `Security-Verify`.
    pub raw: String,
}

/// Parse a `Security-Server` header value.
///
/// Multiple mechanisms may be offered, comma-separated; the first
/// `ipsec-3gpp` entry wins. Missing header -> `volte_security_server_missing`.
pub fn parse_security_server(header_value: &str) -> Result<SecurityServer, String> {
    let v = header_value.trim();
    if v.is_empty() {
        return Err(err::SECURITY_SERVER_MISSING.to_string());
    }

    for candidate in v.split(',') {
        let c = candidate.trim();
        if !c.starts_with(MECHANISM_IPSEC_3GPP) {
            continue;
        }
        let mut alg = String::new();
        let mut ealg = String::new();
        let mut spi_c = None;
        let mut spi_s = None;
        let mut port_c = None;
        let mut port_s = None;

        for part in c.split(';').skip(1) {
            let (k, val) = match part.split_once('=') {
                Some((k, val)) => (k.trim().to_ascii_lowercase(), val.trim()),
                None => continue,
            };
            match k.as_str() {
                "alg" => alg = val.to_string(),
                "ealg" => ealg = val.to_string(),
                "spi-c" => spi_c = val.parse::<u32>().ok(),
                "spi-s" => spi_s = val.parse::<u32>().ok(),
                "port-c" => port_c = val.parse::<u16>().ok(),
                "port-s" => port_s = val.parse::<u16>().ok(),
                _ => {}
            }
        }

        let (spi_c, spi_s, port_c, port_s) = match (spi_c, spi_s, port_c, port_s) {
            (Some(a), Some(b), Some(cc), Some(d)) => (a, b, cc, d),
            _ => return Err(err::SECURITY_SERVER_MISSING.to_string()),
        };

        return Ok(SecurityServer {
            mechanism: MECHANISM_IPSEC_3GPP.to_string(),
            alg,
            ealg,
            spi_c,
            spi_s,
            port_c,
            port_s,
            raw: c.to_string(),
        });
    }

    Err(err::SECURITY_SERVER_MISSING.to_string())
}

/// `Security-Verify` must echo the server's parameters **verbatim**. Any
/// normalisation (reordering, whitespace changes) causes a 401/403 loop.
pub fn security_verify_header(server: &SecurityServer) -> String {
    server.raw.clone()
}

/// The four SAs that make up a protected SIP association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsecContext {
    pub ue_addr: Ipv6Addr,
    pub pcscf_addr: Ipv6Addr,
    pub client: SecurityClient,
    pub server: SecurityServer,
    /// Integrity key = IK from AKA.
    pub ik: Vec<u8>,
}

impl IpsecContext {
    /// UE socket used to send protected requests (port_c).
    pub fn local_send_port(&self) -> u16 {
        self.client.port_c
    }
    /// UE socket that receives protected responses/requests (port_s, Contact).
    pub fn local_receive_port(&self) -> u16 {
        self.client.port_s
    }
    /// P-CSCF port we send to (server port).
    pub fn remote_server_port(&self) -> u16 {
        self.server.port_s
    }
    /// P-CSCF port that originates traffic toward us (requests to our
    /// Contact arrive from the P-CSCF's client port).
    pub fn remote_client_port(&self) -> u16 {
        self.server.port_c
    }
}

/// `ip xfrm` reqid and policy priority used by the reference fleet.
pub const XFRM_REQID: u32 = 18173;
pub const XFRM_POLICY_PRIORITY: u32 = 18173;

/// Build and install all SAs and policies with `ip xfrm`.
///
/// Eight rules — four states then four policies — the exact scheme the
/// reference implementation runs against China Unicom (TS 33.203 §6.3):
///
/// ```text
/// state  src ue dst pc spi=ss.spi-s   # out ue:port_c -> pc:port_s
/// state  src pc dst ue spi=cl.spi-c   # in  pc:port_s -> ue:port_c
/// state  src pc dst ue spi=cl.spi-s   # in  pc:port_c -> ue:port_s
/// state  src ue dst pc spi=ss.spi-c   # out ue:port_s -> pc:port_c
/// ```
///
/// (The sender-side SPI advertised by the peer: `ss.spi-*` protect UE→P-CSCF,
/// `cl.spi-*` protect P-CSCF→UE — RFC 3329 advertises the SPI the *other*
/// side must use when sending to the named port.)
///
/// All four states share the same integrity key (IK). States are installed
/// **before** policies: a policy with `level required` takes effect
/// immediately, and an outbound packet matching a policy without a state is
/// dropped with ENOENT instead of going out plain.
///
/// Android 4.4's iproute2 rejects `proto udp` as a policy selector
/// (`argument "udp" is wrong`); the numeric `proto 17` form is required.
///
/// Returns the argv sequences that were run, which makes the whole thing
/// testable without touching the kernel.
pub fn install(ctx: &IpsecContext) -> Result<Vec<Vec<String>>, String> {
    let ip = ip_bin()?;
    if ctx.ik.len() < 16 {
        return Err(err::IPSEC_IK_INVALID.to_string());
    }
    let key = format!("0x{}", ctx.ik.iter().map(|b| format!("{b:02x}")).collect::<String>());

    let ue = ctx.ue_addr.to_string();
    let pc = ctx.pcscf_addr.to_string();
    let ue_send = ctx.client.port_c; // UE 发
    let ue_recv = ctx.client.port_s; // UE 收（Contact）
    let pc_send = ctx.server.port_s; // UE 发往
    let pc_recv = ctx.server.port_c; // UE 侧请求的来源

    let mut cmds: Vec<Vec<String>> = Vec::new();

    // --- four states first ---
    cmds.push(state_add(ip, &ue, &pc, ctx.server.spi_s, &key));
    cmds.push(state_add(ip, &pc, &ue, ctx.client.spi_c, &key));
    cmds.push(state_add(ip, &pc, &ue, ctx.client.spi_s, &key));
    cmds.push(state_add(ip, &ue, &pc, ctx.server.spi_c, &key));

    // --- then four policies ---
    cmds.push(policy_add(ip, &ue, &pc, "out", ctx.server.spi_s, ue_send, pc_send));
    cmds.push(policy_add(ip, &pc, &ue, "in", ctx.client.spi_c, pc_send, ue_send));
    cmds.push(policy_add(ip, &pc, &ue, "in", ctx.client.spi_s, pc_recv, ue_recv));
    cmds.push(policy_add(ip, &ue, &pc, "out", ctx.server.spi_c, ue_recv, pc_recv));

    Ok(cmds)
}

/// 无缝换装（refresh 专用）：P-CSCF 每次 401 都轮换 Security-Server SPI
/// （设备日志实证：bg8 两轮 spi-c 2449533642→2661483942），IK 也随 AKA
/// 重算，所以每轮 refresh 必须装 4 条新 state + 重挂 4 条 policy。
///
/// 旧序列 `state flush + policy flush + add ×8` 有 1-3 秒黑洞：
///   - 入站：在途 MT 的 ESP 已无 SA，被内核静默丢弃（SMSC 之后重投，
///     重投失败计入退避阶梯，白天多次重启已把退避拉到 13.5 分钟）；
///   - 出站：窗口内发出的 RP-ACK/200 OK 没有 policy 保护，裸奔被
///     P-CSCF 丢弃。
///
/// 新序列「先装 → 原子换挂 → 精确删旧」：
///   1. 4× `state add`（新 SPI/新 IK）—— 旧 SA 原样还在，流量无感；
///   2. 4× `policy update`（out 先行）—— 同选择器就地替换 tmpl，
///      每条 policy 一个原子操作，受保护二轮 REGISTER 发出前 out 已就绪；
///   3. `policy del` 上一代**选择器发生变化**的策略 —— P-CSCF 每轮会
///      轮换自己的端口（实测 port-c 9950→9951），策略选择器含对端端口，
///      端口一变 update 就退化成"新建"，旧端口的死策略会越积越多
///      （实测一轮 refresh 后内核 6 条 policy）。端口没变的槽位已被
///      update 原地替换，跳过；
///   4. 4× `state del`（上一代 SPI，精确删除）—— 不留泄漏。
/// `prev = None` 时即进程首次安装：`policy update` 对不存在同选择器的
/// 情况等价于 add，天然覆盖上个进程残留的 policy，无需 flush。
pub fn install_seamless(
    ctx: &IpsecContext,
    prev: Option<&IpsecContext>,
) -> Result<Vec<Vec<String>>, String> {
    let ip = ip_bin()?;
    if ctx.ik.len() < 16 {
        return Err(err::IPSEC_IK_INVALID.to_string());
    }
    let key = format!("0x{}", ctx.ik.iter().map(|b| format!("{b:02x}")).collect::<String>());

    let ue = ctx.ue_addr.to_string();
    let pc = ctx.pcscf_addr.to_string();
    let ue_send = ctx.client.port_c; // UE 发
    let ue_recv = ctx.client.port_s; // UE 收（Contact）
    let pc_send = ctx.server.port_s; // UE 发往
    let pc_recv = ctx.server.port_c; // UE 侧请求的来源

    let mut cmds: Vec<Vec<String>> = Vec::new();

    // --- 1) new states first: old SAs keep protecting traffic ---
    cmds.push(state_add(ip, &ue, &pc, ctx.server.spi_s, &key));
    cmds.push(state_add(ip, &pc, &ue, ctx.client.spi_c, &key));
    cmds.push(state_add(ip, &pc, &ue, ctx.client.spi_s, &key));
    cmds.push(state_add(ip, &ue, &pc, ctx.server.spi_c, &key));

    // --- 2) atomic per-direction repoint (out first: re-REGISTER #2
    //        is sent immediately after these run) ---
    cmds.push(policy_update(ip, &ue, &pc, "out", ctx.server.spi_s, ue_send, pc_send));
    cmds.push(policy_update(ip, &ue, &pc, "out", ctx.server.spi_c, ue_recv, pc_recv));
    cmds.push(policy_update(ip, &pc, &ue, "in", ctx.client.spi_c, pc_send, ue_send));
    cmds.push(policy_update(ip, &pc, &ue, "in", ctx.client.spi_s, pc_recv, ue_recv));

    if let Some(old) = prev {
        // --- 3) prune previous-generation policies whose selector moved
        //        (P-CSCF rotated its port between cycles). A selector that
        //        did NOT move was already replaced in place by update. ---
        // (dir, old sport, old dport, new sport, new dport, src, dst)
        let slots: [(&str, u16, u16, u16, u16, &str, &str); 4] = [
            ("out", old.client.port_c, old.server.port_s, ue_send, pc_send, &ue, &pc),
            ("out", old.client.port_s, old.server.port_c, ue_recv, pc_recv, &ue, &pc),
            ("in", old.server.port_s, old.client.port_c, pc_send, ue_send, &pc, &ue),
            ("in", old.server.port_c, old.client.port_s, pc_recv, ue_recv, &pc, &ue),
        ];
        for (dir, os, od, ns, nd, src, dst) in slots {
            if os != ns || od != nd {
                cmds.push(policy_del(ip, src, dst, dir, os, od));
            }
        }

        // --- 4) precise removal of the previous generation's states ---
        cmds.push(state_del(ip, &ue, &pc, old.server.spi_s));
        cmds.push(state_del(ip, &pc, &ue, old.client.spi_c));
        cmds.push(state_del(ip, &pc, &ue, old.client.spi_s));
        cmds.push(state_del(ip, &ue, &pc, old.server.spi_c));
    }

    Ok(cmds)
}

fn state_add(ip: &str, src: &str, dst: &str, spi: u32, key: &str) -> Vec<String> {
    vec![
        ip.into(), "xfrm".into(), "state".into(), "add".into(),
        "src".into(), src.into(),
        "dst".into(), dst.into(),
        "proto".into(), "esp".into(),
        "spi".into(), format!("0x{spi:08x}"),
        "reqid".into(), XFRM_REQID.to_string(),
        "mode".into(), "transport".into(),
        "auth-trunc".into(), XFRM_AUTH_ALG.into(), key.into(), XFRM_AUTH_TRUNC_BITS.to_string(),
        "enc".into(), XFRM_ENC_ALG.into(), "".into(),
    ]
}

fn policy_cmd(
    ip: &str,
    verb: &str,
    src: &str,
    dst: &str,
    dir: &str,
    spi: u32,
    sport: u16,
    dport: u16,
) -> Vec<String> {
    vec![
        ip.into(), "xfrm".into(), "policy".into(), verb.into(),
        "src".into(), format!("{src}/128"),
        "dst".into(), format!("{dst}/128"),
        "proto".into(), "17".into(),
        "sport".into(), sport.to_string(),
        "dport".into(), dport.to_string(),
        "dir".into(), dir.into(),
        "priority".into(), XFRM_POLICY_PRIORITY.to_string(),
        "tmpl".into(),
        "src".into(), src.into(),
        "dst".into(), dst.into(),
        "proto".into(), "esp".into(),
        "spi".into(), format!("0x{spi:08x}"),
        "reqid".into(), XFRM_REQID.to_string(),
        "mode".into(), "transport".into(),
        "level".into(), "required".into(),
    ]
}

fn policy_add(
    ip: &str,
    src: &str,
    dst: &str,
    dir: &str,
    spi: u32,
    sport: u16,
    dport: u16,
) -> Vec<String> {
    policy_cmd(ip, "add", src, dst, dir, spi, sport, dport)
}

/// `ip xfrm policy update` —— 同选择器 + 同 priority 时**就地替换**
/// （设备实测：同选择器第二次 update 不会重复，tmpl 指向新 SPI）。
/// 这一步是整个无缝刷新的核心：每条 policy 的替换是一个原子操作，
/// 换装瞬间不存在"新旧 SA 都不在"的窗口。
fn policy_update(
    ip: &str,
    src: &str,
    dst: &str,
    dir: &str,
    spi: u32,
    sport: u16,
    dport: u16,
) -> Vec<String> {
    policy_cmd(ip, "update", src, dst, dir, spi, sport, dport)
}

/// 精确删除单条 state（按 src/dst/spi，不是 flush）。
fn state_del(ip: &str, src: &str, dst: &str, spi: u32) -> Vec<String> {
    vec![
        ip.into(), "xfrm".into(), "state".into(), "del".into(),
        "src".into(), src.into(),
        "dst".into(), dst.into(),
        "proto".into(), "esp".into(),
        "spi".into(), format!("0x{spi:08x}"),
    ]
}

/// 精确删除单条 policy（按选择器 + dir）。注意 delete 语法**不接受
/// priority/tmpl**（设备实测 `argument "priority" is wrong`）。
fn policy_del(
    ip: &str,
    src: &str,
    dst: &str,
    dir: &str,
    sport: u16,
    dport: u16,
) -> Vec<String> {
    vec![
        ip.into(), "xfrm".into(), "policy".into(), "del".into(),
        "src".into(), format!("{src}/128"),
        "dst".into(), format!("{dst}/128"),
        "proto".into(), "17".into(),
        "sport".into(), sport.to_string(),
        "dport".into(), dport.to_string(),
        "dir".into(), dir.into(),
    ]
}

/// Remove everything this module installed. Called on teardown and before a
/// re-REGISTER so stale SAs can't shadow new ones
/// (`Cleaning up native VoLTE IMS context`).
pub fn teardown() -> Result<Vec<Vec<String>>, String> {
    let ip = ip_bin()?;
    Ok(vec![
        vec![ip.into(), "xfrm".into(), "state".into(), "flush".into()],
        vec![ip.into(), "xfrm".into(), "policy".into(), "flush".into()],
    ])
}

/// IPsec is IPv6-only in this implementation.
pub fn require_ipv6(addr: IpAddr) -> Result<Ipv6Addr, String> {
    match addr {
        IpAddr::V6(a) => Ok(a),
        IpAddr::V4(_) => Err(err::IPSEC_REQUIRES_IPV6.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape a real P-CSCF answers with (same parameter style as our own
    /// Security-Client, plus the customary q-value).
    fn server() -> SecurityServer {
        parse_security_server(
            "ipsec-3gpp;prot=esp;mod=trans;spi-c=9900;spi-s=9950;port-c=5060;port-s=5061;alg=hmac-md5-96;ealg=null;q=0.5",
        )
        .unwrap()
    }

    #[test]
    fn parses_security_server() {
        let s = server();
        assert_eq!(s.spi_c, 9900);
        assert_eq!(s.spi_s, 9950);
        assert_eq!(s.port_c, 5060);
        assert_eq!(s.port_s, 5061);
        assert_eq!(s.alg, ALG_HMAC_MD5_96);
        assert_eq!(s.ealg, EALG_NULL);
    }

    #[test]
    fn missing_or_incomplete_header_rejected() {
        assert_eq!(
            parse_security_server("").unwrap_err(),
            err::SECURITY_SERVER_MISSING
        );
        assert_eq!(
            parse_security_server("ipsec-3gpp;alg=hmac-md5-96;spi-c=1").unwrap_err(),
            err::SECURITY_SERVER_MISSING
        );
        assert_eq!(
            parse_security_server("tls; q=0.1").unwrap_err(),
            err::SECURITY_SERVER_MISSING
        );
    }

    /// Byte-exactness of Security-Verify is the difference between 200 OK and
    /// an endless 401 loop.
    #[test]
    fn security_verify_echoes_raw_value() {
        let s = server();
        assert_eq!(security_verify_header(&s), s.raw);
        assert!(s.raw.contains("q=0.5"), "trailing params must be preserved");
        assert!(s.raw.contains("prot=esp"), "prot/mod must survive verbatim");
    }

    /// Byte-exact reproduction of the format string at VA 0x8edfcd.
    #[test]
    fn security_client_header_is_byte_exact() {
        let c = SecurityClient {
            spi_c: 42221,
            spi_s: 48657,
            port_c: 42221,
            port_s: 48657,
        };
        assert_eq!(
            c.to_header(),
            "ipsec-3gpp;prot=esp;mod=trans;spi-c=42221;spi-s=48657;port-c=42221;port-s=48657;alg=hmac-md5-96;ealg=null"
        );
    }

    #[test]
    fn security_client_has_no_spaces_and_correct_param_order() {
        let c = SecurityClient { spi_c: 1, spi_s: 2, port_c: 3, port_s: 4 };
        let h = c.to_header();
        assert!(!h.contains("; "), "binary uses bare semicolons");
        // prot/mod first, alg/ealg last.
        assert!(h.find("prot=esp").unwrap() < h.find("spi-c").unwrap());
        assert!(h.find("alg=").unwrap() > h.find("port-s").unwrap());
        assert!(h.ends_with("ealg=null"));
        assert!(!h.contains("sha"));
        assert!(!h.contains("aes"));
    }

    #[test]
    fn installs_four_xfrm_rules() {
        let ctx = IpsecContext {
            ue_addr: "2408:8556:a231:104e::1".parse().unwrap(),
            pcscf_addr: "2408:8142:6001:1::".parse().unwrap(),
            client: SecurityClient {
                spi_c: 42221,
                spi_s: 48657,
                port_c: 42221,
                port_s: 48657,
            },
            server: server(),
            ik: vec![0xEB; 16],
        };
        let cmds = install(&ctx).unwrap();
        assert_eq!(cmds.len(), 8, "4 states + 4 policies");
        let flat: Vec<String> = cmds.iter().flatten().cloned().collect();
        assert!(flat.contains(&"hmac(md5)".to_string()));
        assert!(flat.contains(&"ecb(cipher_null)".to_string()));
        assert!(flat.contains(&"96".to_string()));
        assert!(flat.iter().any(|s| s == "transport"));
        assert!(flat.contains(&"18173".to_string()), "reqid + priority");
        assert!(flat.contains(&"17".to_string()), "numeric UDP proto selector");
        assert!(!flat.contains(&"encap".to_string()), "no UDP encapsulation");
    }

    #[test]
    fn short_ik_is_rejected() {
        let ctx = IpsecContext {
            ue_addr: "2408::1".parse().unwrap(),
            pcscf_addr: "2408::2".parse().unwrap(),
            client: SecurityClient { spi_c: 1, spi_s: 2, port_c: 3, port_s: 4 },
            server: server(),
            ik: vec![0; 8],
        };
        assert_eq!(install(&ctx).unwrap_err(), err::IPSEC_IK_INVALID);
        assert_eq!(
            install_seamless(&ctx, None).unwrap_err(),
            err::IPSEC_IK_INVALID
        );
    }

    /// 无缝换装序列：新 state add → policy update（原子重挂，绝不 flush）
    /// → 旧 SPI 精确 del；P-CSCF 轮换端口时额外删旧选择器的 policy。
    #[test]
    fn seamless_install_updates_policies_and_prunes_previous_states() {
        let ctx = IpsecContext {
            ue_addr: "2408:8556:a231:104e::1".parse().unwrap(),
            pcscf_addr: "2408:8142:6001:1::".parse().unwrap(),
            client: SecurityClient {
                spi_c: 42221,
                spi_s: 48657,
                port_c: 42221,
                port_s: 48657,
            },
            server: server(),
            ik: vec![0xEB; 16],
        };
        // 端口稳定的上一代（port-c 5060 / port-s 5061 与新一代相同，
        // 但 SPI 已轮换；UE 端口同进程固定，与 ctx 一致）
        let prev = IpsecContext {
            ue_addr: ctx.ue_addr,
            pcscf_addr: ctx.pcscf_addr,
            client: SecurityClient {
                spi_c: 1,
                spi_s: 2,
                port_c: 42221,
                port_s: 48657,
            },
            server: parse_security_server(
                "ipsec-3gpp;prot=esp;mod=trans;spi-c=9911;spi-s=9961;port-c=5060;port-s=5061;alg=hmac-md5-96;ealg=null;q=0.5",
            )
            .unwrap(),
            ik: vec![0xEA; 16],
        };
        // 首装：4 state add + 4 policy update，无 del
        let first = install_seamless(&ctx, None).unwrap();
        assert_eq!(first.len(), 8);
        assert!(
            first[4..].iter().all(|c| c[3] == "update"),
            "policies must use the atomic update verb, never add/flush"
        );

        // ---- 端口不变：update 原地替换，只删 4 条旧 state ----
        let swap = install_seamless(&ctx, Some(&prev)).unwrap();
        assert_eq!(swap.len(), 12, "8 + 4 state del, no policy del");
        let spi_of = |c: &Vec<String>| c[c.iter().position(|s| s == "spi").unwrap() + 1].clone();
        let del_spis: Vec<String> = swap[8..].iter().map(|c| spi_of(c)).collect();
        assert_eq!(
            del_spis,
            vec![
                "0x000026e9".to_string(), // prev ss.spi-s 9961
                "0x00000001".to_string(), // prev cl.spi-c
                "0x00000002".to_string(), // prev cl.spi-s
                "0x000026b7".to_string(), // prev ss.spi-c 9911
            ]
        );
        // 新 SPI 的 state add 在前 4 条
        let add_spis: Vec<String> = swap[..4].iter().map(|c| spi_of(c)).collect();
        assert_eq!(
            add_spis,
            vec![
                "0x000026de".to_string(), // ss.spi-s 9950
                "0x0000a4ed".to_string(), // cl.spi-c 42221
                "0x0000be11".to_string(), // cl.spi-s 48657
                "0x000026ac".to_string(), // ss.spi-c 9900
            ]
        );

        // ---- P-CSCF 轮换 port-c（5060→5062）：旧选择器的 2 条 47482
        //      policy 要被精确删掉，否则越积越多 ----
        let rotated = IpsecContext {
            server: parse_security_server(
                "ipsec-3gpp;prot=esp;mod=trans;spi-c=9901;spi-s=9951;port-c=5062;port-s=5061;alg=hmac-md5-96;ealg=null;q=0.5",
            )
            .unwrap(),
            ..prev.clone()
        };
        let swap2 = install_seamless(&ctx, Some(&rotated)).unwrap();
        assert_eq!(swap2.len(), 14, "8 + 2 policy del + 4 state del");
        let pol_dels: Vec<&Vec<String>> = swap2[8..10].iter().collect();
        assert!(
            pol_dels.iter().all(|c| c[2] == "policy" && c[3] == "del"),
            "prune must target policies"
        );
        let dport_of = |c: &Vec<String>| c[c.iter().position(|s| s == "dport").unwrap() + 1].clone();
        // 删的是上一代旧 port-c（5062）的 47482 两条：out ue:48657→pc:5062、
        // in pc:5062→ue:48657；47481 槽位（port-s 5061 未变）不删
        assert_eq!(dport_of(pol_dels[0]), "5062");
        assert_eq!(pol_dels[0][pol_dels[0].len() - 1], "out");
        assert_eq!(dport_of(pol_dels[1]), "48657");
        assert_eq!(pol_dels[1][pol_dels[1].len() - 1], "in");
        // 47481 槽位（port-s 5061 未变）不删
        let rest: Vec<&Vec<String>> = swap2[10..].iter().collect();
        assert!(rest.iter().all(|c| c[2] == "state" && c[3] == "del"));
        // 全程没有 flush
        let flat: Vec<String> = swap2.iter().flatten().cloned().collect();
        assert!(!flat.contains(&"flush".to_string()));
    }

    #[test]
    fn ipv4_pcscf_rejected() {
        assert_eq!(
            require_ipv6("1.2.3.4".parse().unwrap()).unwrap_err(),
            err::IPSEC_REQUIRES_IPV6
        );
        assert!(require_ipv6("2408::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn port_accessors_map_to_the_right_side() {
        let ctx = IpsecContext {
            ue_addr: "2408::1".parse().unwrap(),
            pcscf_addr: "2408::2".parse().unwrap(),
            client: SecurityClient { spi_c: 1, spi_s: 2, port_c: 42221, port_s: 48657 },
            server: server(),
            ik: vec![0; 16],
        };
        assert_eq!(ctx.local_send_port(), 42221, "port_c 是发送口");
        assert_eq!(ctx.local_receive_port(), 48657, "port_s 是接收/Contact 口");
        assert_eq!(ctx.remote_client_port(), 5060);
        assert_eq!(ctx.remote_server_port(), 5061);
    }
}
