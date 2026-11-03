//! SIP 报文构造与解析（IMS REGISTER / MESSAGE）。
//!
//! 只覆盖 SMS over IMS 所需的最小集合，不做通用 SIP 协议栈：
//! - 构造 `REGISTER`（含 AKA Digest 与 `Security-Client`）
//! - 构造承载短信的 `MESSAGE`（`Content-Type: application/vnd.3gpp.sms`）
//! - 解析响应状态行与关键头（`WWW-Authenticate`、`Security-Server`、`Authentication-Info`）
//!
//! 报文一律以 `\r\n` 结尾（RFC 3261 要求），最后一行为空行。

use std::collections::HashMap;

/// 一个已解析的 SIP 响应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipResponse {
    pub status: u16,
    pub reason: String,
    pub headers: HashMap<String, String>,
}

impl SipResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// 解析 SIP 响应文本。容忍前导空行与多余的 CRLF。
pub fn parse_response(raw: &str) -> Option<SipResponse> {
    let mut lines = raw.lines().map(|l| l.trim_end_matches('\r'));
    let status_line = lines.find(|l| !l.trim().is_empty())?;
    if !status_line.starts_with("SIP/2.0 ") {
        return None;
    }
    let mut parts = status_line.splitn(3, ' ');
    let _ = parts.next()?; // SIP/2.0
    let status: u16 = parts.next()?.parse().ok()?;
    let reason = parts.next().unwrap_or("").to_string();

    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let key = name.trim().to_ascii_lowercase();
        let val = value.trim().to_string();
        // 同名头保留第一次出现（SIP 允许重复，这里只关心第一个）
        headers.entry(key).or_insert(val);
    }

    Some(SipResponse {
        status,
        reason,
        headers,
    })
}

/// 解析 `WWW-Authenticate` 里的 Digest 参数。
pub fn parse_digest_challenge(header: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let body = header
        .strip_prefix("Digest ")
        .or_else(|| header.strip_prefix("digest "))
        .unwrap_or(header);
    for part in split_params(body) {
        if let Some((k, v)) = part.split_once('=') {
            out.insert(
                k.trim().to_ascii_lowercase(),
                v.trim().trim_matches('"').to_string(),
            );
        }
    }
    out
}

/// 解析 `Security-Server` / `Security-Client` 里的 ipsec-3gpp 参数。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpsecMechanism {
    pub alg: String,
    pub ealg: String,
    pub prot: String,
    pub mode: String,
    pub spi_c: u32,
    pub spi_s: u32,
    pub port_c: u16,
    pub port_s: u16,
}

/// 从 `Security-Server: ipsec-3gpp;alg=...;spi-c=...` 中挑出可用的机制。
///
/// 只接受 `alg=hmac-md5-96` + `ealg=null`：这是运营商网络实际下发的组合，
/// 其它组合（sha-1-96 / aes-cbc）在 IMS 信令场景会被对端拒绝。
pub fn parse_security_server(header: &str) -> Option<IpsecMechanism> {
    let first = header.split(',').next()?.trim();
    if !first.starts_with("ipsec-3gpp") {
        return None;
    }
    let mut mech = IpsecMechanism {
        prot: "esp".into(),
        mode: "trans".into(),
        ..Default::default()
    };
    for part in first.split(';').skip(1) {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        match k.trim().to_ascii_lowercase().as_str() {
            "alg" => mech.alg = v.trim().to_string(),
            "ealg" => mech.ealg = v.trim().to_string(),
            "prot" => mech.prot = v.trim().to_string(),
            "mod" | "mode" => mech.mode = v.trim().to_string(),
            "spi-c" | "spic" => mech.spi_c = v.trim().parse().unwrap_or(0),
            "spi-s" | "spis" => mech.spi_s = v.trim().parse().unwrap_or(0),
            "port-c" | "portc" => mech.port_c = v.trim().parse().unwrap_or(0),
            "port-s" | "ports" => mech.port_s = v.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    if mech.alg.is_empty() {
        return None;
    }
    Some(mech)
}

/// 把 `Security-Client` 值序列化回头部格式。
pub fn render_security_client(mech: &IpsecMechanism) -> String {
    format!(
        "ipsec-3gpp;prot={};mod={};spi-c={};spi-s={};port-c={};port-s={};alg={};ealg={}",
        mech.prot, mech.mode, mech.spi_c, mech.spi_s, mech.port_c, mech.port_s, mech.alg, mech.ealg
    )
}

/// 构造 REGISTER 请求所需的上下文。
pub struct RegisterContext<'a> {
    /// 归属域，例如 `ims.mnc001.mcc460.3gppnetwork.org`
    pub home_domain: &'a str,
    /// 公有身份（IMSI 形式）
    pub impu: &'a str,
    /// 本地 IP（不带方括号）
    pub local_ip: &'a str,
    /// 本地 SIP 端口
    pub local_port: u16,
    /// P-CSCF 地址（不带方括号）
    pub pcscf: &'a str,
    /// 本次注册的 Call-ID
    pub call_id: &'a str,
    /// CSeq 序号
    pub cseq: u32,
    /// `Authorization` 头（首次注册时为空串）
    pub authorization: Option<String>,
    /// `Security-Client` 头
    pub security_client: Option<String>,
    /// `Security-Verify` 头
    pub security_verify: Option<String>,
    /// 接入技术描述
    pub access_info: &'a str,
}

/// 构造完整的 REGISTER 报文。
///
/// `security_verify` 存在时视为「认证后的第二次 REGISTER」，会走精简模式。
///
/// 精简的原因是硬约束：IMS 承载的 MTU 只有 1432，而 IPsec 封装后一旦超过
/// 这个值就会被 IPv6 分片，P-CSCF 对分片的 ESP 包直接静默丢弃（实测抓包
/// 能看到 `frag (0|1384) ESP ...` 然后毫无响应）。所以第二次 REGISTER 必须
/// 裁掉非必需头部，保证整包能装进一个 MTU。
pub fn build_register(ctx: &RegisterContext<'_>) -> String {
    let compact = ctx.security_verify.is_some();

    let contact = format!(
        "<sip:{}@[{}]:{};transport=UDP>;+g.3gpp.accesstype=\"3GPP-E-UTRAN-FDD\";+g.3gpp.smsip;expires=3600",
        user_part(ctx.impu),
        ctx.local_ip,
        ctx.local_port
    );

    let mut msg = String::new();
    msg.push_str(&format!("REGISTER sip:{} SIP/2.0\r\n", ctx.home_domain));
    msg.push_str(&format!(
        "Via: SIP/2.0/UDP [{}]:{};branch={};rport\r\n",
        ctx.local_ip,
        ctx.local_port,
        branch_for(ctx.call_id, ctx.cseq)
    ));
    msg.push_str("Max-Forwards: 70\r\n");
    msg.push_str(&format!("From: <{}>;tag={}\r\n", ctx.impu, tag_for(ctx.call_id)));
    msg.push_str(&format!("To: <{}>\r\n", ctx.impu));
    msg.push_str(&format!("Call-ID: {}\r\n", ctx.call_id));
    msg.push_str(&format!("CSeq: {} REGISTER\r\n", ctx.cseq));
    if let Some(auth) = ctx.authorization.as_deref().filter(|a| !a.is_empty()) {
        msg.push_str(&format!("Authorization: {}\r\n", auth));
    }
    msg.push_str(&format!("Contact: {}\r\n", contact));
    // Security-Client 在**每个** REGISTER 里都必须带（RFC 3329）。
    //
    // P-CSCF 靠它知道 UE 提议的 spi-c/spi-s 与 port-c/port-s，据此建自己的
    // 入向 SA。精简模式下把它省掉会让 P-CSCF 无法匹配 SA，加密 REGISTER
    // 被静默丢弃——抓包只有 Out 没有 In。
    if let Some(sc) = ctx.security_client.as_deref().filter(|s| !s.is_empty()) {
        msg.push_str(&format!("Security-Client: {}\r\n", sc));
    }
    if let Some(sv) = ctx.security_verify.as_deref().filter(|s| !s.is_empty()) {
        msg.push_str(&format!("Security-Verify: {}\r\n", sv));
    }
    msg.push_str("Accept-Contact: *;+g.3gpp.smsip\r\n");
    msg.push_str("Accept: application/vnd.3gpp.sms\r\n");
    // 精简模式下请求直接发到 P-CSCF 的 IP:9900，不需要 Route
    if !compact {
        msg.push_str(&format!("Route: <sip:[{}]:5060;lr>\r\n", ctx.pcscf));
    }
    msg.push_str("Expires: 3600\r\n");
    // `sec-agree` 必须出现在 Require / Proxy-Require 里，而不只是 Supported。
    // 中国联通的 P-CSCF 强制 IPsec AKA：只在 Supported 里声明会被判为
    // "Without sec-agree and IPsecAKA is force on"，直接回
    // `420 Bad Extension` + `Unsupported: sec-agree`，不下发 401 挑战。
    msg.push_str("Require: sec-agree\r\n");
    msg.push_str("Proxy-Require: sec-agree\r\n");
    msg.push_str("Supported: path, sec-agree\r\n");
    if !compact {
        msg.push_str("Allow: INVITE,ACK,BYE,CANCEL,MESSAGE,OPTIONS\r\n");
        msg.push_str(&format!("P-Preferred-Identity: <{}>\r\n", ctx.impu));
        msg.push_str(&format!("P-Access-Network-Info: {}\r\n", ctx.access_info));
        msg.push_str("User-Agent: SimAdmin\r\n");
    } else {
        // 精简模式只保留接入类型，去掉 cell-id 与 User-Agent，
        // 为 Security-Client 腾出空间（ESP 后总长必须 ≤ MTU）。
        msg.push_str("P-Access-Network-Info: 3GPP-E-UTRAN-FDD\r\n");
    }
    msg.push_str("Content-Length: 0\r\n");
    msg.push_str("\r\n");
    msg
}

/// 构造承载 SMS over IMS 的 MESSAGE 请求。
pub fn build_message(
    ctx: &RegisterContext<'_>,
    rpdu: &[u8],
    content_type: &str,
) -> String {
    let mut msg = String::new();
    msg.push_str(&format!("MESSAGE {} SIP/2.0\r\n", ctx.impu));
    msg.push_str(&format!(
        "Via: SIP/2.0/UDP [{}]:{};branch={};rport\r\n",
        ctx.local_ip,
        ctx.local_port,
        branch_for(ctx.call_id, ctx.cseq)
    ));
    msg.push_str("Max-Forwards: 70\r\n");
    msg.push_str(&format!("From: <{}>;tag={}\r\n", ctx.impu, tag_for(ctx.call_id)));
    msg.push_str(&format!("To: <{}>\r\n", ctx.impu));
    msg.push_str(&format!("Call-ID: {}\r\n", ctx.call_id));
    msg.push_str(&format!("CSeq: {} MESSAGE\r\n", ctx.cseq));
    if let Some(auth) = ctx.authorization.as_deref().filter(|a| !a.is_empty()) {
        msg.push_str(&format!("Authorization: {}\r\n", auth));
    }
    msg.push_str(&format!("Route: <sip:[{}]:5060;lr>\r\n", ctx.pcscf));
    msg.push_str(&format!("Content-Type: {}\r\n", content_type));
    msg.push_str("Content-Transfer-Encoding: binary\r\n");
    msg.push_str(&format!("Content-Length: {}\r\n", rpdu.len()));
    msg.push_str("\r\n");
    msg.push_str(&String::from_utf8_lossy(rpdu));
    msg
}

fn user_part(impu: &str) -> String {
    impu.strip_prefix("sip:")
        .and_then(|rest| rest.split('@').next())
        .unwrap_or(impu)
        .to_string()
}

fn branch_for(call_id: &str, cseq: u32) -> String {
    format!("z9hG4bK{:x}{:x}", hash(call_id), cseq)
}

fn tag_for(call_id: &str) -> String {
    format!("{:016x}", hash(call_id))
}

fn hash(s: &str) -> u64 {
    // FNV-1a：不需要密码学强度，只要稳定且够短
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// 按 RFC 3261 拆分 `;` 参数，跳过引号内的分号。
fn split_params(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(ch);
            }
            ';' | ',' if !in_quotes => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_401_with_challenge_and_security_server() {
        let raw = "SIP/2.0 401 Unauthorized\r\n\
                   Via: SIP/2.0/UDP [2408::1]:5060;branch=z9hG4bK1;rport=5060\r\n\
                   WWW-Authenticate: Digest realm=\"ims.mnc001.mcc460.3gppnetwork.org\",nonce=\"abc\",algorithm=AKAv1-MD5\r\n\
                   Security-Server: ipsec-3gpp;alg=hmac-md5-96;prot=esp;mod=trans;ealg=null;spi-c=2577690597;spi-s=3869536229;port-c=9950;port-s=9900\r\n\
                   Content-Length: 0\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 401);
        assert!(!resp.is_success());

        let digest = parse_digest_challenge(resp.header("www-authenticate").unwrap());
        assert_eq!(digest.get("realm").unwrap(), "ims.mnc001.mcc460.3gppnetwork.org");
        assert_eq!(digest.get("nonce").unwrap(), "abc");
        assert_eq!(digest.get("algorithm").unwrap(), "AKAv1-MD5");

        let mech = parse_security_server(resp.header("security-server").unwrap()).unwrap();
        assert_eq!(mech.alg, "hmac-md5-96");
        assert_eq!(mech.spi_c, 2577690597);
        assert_eq!(mech.spi_s, 3869536229);
        assert_eq!(mech.port_c, 9950);
        assert_eq!(mech.port_s, 9900);
    }

    #[test]
    fn parses_200_ok() {
        let resp = parse_response("SIP/2.0 200 OK\r\nCSeq: 2 REGISTER\r\n\r\n").unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.is_success());
        assert_eq!(resp.header("cseq").unwrap(), "2 REGISTER");
    }

    #[test]
    fn rejects_non_sip_payload() {
        assert!(parse_response("HTTP/1.1 200 OK\r\n").is_none());
        assert!(parse_response("").is_none());
    }

    #[test]
    fn register_has_mandatory_headers_and_no_body() {
        let ctx = RegisterContext {
            home_domain: "ims.mnc001.mcc460.3gppnetwork.org",
            impu: "sip:460010876089383@ims.mnc001.mcc460.3gppnetwork.org",
            local_ip: "2408:8556:420:9350:64fe:2120:440f:6132",
            local_port: 5060,
            pcscf: "2408:8142:6001:603::",
            call_id: "abc@simadmin",
            cseq: 1,
            authorization: None,
            security_client: None,
            security_verify: None,
            access_info: "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=460010000000;cell-info-age=0",
        };
        let msg = build_register(&ctx);
        assert!(msg.starts_with("REGISTER sip:ims.mnc001.mcc460.3gppnetwork.org SIP/2.0\r\n"));
        assert!(msg.contains("Contact: <sip:460010876089383@[2408:8556:420:9350:64fe:2120:440f:6132]:5060"));
        assert!(msg.contains("Route: <sip:[2408:8142:6001:603::]:5060;lr>"));
        assert!(msg.contains("Accept: application/vnd.3gpp.sms"));
        assert!(msg.contains("Content-Length: 0"));
        assert!(msg.ends_with("\r\n\r\n"));
        assert!(!msg.contains("Authorization:"));
    }

    #[test]
    fn register_includes_authorization_when_present() {
        let ctx = RegisterContext {
            home_domain: "d",
            impu: "sip:1@d",
            local_ip: "::1",
            local_port: 5060,
            pcscf: "::2",
            call_id: "c",
            cseq: 2,
            authorization: Some("Digest username=\"1\"".into()),
            security_client: Some("ipsec-3gpp;alg=hmac-md5-96".into()),
            security_verify: None,
            access_info: "x",
        };
        let msg = build_register(&ctx);
        assert!(msg.contains("Authorization: Digest username=\"1\""));
        assert!(msg.contains("Security-Client: ipsec-3gpp;alg=hmac-md5-96"));
    }

    #[test]
    fn message_sets_binary_content_type_and_length() {
        let ctx = RegisterContext {
            home_domain: "d",
            impu: "sip:1@d",
            local_ip: "::1",
            local_port: 5060,
            pcscf: "::2",
            call_id: "c",
            cseq: 3,
            authorization: None,
            security_client: None,
            security_verify: None,
            access_info: "x",
        };
        let msg = build_message(&ctx, b"\x01\x02\x03", "application/vnd.3gpp.sms");
        assert!(msg.contains("MESSAGE sip:1@d SIP/2.0"));
        assert!(msg.contains("Content-Type: application/vnd.3gpp.sms"));
        assert!(msg.contains("Content-Length: 3"));
    }

    #[test]
    fn security_client_roundtrip() {
        let mech = parse_security_server(
            "ipsec-3gpp;alg=hmac-md5-96;prot=esp;mod=trans;ealg=null;spi-c=1;spi-s=2;port-c=9950;port-s=9900",
        )
        .unwrap();
        let rendered = render_security_client(&mech);
        let back = parse_security_server(&rendered).unwrap();
        assert_eq!(mech, back);
    }

    #[test]
    fn security_server_rejects_non_ipsec() {
        assert!(parse_security_server("digest;alg=md5").is_none());
    }
}
