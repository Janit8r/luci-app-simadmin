//! 3GPP AKA：USIM 鉴权与 SIP Digest 封装。
//!
//! 401 响应里的 `nonce` 是 Base64 编码的 `RAND(16) || AUTN(16) [|| server data]`。
//! 取出 RAND/AUTN 送进 USIM 的 AUTHENTICATE，得到 RES/CK/IK：
//!
//! - `RES` 作为 Digest 口令参与响应计算（RFC 3310 的 AKAv1-MD5）
//! - `CK || IK` 作为 IPsec 完整性密钥
//!
//! 如果 USIM 返回 `AUTS`（序列号失步），需要用 AUTS 重新发起同步流程，
//! 此时不产生 RES。

use base64::Engine as _;

use crate::volte::{codes, VolteError};

/// 从 401 的 nonce 中解出的鉴权素材。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkaChallenge {
    pub rand: Vec<u8>,
    pub autn: Vec<u8>,
    /// 服务器附加数据，参与 Digest 计算时拼在 nonce 后面
    pub server_data: Vec<u8>,
}

/// 解析 Base64 nonce。
pub fn parse_challenge_nonce(nonce_b64: &str) -> Result<AkaChallenge, VolteError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(nonce_b64.trim())
        .map_err(|e| {
            VolteError::with_detail(codes::AKA_MATERIAL_INVALID, format!("nonce base64: {e}"))
        })?;
    if raw.len() < 32 {
        return Err(VolteError::with_detail(
            codes::AKA_MATERIAL_INVALID,
            format!("nonce too short: {} bytes", raw.len()),
        ));
    }
    Ok(AkaChallenge {
        rand: raw[..16].to_vec(),
        autn: raw[16..32].to_vec(),
        server_data: raw[32..].to_vec(),
    })
}

/// USIM 鉴权结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkaOutcome {
    /// 鉴权成功时的 RES
    pub res: Vec<u8>,
    /// 加密密钥
    pub ck: Vec<u8>,
    /// 完整性密钥
    pub ik: Vec<u8>,
    /// 序列号失步时的 AUTS
    pub auts: Option<Vec<u8>>,
}

impl AkaOutcome {
    /// 是否走了同步失败分支（需要用 AUTS 重发 REGISTER）。
    pub fn is_sync_failure(&self) -> bool {
        self.auts.is_some() && self.res.is_empty()
    }
}

/// 计算 RFC 3310 AKAv1-MD5 的 Digest 响应。
///
/// ```text
/// HA1      = MD5(username ":" realm ":" RES)
/// HA2      = MD5("REGISTER" ":" uri)
/// response = MD5(HA1 ":" nonce ":" HA2)
/// ```
///
/// 注意 `nonce` 用的是**原始 Base64 字符串**（含服务器附加数据），不是解码后的字节。
pub fn build_digest_response(
    username: &str,
    realm: &str,
    res: &[u8],
    nonce: &str,
    uri: &str,
    method: &str,
) -> String {
    let ha1 = md5_hex(&[
        username.as_bytes(),
        b":",
        realm.as_bytes(),
        b":",
        res,
    ]);
    let ha2 = md5_hex(&[method.as_bytes(), b":", uri.as_bytes()]);
    md5_hex(&[ha1.as_bytes(), b":", nonce.as_bytes(), b":", ha2.as_bytes()])
}

/// 生成 `Authorization` 头（不含前缀 `Authorization: `）。
pub fn build_authorization(
    username: &str,
    realm: &str,
    nonce: &str,
    uri: &str,
    response: &str,
    algorithm: &str,
    auts: Option<&[u8]>,
) -> String {
    let mut header = format!(
        "Digest username=\"{}\",realm=\"{}\",nonce=\"{}\",uri=\"{}\",response=\"{}\",algorithm={}",
        username, realm, nonce, uri, response, algorithm
    );
    if let Some(auts) = auts {
        // AUTS 以十六进制放在 response 字段，RFC 3310 §3.2
        let hex: String = auts.iter().map(|b| format!("{:02x}", b)).collect();
        header = format!(
            "Digest username=\"{}\",realm=\"{}\",nonce=\"{}\",uri=\"{}\",response=\"{}\",algorithm={},auts=\"{}\"",
            username, realm, nonce, uri, response, algorithm, hex
        );
    }
    header
}

fn md5_hex(parts: &[&[u8]]) -> String {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(p);
    }
    format!("{:x}", md5::compute(&buf))
}

/// 把 USIM 的鉴权结果转成运行时可用的形式。
pub fn outcome_from_usim(
    res: Vec<u8>,
    ck: Vec<u8>,
    ik: Vec<u8>,
    auts: Option<Vec<u8>>,
) -> Result<AkaOutcome, VolteError> {
    if res.is_empty() && auts.is_none() {
        return Err(VolteError::with_detail(
            codes::IPSEC_AKA_EMPTY,
            "usim returned neither RES nor AUTS",
        ));
    }
    Ok(AkaOutcome {
        res,
        ck,
        ik,
        auts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn parses_nonce_without_server_data() {
        let mut raw = vec![0x11u8; 16];
        raw.extend_from_slice(&[0x22u8; 16]);
        let ch = parse_challenge_nonce(&b64(&raw)).unwrap();
        assert_eq!(ch.rand, vec![0x11; 16]);
        assert_eq!(ch.autn, vec![0x22; 16]);
        assert!(ch.server_data.is_empty());
    }

    #[test]
    fn parses_nonce_with_server_data() {
        let mut raw = vec![0u8; 32];
        raw.extend_from_slice(b"srv");
        let ch = parse_challenge_nonce(&b64(&raw)).unwrap();
        assert_eq!(ch.server_data, b"srv".to_vec());
    }

    #[test]
    fn rejects_short_nonce() {
        assert!(parse_challenge_nonce(&b64(&[0u8; 8])).is_err());
        assert!(parse_challenge_nonce("!!!not-base64!!!").is_err());
    }

    #[test]
    fn digest_response_is_stable_and_hex() {
        let r = build_digest_response(
            "460010876089383@ims.mnc001.mcc460.3gppnetwork.org",
            "ims.mnc001.mcc460.3gppnetwork.org",
            &[0x01, 0x02, 0x03, 0x04],
            "bm9uY2U=",
            "sip:ims.mnc001.mcc460.3gppnetwork.org",
            "REGISTER",
        );
        assert_eq!(r.len(), 32);
        assert!(r.chars().all(|c| c.is_ascii_hexdigit()));
        // 同输入必须同输出
        let again = build_digest_response(
            "460010876089383@ims.mnc001.mcc460.3gppnetwork.org",
            "ims.mnc001.mcc460.3gppnetwork.org",
            &[0x01, 0x02, 0x03, 0x04],
            "bm9uY2U=",
            "sip:ims.mnc001.mcc460.3gppnetwork.org",
            "REGISTER",
        );
        assert_eq!(r, again);
    }

    #[test]
    fn authorization_contains_auts_on_sync_failure() {
        let header = build_authorization(
            "u",
            "r",
            "n",
            "sip:d",
            "",
            "AKAv1-MD5",
            Some(&[0xde, 0xad, 0xbe, 0xef]),
        );
        assert!(header.contains("auts=\"deadbeef\""));
        assert!(header.contains("algorithm=AKAv1-MD5"));
    }

    #[test]
    fn outcome_flags_sync_failure() {
        let o = outcome_from_usim(vec![], vec![], vec![], Some(vec![1, 2])).unwrap();
        assert!(o.is_sync_failure());
        let ok = outcome_from_usim(vec![1, 2, 3], vec![0; 16], vec![0; 16], None).unwrap();
        assert!(!ok.is_sync_failure());
    }

    #[test]
    fn outcome_rejects_empty() {
        assert!(outcome_from_usim(vec![], vec![], vec![], None).is_err());
    }
}
