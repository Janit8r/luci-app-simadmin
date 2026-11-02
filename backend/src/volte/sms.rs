//! SMS over IMS 的 RPDU/TPDU 编解码（3GPP TS 24.011 / TS 23.040）。
//!
//! IMS 短信的载荷是 **RP-DATA**，里面再包一层 **TPDU**：
//!
//! ```text
//! RP-DATA (MO)  = [RP-MR][RP-DA][RP-OA][RP-UD]
//!   RP-UD       = [TPDU]
//! TPDU (SUBMIT) = [头][MR][DA][PID][DCS][VP][UDL][UD]
//! ```
//!
//! 只实现点对点短消息：GSM 7-bit 与 UCS2 两种编码，不做小区广播、
//! 不做状态报告以外的扩展。

/// 短信正文编码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// GSM 7-bit（ASCII 子集，7 字节/7 字符）
    Gsm7,
    /// UCS2（UTF-16BE）
    Ucs2,
}

/// 编码后的用户数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserData {
    pub encoding: Encoding,
    /// 已按编码规则打包好的字节
    pub payload: Vec<u8>,
    /// 用户数据长度（GSM7 单位是 septet 数，UCS2 单位是字节数）
    pub length: u8,
}

/// 把文本编码成用户数据。
///
/// 纯 ASCII 走 GSM 7-bit（省一半空间），含非 ASCII 走 UCS2。
pub fn encode_user_data(text: &str) -> UserData {
    if text.is_ascii() {
        let septets = text.len();
        UserData {
            encoding: Encoding::Gsm7,
            payload: pack_gsm7(text.as_bytes()),
            length: septets.min(255) as u8,
        }
    } else {
        let mut payload = Vec::with_capacity(text.len() * 2);
        for unit in text.encode_utf16() {
            payload.extend_from_slice(&unit.to_be_bytes());
        }
        UserData {
            encoding: Encoding::Ucs2,
            payload: payload.clone(),
            length: payload.len().min(255) as u8,
        }
    }
}

/// GSM 7-bit 打包：把 7 位字符压进 8 位字节流。
pub fn pack_gsm7(septets: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((septets.len() * 7).div_ceil(8));
    let mut acc: u16 = 0;
    let mut bits = 0u32;
    for &s in septets {
        acc |= ((s & 0x7f) as u16) << bits;
        bits += 7;
        while bits >= 8 {
            out.push((acc & 0xff) as u8);
            acc >>= 8;
            bits -= 8;
        }
    }
    if bits > 0 {
        out.push((acc & 0xff) as u8);
    }
    out
}

/// GSM 7-bit 解包。
pub fn unpack_gsm7(bytes: &[u8], septet_count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(septet_count);
    let mut acc: u16 = 0;
    let mut bits = 0u32;
    let mut idx = 0usize;
    while out.len() < septet_count {
        while bits < 7 {
            if idx >= bytes.len() {
                return out;
            }
            acc |= (bytes[idx] as u16) << bits;
            idx += 1;
            bits += 8;
        }
        out.push((acc & 0x7f) as u8);
        acc >>= 7;
        bits -= 7;
    }
    out
}

/// BCD 半字节编码（用于电话号码、SMSC）。
pub fn encode_bcd_number(number: &str) -> (u8, Vec<u8>) {
    let digits: Vec<u8> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c as u8 - b'0')
        .collect();
    let mut out = Vec::with_capacity(digits.len().div_ceil(2));
    let mut i = 0;
    while i < digits.len() {
        let lo = digits[i];
        let hi = if i + 1 < digits.len() { digits[i + 1] } else { 0x0f };
        out.push((hi << 4) | lo);
        i += 2;
    }
    (digits.len() as u8, out)
}

/// BCD 半字节解码。
pub fn decode_bcd_number(len_digits: u8, bytes: &[u8]) -> String {
    let mut s = String::new();
    for (i, b) in bytes.iter().enumerate() {
        for nibble in [b & 0x0f, b >> 4] {
            if s.len() >= len_digits as usize {
                break;
            }
            if nibble == 0x0f {
                break;
            }
            s.push(char::from(b'0' + nibble));
        }
        let _ = i;
    }
    s
}

/// 构造 SMS-SUBMIT 的 TPDU（不含 SMSC 地址）。
///
/// 结构：`[FO][MR][DA len][DA type][DA BCD...][PID][DCS][VP][UDL][UD]`
pub fn build_submit_tpdu(dest: &str, text: &str, message_ref: u8) -> Vec<u8> {
    let ud = encode_user_data(text);
    let (da_len, da_bcd) = encode_bcd_number(dest);

    let mut tpdu = Vec::new();
    // FO：提交、不需要状态报告、有效期为相对格式
    tpdu.push(0x11);
    tpdu.push(message_ref);
    tpdu.push(da_len);
    // DA type：国际号码（带 + 前缀时 0x91，否则 0x81）
    tpdu.push(if dest.trim_start().starts_with('+') { 0x91 } else { 0x81 });
    tpdu.extend_from_slice(&da_bcd);
    tpdu.push(0x00); // PID
    tpdu.push(match ud.encoding {
        Encoding::Gsm7 => 0x00,
        Encoding::Ucs2 => 0x08,
    });
    tpdu.push(0xaa); // VP：相对格式，4 天
    tpdu.push(ud.length);
    tpdu.extend_from_slice(&ud.payload);
    tpdu
}

/// 解析 SMS-DELIVER 的 TPDU，返回（发件号码, 正文）。
///
/// 入参是完整的 TPDU（不含 SMSC 地址）。
pub fn parse_deliver_tpdu(tpdu: &[u8]) -> Option<(String, String)> {
    if tpdu.len() < 2 {
        return None;
    }
    let mut i = 0usize;
    let fo = tpdu[i];
    i += 1;
    let _ = fo;
    if tpdu.len() < i + 2 {
        return None;
    }
    let oa_len = tpdu[i] as usize;
    i += 1;
    let _toa = tpdu[i];
    i += 1;
    let bcd_bytes = oa_len.div_ceil(2);
    if tpdu.len() < i + bcd_bytes + 2 {
        return None;
    }
    let number = decode_bcd_number(oa_len as u8, &tpdu[i..i + bcd_bytes]);
    i += bcd_bytes;
    let _pid = tpdu[i];
    i += 1;
    let dcs = tpdu[i];
    i += 1;
    // 时间戳 7 字节
    if tpdu.len() < i + 7 {
        return None;
    }
    i += 7;
    if tpdu.len() < i + 1 {
        return None;
    }
    let udl = tpdu[i] as usize;
    i += 1;
    let payload = &tpdu[i..];

    let text = if dcs & 0x0c == 0x08 {
        // UCS2
        let take = udl.min(payload.len());
        let mut units = Vec::new();
        let mut k = 0;
        while k + 1 < take {
            units.push(u16::from_be_bytes([payload[k], payload[k + 1]]));
            k += 2;
        }
        String::from_utf16_lossy(&units)
    } else {
        let septets = unpack_gsm7(payload, udl);
        septets.iter().map(|b| *b as char).collect()
    };

    Some((number, text))
}

/// 构造 MO 方向的 RP-DATA，包住 SUBMIT TPDU。
///
/// `[RP-MR][RP-DA][RP-OA][RP-UDL][TPDU]`
pub fn build_rp_data_mo(smsc: &str, tpdu: &[u8], message_ref: u8) -> Vec<u8> {
    let (da_len, da_bcd) = encode_bcd_number(smsc);
    let mut out = Vec::new();
    out.push(message_ref);
    // RP-DA
    out.push(da_len);
    out.push(if smsc.starts_with('+') { 0x91 } else { 0x81 });
    out.extend_from_slice(&da_bcd);
    // RP-OA 长度 0（MO 时由网络填充）
    out.push(0x00);
    // RP-UD
    out.push(tpdu.len().min(255) as u8);
    out.extend_from_slice(tpdu);
    out
}

/// 从 MT 方向的 RP-DATA 里剥出 TPDU。
///
/// 返回 `(originating, tpdu)`。
pub fn parse_rp_data_mt(rpdu: &[u8]) -> Option<(String, Vec<u8>)> {
    if rpdu.len() < 3 {
        return None;
    }
    let mut i = 0usize;
    let _rp_mr = rpdu[i];
    i += 1;
    // RP-OA
    let oa_len = rpdu[i] as usize;
    i += 1;
    if i >= rpdu.len() {
        return None;
    }
    let _toa = rpdu[i];
    i += 1;
    let bcd_bytes = oa_len.div_ceil(2);
    if rpdu.len() < i + bcd_bytes + 1 {
        return None;
    }
    let origin = decode_bcd_number(oa_len as u8, &rpdu[i..i + bcd_bytes]);
    i += bcd_bytes;
    let udl = rpdu[i] as usize;
    i += 1;
    if rpdu.len() < i + udl {
        return None;
    }
    Some((origin, rpdu[i..i + udl].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gsm7_pack_unpack_roundtrip() {
        let text = b"hello world";
        let packed = pack_gsm7(text);
        let back = unpack_gsm7(&packed, text.len());
        assert_eq!(back, text.to_vec());
    }

    #[test]
    fn gsm7_packs_seven_chars_into_seven_bytes() {
        // 7 个 septet 恰好占 7 字节（49 位 → 7 字节）
        let packed = pack_gsm7(b"1234567");
        assert_eq!(packed.len(), 7);
    }

    #[test]
    fn ascii_text_uses_gsm7() {
        let ud = encode_user_data("test");
        assert_eq!(ud.encoding, Encoding::Gsm7);
        assert_eq!(ud.length, 4);
    }

    #[test]
    fn non_ascii_text_uses_ucs2() {
        let ud = encode_user_data("测试");
        assert_eq!(ud.encoding, Encoding::Ucs2);
        assert_eq!(ud.length, 4);
        assert_eq!(ud.payload.len(), 4);
    }

    #[test]
    fn bcd_roundtrip_even_and_odd() {
        let (len, bytes) = encode_bcd_number("10010");
        assert_eq!(len, 5);
        assert_eq!(decode_bcd_number(len, &bytes), "10010");

        let (len2, bytes2) = encode_bcd_number("1001");
        assert_eq!(len2, 4);
        assert_eq!(decode_bcd_number(len2, &bytes2), "1001");
    }

    #[test]
    fn submit_tpdu_contains_destination_and_text() {
        let tpdu = build_submit_tpdu("10010", "test", 1);
        assert_eq!(tpdu[0], 0x11);
        assert_eq!(tpdu[1], 1);
        assert_eq!(tpdu[2], 5); // 号码位数
        // 布局：FO MR DAlen DAtype BCD(3) PID DCS VP UDL UD...
        let udl_index = 1 + 1 + 1 + 1 + 3 + 1 + 1 + 1;
        assert_eq!(tpdu[udl_index], 4); // 4 个 septet
        let decoded = unpack_gsm7(&tpdu[udl_index + 1..], 4);
        assert_eq!(decoded, b"test".to_vec());
    }

    #[test]
    fn deliver_tpdu_roundtrip_gsm7() {
        // 手工拼一个 DELIVER：OA=10010，DCS=0，UD="test"
        let ud = encode_user_data("test");
        let mut tpdu = Vec::new();
        tpdu.push(0x04); // FO
        tpdu.push(5); // OA len
        tpdu.push(0x81); // TOA
        let (_, bcd) = encode_bcd_number("10010");
        tpdu.extend_from_slice(&bcd);
        tpdu.push(0x00); // PID
        tpdu.push(0x00); // DCS
        tpdu.extend_from_slice(&[0x51, 0x11, 0x21, 0x43, 0x65, 0x87, 0x09]); // SCTS
        tpdu.push(ud.length);
        tpdu.extend_from_slice(&ud.payload);

        let (number, text) = parse_deliver_tpdu(&tpdu).unwrap();
        assert_eq!(number, "10010");
        assert_eq!(text, "test");
    }

    #[test]
    fn rp_data_mo_wraps_tpdu() {
        let tpdu = build_submit_tpdu("10010", "hi", 7);
        let rpdu = build_rp_data_mo("+8613010200500", &tpdu, 7);
        assert_eq!(rpdu[0], 7); // RP-MR
        // 尾部应包含完整 TPDU
        assert_eq!(&rpdu[rpdu.len() - tpdu.len()..], &tpdu[..]);
    }

    #[test]
    fn parse_rp_data_mt_extracts_tpdu() {
        // RP-DATA: MR=1, OA=10010, UDL=3, TPDU=[AA BB CC]
        let mut rpdu = vec![1u8, 5, 0x81];
        let (_, bcd) = encode_bcd_number("10010");
        rpdu.extend_from_slice(&bcd);
        rpdu.push(3);
        rpdu.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let (origin, tpdu) = parse_rp_data_mt(&rpdu).unwrap();
        assert_eq!(origin, "10010");
        assert_eq!(tpdu, vec![0xAA, 0xBB, 0xCC]);
    }
}
