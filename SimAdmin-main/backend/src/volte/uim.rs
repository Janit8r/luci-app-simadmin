//! USIM access for IMS: APDU transport and 3GPP AKA via the SIM Auth proxy.
//!
//! ============================================================================
//! REVERSE-ENGINEERED from simadmin 1.1.6-beta9
//!   binary md5 : de53b623259c8190eb70aa6a82c6f2da
//!
//! Evidence
//!   - source path literal `src/ims_uim.rs` @ 0x8ee5fb
//!   - complete `sim_auth_*` error family @ 0x9184dc..: `proxy_connect_failed`,
//!     `proxy_open_failed`, `uim_client_failed`, `logical_channel_failed`,
//!     `logical_channel_close_failed`, `apdu_exchange_failed`,
//!     `apdu_security_status`, `aka_response_parse_failed`,
//!     `aka_response_empty`, `aka_success_parse_failed`,
//!     `aka_sync_failure_parse_failed`, `aka_response_unknown_tag`,
//!     `apdu_more_data_unhandled`, `apdu_wrong_length_unhandled`,
//!     `apdu_wrong_length`, `apdu_instruction_not_supported`,
//!     `apdu_class_not_supported`, `apdu_build_failed`,
//!     `apdu_parameter_rejected`, `retry_not_attempted`
//!   - `apdu_response` field in the HTTP response struct list
//!   - `--uim-get-card-status`, `--uim-read-transparent=0x3F00,0x7FFF,0x6FAD`
//!   - `@qmi-proxy` (proxy socket suffix)
//!   - `application type:`, `application id:`, `'usim`
//!
//! Confidence: A for all literals and status words; B for APDU framing (derived
//! from ETSI TS 102 221 / 3GPP TS 31.102, cross-checked against the error set).
//! ============================================================================
//!
//! # Why a proxy
//!
//! ModemManager holds the QMI device open, so a second client cannot simply
//! attach. libqmi ships `qmi-proxy` for exactly this: clients connect to the
//! abstract socket and the proxy multiplexes onto the real device. Failing to
//! reach it is `sim_auth_proxy_connect_failed`; failing to open the device
//! behind it is `sim_auth_proxy_open_failed`.
//!
//! # The AKA exchange
//!
//! ```text
//!   MANAGE CHANNEL (open)             -> logical channel N
//!   SELECT by AID (USIM ADF) on N
//!   AUTHENTICATE (RAND, AUTN) on N    -> 0xDB success | 0xDC sync failure
//!   MANAGE CHANNEL (close N)
//! ```
//! The card, not the host, holds K — see [`super::aka`].

use super::aka::AkaResult;

/// libqmi proxy socket. The leading `@` selects the abstract namespace.
pub const QMI_PROXY_SOCKET: &str = "@qmi-proxy";

/// qmicli flag for card status. Present in beta9 (confidence A).
pub const QMI_CARD_STATUS: &str = "--uim-get-card-status";

/// EF_AD read via QMI.
///
/// **beta8-only (confidence C for beta9).** This exact string is in the
/// 1.1.7-beta8 binary but absent from beta9 — beta9 contains only
/// `--uim-get-card-status`. Either beta9 dropped the QMI EF_AD path, or it
/// assembles the argument at runtime. Kept because the file id and path are
/// fixed by 3GPP TS 31.102 (EF_AD = 0x6FAD under 0x3F00/0x7FFF).
pub const QMI_READ_EF_AD: &str = "--uim-read-transparent=0x3F00,0x7FFF,0x6FAD";

// ---------------------------------------------------------------------------
// Error codes (verbatim)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub mod err {
    pub const PROXY_CONNECT_FAILED: &str = "sim_auth_proxy_connect_failed";
    pub const PROXY_OPEN_FAILED: &str = "sim_auth_proxy_open_failed";
    pub const UIM_CLIENT_FAILED: &str = "sim_auth_uim_client_failed";
    pub const LOGICAL_CHANNEL_FAILED: &str = "sim_auth_logical_channel_failed";
    pub const LOGICAL_CHANNEL_CLOSE_FAILED: &str = "sim_auth_logical_channel_close_failed";
    pub const APDU_EXCHANGE_FAILED: &str = "sim_auth_apdu_exchange_failed";
    pub const APDU_SECURITY_STATUS: &str = "sim_auth_apdu_security_status";
    pub const APDU_BUILD_FAILED: &str = "sim_auth_apdu_build_failed";
    pub const APDU_MORE_DATA_UNHANDLED: &str = "sim_auth_apdu_more_data_unhandled";
    pub const APDU_WRONG_LENGTH: &str = "sim_auth_apdu_wrong_length";
    pub const APDU_WRONG_LENGTH_UNHANDLED: &str = "sim_auth_apdu_wrong_length_unhandled";
    pub const APDU_INSTRUCTION_NOT_SUPPORTED: &str = "sim_auth_apdu_instruction_not_supported";
    pub const APDU_CLASS_NOT_SUPPORTED: &str = "sim_auth_apdu_class_not_supported";
    pub const APDU_PARAMETER_REJECTED: &str = "sim_auth_apdu_parameter_rejected";
    pub const AKA_RESPONSE_EMPTY: &str = "sim_auth_aka_response_empty";
    pub const AKA_RESPONSE_PARSE_FAILED: &str = "sim_auth_aka_response_parse_failed";
    pub const AKA_RESPONSE_UNKNOWN_TAG: &str = "sim_auth_aka_response_unknown_tag";
    pub const AKA_SUCCESS_PARSE_FAILED: &str = "sim_auth_aka_success_parse_failed";
    pub const AKA_SYNC_FAILURE_PARSE_FAILED: &str = "sim_auth_aka_sync_failure_parse_failed";
    pub const RETRY_NOT_ATTEMPTED: &str = "sim_auth_retry_not_attempted";
}

// ---------------------------------------------------------------------------
// APDU layer (ETSI TS 102 221)
// ---------------------------------------------------------------------------

/// INS bytes we use.
const INS_MANAGE_CHANNEL: u8 = 0x70;
const INS_SELECT: u8 = 0xA4;
const INS_AUTHENTICATE: u8 = 0x88;
const INS_GET_RESPONSE: u8 = 0xC0;

/// CLA for the basic channel; logical channels OR the channel number in.
const CLA_BASE: u8 = 0x00;

/// AUTHENTICATE response tags (3GPP TS 31.102 §7.1.2).
const TAG_AKA_SUCCESS: u8 = 0xDB;
const TAG_AKA_SYNC_FAILURE: u8 = 0xDC;

/// Status words worth naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusWord {
    pub sw1: u8,
    pub sw2: u8,
}

impl StatusWord {
    pub fn new(sw1: u8, sw2: u8) -> Self {
        Self { sw1, sw2 }
    }

    pub fn is_success(self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }

    /// `61 XX` — XX bytes still available, fetch with GET RESPONSE.
    pub fn more_data(self) -> Option<u8> {
        (self.sw1 == 0x61).then_some(self.sw2)
    }

    /// `6C XX` — wrong Le, retry with Le = XX.
    pub fn wrong_length(self) -> Option<u8> {
        (self.sw1 == 0x6C).then_some(self.sw2)
    }

    /// Map a failure status word onto the binary's error code.
    pub fn to_error(self) -> Option<&'static str> {
        if self.is_success() {
            return None;
        }
        Some(match (self.sw1, self.sw2) {
            (0x61, _) => err::APDU_MORE_DATA_UNHANDLED,
            (0x6C, _) => err::APDU_WRONG_LENGTH,
            (0x69, 0x82) | (0x69, 0x83) | (0x69, 0x84) | (0x69, 0x85) => {
                err::APDU_SECURITY_STATUS
            }
            (0x6D, _) => err::APDU_INSTRUCTION_NOT_SUPPORTED,
            (0x6E, _) => err::APDU_CLASS_NOT_SUPPORTED,
            (0x6A, _) => err::APDU_PARAMETER_REJECTED,
            (0x67, _) => err::APDU_WRONG_LENGTH_UNHANDLED,
            _ => err::APDU_EXCHANGE_FAILED,
        })
    }
}

/// A command APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandApdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    /// `None` = no Le byte.
    pub le: Option<u8>,
}

impl CommandApdu {
    /// Serialise to the wire. Case 1/2/3/4 short form only — USIM AUTHENTICATE
    /// data never exceeds 255 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.data.len() > 255 {
            return Err(err::APDU_BUILD_FAILED.to_string());
        }
        let mut v = vec![self.cla, self.ins, self.p1, self.p2];
        if !self.data.is_empty() {
            v.push(self.data.len() as u8);
            v.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            v.push(le);
        }
        Ok(v)
    }
}

/// Apply a logical channel number to CLA (TS 102 221 §10.1.1).
pub fn cla_for_channel(channel: u8) -> u8 {
    // Channels 1..=3 go in the low two bits; 4..=19 need the extended form,
    // which no USIM in this fleet uses.
    CLA_BASE | (channel & 0x03)
}

/// MANAGE CHANNEL — open.
pub fn apdu_open_channel() -> CommandApdu {
    CommandApdu {
        cla: CLA_BASE,
        ins: INS_MANAGE_CHANNEL,
        p1: 0x00,
        p2: 0x00,
        data: Vec::new(),
        le: Some(0x01),
    }
}

/// MANAGE CHANNEL — close `channel`.
pub fn apdu_close_channel(channel: u8) -> CommandApdu {
    CommandApdu {
        cla: CLA_BASE,
        ins: INS_MANAGE_CHANNEL,
        p1: 0x80,
        p2: channel,
        data: Vec::new(),
        le: None,
    }
}

/// SELECT the USIM application by AID on a logical channel.
pub fn apdu_select_aid(channel: u8, aid: &[u8]) -> CommandApdu {
    CommandApdu {
        cla: cla_for_channel(channel),
        ins: INS_SELECT,
        // P1=0x04 select by DF name, P2=0x04 return FCP
        p1: 0x04,
        p2: 0x04,
        data: aid.to_vec(),
        le: Some(0x00),
    }
}

/// AUTHENTICATE with RAND and AUTN.
///
/// Data field is `len(RAND) || RAND || len(AUTN) || AUTN`, per TS 31.102.
/// P2 = 0x81 selects the 3G security context.
pub fn apdu_authenticate(channel: u8, rand: &[u8; 16], autn: &[u8; 16]) -> CommandApdu {
    let mut data = Vec::with_capacity(34);
    data.push(rand.len() as u8);
    data.extend_from_slice(rand);
    data.push(autn.len() as u8);
    data.extend_from_slice(autn);
    CommandApdu {
        cla: cla_for_channel(channel),
        ins: INS_AUTHENTICATE,
        p1: 0x00,
        p2: 0x81,
        data,
        le: Some(0x00),
    }
}

/// GET RESPONSE for `len` bytes.
pub fn apdu_get_response(channel: u8, len: u8) -> CommandApdu {
    CommandApdu {
        cla: cla_for_channel(channel),
        ins: INS_GET_RESPONSE,
        p1: 0x00,
        p2: 0x00,
        data: Vec::new(),
        le: Some(len),
    }
}

/// Split a response APDU into body and status word.
pub fn split_response(resp: &[u8]) -> Result<(&[u8], StatusWord), String> {
    if resp.len() < 2 {
        return Err(err::APDU_EXCHANGE_FAILED.to_string());
    }
    let n = resp.len();
    Ok((
        &resp[..n - 2],
        StatusWord::new(resp[n - 2], resp[n - 1]),
    ))
}

/// Parse the body of a successful AUTHENTICATE.
///
/// Success (`0xDB`): `DB | len(RES) | RES | len(CK) | CK | len(IK) | IK [| len(Kc) | Kc]`
/// Sync failure (`0xDC`): `DC | len(AUTS) | AUTS`
///
/// An unknown leading tag is reported distinctly (`..._unknown_tag`) because it
/// usually means the card fell back to a 2G context, not that the data is
/// corrupt.
pub fn parse_authenticate_response(body: &[u8]) -> Result<AkaResult, String> {
    if body.is_empty() {
        return Err(err::AKA_RESPONSE_EMPTY.to_string());
    }

    match body[0] {
        TAG_AKA_SUCCESS => {
            let mut i = 1usize;
            let mut take = |what: &'static str| -> Result<Vec<u8>, String> {
                if i >= body.len() {
                    return Err(what.to_string());
                }
                let l = body[i] as usize;
                i += 1;
                if i + l > body.len() {
                    return Err(what.to_string());
                }
                let v = body[i..i + l].to_vec();
                i += l;
                Ok(v)
            };
            let res = take(err::AKA_SUCCESS_PARSE_FAILED)?;
            let ck = take(err::AKA_SUCCESS_PARSE_FAILED)?;
            let ik = take(err::AKA_SUCCESS_PARSE_FAILED)?;
            if res.is_empty() {
                return Err(err::AKA_RESPONSE_EMPTY.to_string());
            }
            Ok(AkaResult::Success { res, ck, ik })
        }
        TAG_AKA_SYNC_FAILURE => {
            if body.len() < 2 {
                return Err(err::AKA_SYNC_FAILURE_PARSE_FAILED.to_string());
            }
            let l = body[1] as usize;
            if 2 + l > body.len() {
                return Err(err::AKA_SYNC_FAILURE_PARSE_FAILED.to_string());
            }
            Ok(AkaResult::Resync {
                auts: body[2..2 + l].to_vec(),
            })
        }
        _ => Err(err::AKA_RESPONSE_UNKNOWN_TAG.to_string()),
    }
}

/// Parse EF_AD (administrative data). Byte 4 low nibble = MNC length.
pub fn parse_ef_ad(body: &[u8]) -> Option<usize> {
    if body.len() < 4 {
        return None;
    }
    let n = (body[3] & 0x0F) as usize;
    (n == 2 || n == 3).then_some(n)
}

/// `AT+CRSM` equivalent of the EF_AD read, for the AT fallback path.
/// 176 = READ BINARY, 28589 = 0x6FAD, 4 bytes.
///
/// **beta8-only (confidence C for beta9).** beta9 contains the `CRSM` token but
/// not this fully-formed command string, so it is likely composed at runtime.
pub const AT_CRSM_EF_AD: &str = "AT+CRSM=176,28589,0,0,4";

/// Parse `+CRSM: sw1,sw2,"hexdata"`.
pub fn parse_crsm(response: &str) -> Result<(StatusWord, Vec<u8>), String> {
    for line in response.lines() {
        let rest = match line.trim().strip_prefix("+CRSM:") {
            Some(r) => r.trim(),
            None => continue,
        };
        let f: Vec<&str> = rest.split(',').collect();
        if f.len() < 2 {
            continue;
        }
        let sw1 = f[0].trim().parse::<u8>().map_err(|_| err::APDU_EXCHANGE_FAILED.to_string())?;
        let sw2 = f[1].trim().parse::<u8>().map_err(|_| err::APDU_EXCHANGE_FAILED.to_string())?;
        let data = f
            .get(2)
            .map(|h| h.trim().trim_matches('"'))
            .unwrap_or("");
        let bytes = super::parse_hex(data).unwrap_or_default();
        return Ok((StatusWord::new(sw1, sw2), bytes));
    }
    Err(err::APDU_EXCHANGE_FAILED.to_string())
}
