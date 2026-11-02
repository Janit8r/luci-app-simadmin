//! IMS 身份推导。
//!
//! 归属域完全由 SIM 的 MCC/MNC 决定，不做任何运营商硬编码：
//!
//! ```text
//! IMSI 460 01 0876089383
//!      └──┘ └┘
//!      MCC  MNC
//!   → ims.mnc001.mcc460.3gppnetwork.org
//! ```
//!
//! MNC 长度在 2 位与 3 位之间存在歧义（`46001` 可能是 MCC=460/MNC=01，
//! 也可能是 MCC=460/MNC=001），必须由 EF_AD 或运营商信息决定，不能猜。

use crate::volte::{codes, VolteError};

/// IMS 身份信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImsIdentity {
    /// 国际移动用户识别码（15 位十进制）
    pub imsi: String,
    /// 移动国家码（3 位）
    pub mcc: String,
    /// 移动网络码（2 或 3 位，保留原始宽度）
    pub mnc: String,
    /// 归属域，例如 `ims.mnc001.mcc460.3gppnetwork.org`
    pub home_domain: String,
    /// 公有用户身份（IMPU），`sip:{imsi}@{home_domain}`
    pub public_identity: String,
    /// 短信中心号码，可为空
    pub smsc: String,
}

impl ImsIdentity {
    /// 由 IMSI、MNC 长度与 SMSC 构造身份。
    ///
    /// `mnc_length` 必须是 2 或 3；`smsc` 允许为空（部分场景只做注册不发送）。
    pub fn derive(
        imsi: &str,
        mnc_length: u8,
        smsc: Option<&str>,
    ) -> Result<Self, VolteError> {
        let imsi = imsi.trim();
        if !is_decimal(imsi) {
            return Err(VolteError::with_detail(
                codes::IMSI_MISSING,
                "imsi is not decimal digits",
            ));
        }
        // MCC 固定 3 位，MNC 占 2~3 位，因此 IMSI 至少 5 位。
        if imsi.len() < 5 {
            return Err(VolteError::with_detail(
                codes::IMSI_MISSING,
                format!("imsi too short: {}", imsi.len()),
            ));
        }
        if mnc_length != 2 && mnc_length != 3 {
            return Err(VolteError::with_detail(
                codes::IMSI_MISSING,
                format!("invalid mnc_length: {mnc_length}"),
            ));
        }
        let need = 3 + mnc_length as usize;
        if imsi.len() < need {
            return Err(VolteError::with_detail(
                codes::IMSI_MISSING,
                format!("imsi too short for mnc_length {mnc_length}"),
            ));
        }

        let mcc = &imsi[..3];
        let mnc = &imsi[3..need];
        let home_domain = format!(
            "ims.mnc{:0>3}.mcc{:0>3}.3gppnetwork.org",
            mnc, mcc
        );
        let public_identity = format!("sip:{}@{}", imsi, home_domain);

        Ok(Self {
            imsi: imsi.to_string(),
            mcc: mcc.to_string(),
            mnc: mnc.to_string(),
            home_domain,
            public_identity,
            smsc: smsc.unwrap_or_default().trim().to_string(),
        })
    }

    /// 带括号的 SIP URI 形式，用于 Contact 头里的主机部分。
    pub fn sip_uri_with_host(&self, host: &str) -> String {
        format!("sip:{}@[{}]", self.imsi, host)
    }

    /// 裸 SIP URI 形式（不带括号），用于 Route 头等。
    pub fn sip_uri_with_host_plain(&self, host: &str) -> String {
        format!("sip:{}@{}", self.imsi, host)
    }
}

fn is_decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_domain_for_2_digit_mnc() {
        let id = ImsIdentity::derive("460010876089383", 2, Some("+8613010200500")).unwrap();
        assert_eq!(id.mcc, "460");
        assert_eq!(id.mnc, "01");
        assert_eq!(id.home_domain, "ims.mnc001.mcc460.3gppnetwork.org");
        assert_eq!(
            id.public_identity,
            "sip:460010876089383@ims.mnc001.mcc460.3gppnetwork.org"
        );
        assert_eq!(id.smsc, "+8613010200500");
    }

    #[test]
    fn derives_domain_for_3_digit_mnc() {
        let id = ImsIdentity::derive("460011123456789", 3, None).unwrap();
        assert_eq!(id.mcc, "460");
        assert_eq!(id.mnc, "011");
        assert_eq!(id.home_domain, "ims.mnc011.mcc460.3gppnetwork.org");
        assert!(id.smsc.is_empty());
    }

    #[test]
    fn rejects_non_decimal_imsi() {
        assert!(ImsIdentity::derive("46001abc", 2, None).is_err());
    }

    #[test]
    fn rejects_short_imsi() {
        assert!(ImsIdentity::derive("460", 2, None).is_err());
    }

    #[test]
    fn rejects_bad_mnc_length() {
        assert!(ImsIdentity::derive("460010876089383", 4, None).is_err());
    }
}
