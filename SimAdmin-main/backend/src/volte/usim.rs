//! USIM AKA 双通道：qmi-proxy（优先）→ 裸 QMUX UIM（降级）。
//!
//! 两条通道做的事完全一样：在 USIM 逻辑通道上发 AUTHENTICATE(RAND, AUTN)，
//! 卡返回 RES/CK/IK，或返回 AUTS 表示序列号失步需要 resync。
//!
//! - 优先走 `simadmin_device_runtime::qmi_uim`：它已经在 eSIM/APDU 场景下跑通，
//!   且 `@qmi-proxy` 能与 ModemManager 共存（MM 常驻时唯一能用的通路）。
//! - 降级走自有 QMUX：`QMI UIM(0x0b)` Open Logical Channel → Send APDU →
//!   Close，帧布局与设备侧实测版本一致。

use std::time::Duration;

use simadmin_device_runtime::qmi_uim::execute_usim_authenticate_via_proxy;

use super::aka::{AkaChallenge, AkaResult};
use super::qmi_raw::{Qmux, SVC_UIM};
use super::uim;

/// 逻辑通道槽位（单卡设备固定 1）。
pub const USIM_SLOT: u8 = 1;

/// 走哪条通道完成了 AKA。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AkaTransport {
    QmiProxy,
    RawQmux,
}

impl AkaTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            AkaTransport::QmiProxy => "qmi_proxy",
            AkaTransport::RawQmux => "raw_qmux",
        }
    }
}

/// 执行一次 AKA。返回卡的结果与所用通道。
pub fn authenticate(
    challenge: &AkaChallenge,
    aid: &[u8],
) -> Result<(AkaResult, AkaTransport), String> {
    let mut errors: Vec<String> = Vec::new();

    match via_proxy(challenge, aid) {
        Ok(result) => return Ok((result, AkaTransport::QmiProxy)),
        Err(error) => {
            errors.push(format!("qmi_proxy: {error}"));
            tracing::warn!(
                target: "simadmin::volte",
                error = %error,
                "USIM AKA qmi-proxy 通道失败，降级裸 QMUX"
            );
        }
    }

    match via_raw_qmux(challenge, aid) {
        Ok(result) => Ok((result, AkaTransport::RawQmux)),
        Err(error) => {
            errors.push(format!("raw_qmux: {error}"));
            Err(format!("{}: {}", super::err::USIM_AKA_FAILED, errors.join("; ")))
        }
    }
}

fn via_proxy(challenge: &AkaChallenge, aid: &[u8]) -> Result<AkaResult, String> {
    let device = find_qmi_device().ok_or_else(|| super::err::QMI_DEVICE_MISSING.to_string())?;
    let socket =
        std::env::var("SIMADMIN_QMI_PROXY").unwrap_or_else(|_| "@qmi-proxy".to_string());
    let result = execute_usim_authenticate_via_proxy(
        &socket,
        &device,
        USIM_SLOT,
        aid,
        &challenge.rand,
        &challenge.autn,
        Duration::from_secs(12),
    )
    .map_err(|e| format!("{e}"))?;

    if let Some(auts) = result.auts {
        return Ok(AkaResult::Resync { auts });
    }
    Ok(AkaResult::Success {
        res: result.res,
        ck: result.ck,
        ik: result.ik,
    })
}

fn via_raw_qmux(challenge: &AkaChallenge, aid: &[u8]) -> Result<AkaResult, String> {
    let mut qmux = Qmux::open()?;
    let client = qmux.allocate_client(SVC_UIM)?;
    let result = (|| -> Result<AkaResult, String> {
        let channel = open_channel(&mut qmux, client, aid)?;
        let outcome = (|| -> Result<AkaResult, String> {
            // Open Logical Channel 通常已经选中 ADF，但部分固件要求再显式 SELECT。
            let select = uim::apdu_select_aid(channel, aid)
                .encode()
                .map_err(|e| format!("select apdu: {e}"))?;
            let _ = qmux.uim_send_apdu(client, USIM_SLOT, channel, &select);

            let apdu = uim::apdu_authenticate(channel, &challenge.rand, &challenge.autn)
                .encode()
                .map_err(|e| format!("authenticate apdu: {e}"))?;
            let mut response = qmux.uim_send_apdu(client, USIM_SLOT, channel, &apdu)?;

            // 61 XX = 还有数据；6C XX = Le 不对，换 Le 重发。
            let (_, status) = uim::split_response(&response)?;
            if let Some(len) = status.more_data() {
                let get = uim::apdu_get_response(channel, len)
                    .encode()
                    .map_err(|e| format!("get-response apdu: {e}"))?;
                response = qmux.uim_send_apdu(client, USIM_SLOT, channel, &get)?;
            } else if status.wrong_length().is_some() {
                let mut adjusted = apdu.clone();
                if let Some(last) = adjusted.last_mut() {
                    *last = status.sw2;
                }
                response = qmux.uim_send_apdu(client, USIM_SLOT, channel, &adjusted)?;
            }

            let (body, status) = uim::split_response(&response)?;
            if !status.is_success() {
                return Err(status
                    .to_error()
                    .unwrap_or(super::err::USIM_AKA_FAILED)
                    .to_string());
            }
            uim::parse_authenticate_response(body)
        })();
        let _ = qmux.uim_close_channel(client, USIM_SLOT, channel);
        outcome
    })();
    qmux.release_client(SVC_UIM, client);
    result
}

/// 打开 USIM 逻辑通道；AID 长度前缀先试 u8，失败再试 u16。
fn open_channel(qmux: &mut Qmux, client: u8, aid: &[u8]) -> Result<u8, String> {
    match qmux.uim_open_channel(client, USIM_SLOT, aid, false) {
        Ok(channel) => Ok(channel),
        Err(first) => qmux
            .uim_open_channel(client, USIM_SLOT, aid, true)
            .map_err(|second| format!("open-channel: {first}; wide: {second}")),
    }
}

fn find_qmi_device() -> Option<String> {
    for index in 0..4 {
        let path = format!("/dev/cdc-wdm{index}");
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// EF_SMSC 读取（IMS 侧必须自带 SMSC 号码，否则 MESSAGE 无法定址）
// ---------------------------------------------------------------------------
//
// 设备侧笔记：EF_SMSC 是**线性固定**文件，READ BINARY 会返回 SW=6981
// （command incompatible with file structure），必须用 READ RECORD。
// 路径为 MF(3F00) → DF_TELECOM(7F10) → EF_SMSC(6F42)，记录 1。

/// EF_SMSC（短消息服务中心地址）。
pub const EF_SMSC: u16 = 0x6F42;
/// DF_TELECOM。
pub const DF_TELECOM: u16 = 0x7F10;
/// 主文件。
pub const MF: u16 = 0x3F00;

/// 读取 EF_SMSC，返回可拨号串（国际号码带 `+`）。
///
/// 通道顺序：裸 QMUX UIM（自包含）→ `mmcli AT+CRSM`（ModemManager 存在时）。
pub fn read_ef_smsc() -> Option<String> {
    if let Some(smsc) = via_raw_qmux_smsc() {
        return Some(smsc);
    }
    via_at_crsm_smsc()
}

fn via_raw_qmux_smsc() -> Option<String> {
    let mut qmux = Qmux::open().ok()?;
    let client = qmux.allocate_client(SVC_UIM).ok()?;
    let record = (|| -> Result<Vec<u8>, String> {
        // 基础通道（channel 0）落在 MF，正好是 DF_TELECOM 的父节点。
        let _ = exchange(&mut qmux, client, &select_file_apdu(MF))?;
        let _ = exchange(&mut qmux, client, &select_file_apdu(DF_TELECOM))?;
        exchange(&mut qmux, client, &read_record_apdu(1, 0x28))
    })();
    qmux.release_client(SVC_UIM, client);
    parse_smsc_record(&record.ok()?)
}

fn via_at_crsm_smsc() -> Option<String> {
    let output = std::process::Command::new("mmcli")
        .args([
            "-m",
            "any",
            "--command=AT+CRSM=178,28482,1,4,40,\"\",\"7F10\"",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let (status, body) = uim::parse_crsm(&text).ok()?;
    if !status.is_success() {
        return None;
    }
    parse_smsc_record(&body)
}

/// 发送 APDU，自动处理 `61 XX`（GET RESPONSE）与 `6C XX`（换 Le 重发）。
fn exchange(qmux: &mut Qmux, client: u8, apdu: &[u8]) -> Result<Vec<u8>, String> {
    let mut response = qmux.uim_send_apdu(client, USIM_SLOT, 0, apdu)?;
    let (_, mut status) = uim::split_response(&response)?;

    if let Some(len) = status.more_data() {
        let get = uim::apdu_get_response(0, len)
            .encode()
            .map_err(|e| format!("get-response apdu: {e}"))?;
        response = qmux.uim_send_apdu(client, USIM_SLOT, 0, &get)?;
        let (_, next) = uim::split_response(&response)?;
        status = next;
    } else if status.wrong_length().is_some() {
        let mut adjusted = apdu.to_vec();
        if let Some(last) = adjusted.last_mut() {
            *last = status.sw2;
        }
        response = qmux.uim_send_apdu(client, USIM_SLOT, 0, &adjusted)?;
        let (_, next) = uim::split_response(&response)?;
        status = next;
    }

    if !status.is_success() {
        return Err(status
            .to_error()
            .unwrap_or("sim_smsc_apdu_failed")
            .to_string());
    }
    let (body, _) = uim::split_response(&response)?;
    Ok(body.to_vec())
}

/// SELECT by file id（P1=0x00 直接给 FID）。
fn select_file_apdu(file: u16) -> Vec<u8> {
    vec![
        0xA0,
        0xA4,
        0x00,
        0x00,
        0x02,
        (file >> 8) as u8,
        (file & 0xFF) as u8,
    ]
}

/// READ RECORD（P2=0x04 绝对记录号，Le 给足长度）。
fn read_record_apdu(record: u8, le: u8) -> Vec<u8> {
    vec![0xA0, 0xB2, record, 0x04, le]
}

/// 解析 EF_SMSC 记录。
///
/// 布局（TS 31.102 §4.2.16 → TS 23.040 §9.1.2.5）：
/// ```text
///   [0] 地址长度（八位组数，部分卡把它算成"含 TOA"，故按可用长度钳位）
///   [1] Type-of-Address
///   [2..] 地址值（半八位组，低位在前）
/// ```
/// 某些卡把它包成 TLV（tag 0x80）。
pub fn parse_smsc_record(data: &[u8]) -> Option<String> {
    let body = unwrap_tlv(data);
    if body.len() < 2 {
        return None;
    }
    let declared = body[0] as usize;
    if declared == 0 || declared == 0xFF {
        return None;
    }
    let toa = body[1];
    let avail = body.len() - 2;
    // 半八位组解码对尾部 0xFF 填充天然免疫，所以这里按 declared 取、
    // 超界则退化为全部可用字节，兼容"长度含 TOA"的写法。
    let n = declared.min(avail).max(1);
    let value = &body[2..2 + n];

    let mut digits = String::new();
    for byte in value {
        for nibble in [byte & 0x0F, byte >> 4] {
            match nibble {
                0..=9 => digits.push((b'0' + nibble) as char),
                0x0A => digits.push('*'),
                0x0B => digits.push('#'),
                0x0C => digits.push('a'),
                0x0D => digits.push('b'),
                0x0E => digits.push('c'),
                _ => {}
            }
        }
    }

    if digits.chars().filter(char::is_ascii_digit).count() < 3 {
        return None;
    }
    // TOA 高三位 0x10 = 国际号码
    if toa & 0x70 == 0x10 {
        Some(format!("+{digits}"))
    } else {
        Some(digits)
    }
}

/// 若首字节是 TLV tag 0x80，剥掉 tag/len。
fn unwrap_tlv(data: &[u8]) -> &[u8] {
    if data.len() >= 3 && data[0] == 0x80 {
        let len = data[1] as usize;
        if len + 2 <= data.len() && len >= 2 {
            return &data[2..2 + len];
        }
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_tokens_are_stable() {
        assert_eq!(AkaTransport::QmiProxy.as_str(), "qmi_proxy");
        assert_eq!(AkaTransport::RawQmux.as_str(), "raw_qmux");
    }

    #[test]
    fn parses_international_smsc() {
        // 06 91 68 31 08 60 87 19  → +861380067891
        let raw = [
            0x06, 0x91, 0x68, 0x31, 0x08, 0x60, 0x87, 0x19, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        assert_eq!(parse_smsc_record(&raw).as_deref(), Some("+861380067891"));
    }

    #[test]
    fn parses_smsc_with_tlv_wrapper() {
        let raw = [
            0x80, 0x09, 0x07, 0x91, 0x68, 0x31, 0x08, 0x60, 0x87, 0x19, 0xF0, 0xFF,
        ];
        assert_eq!(parse_smsc_record(&raw).as_deref(), Some("+8613800678910"));
    }

    #[test]
    fn rejects_empty_smsc() {
        assert!(parse_smsc_record(&[0xFF; 12]).is_none());
        assert!(parse_smsc_record(&[]).is_none());
    }
}
