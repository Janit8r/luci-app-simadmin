//! 裸 QMUX 客户端（OpenWrt 侧 IMS 承载 / AKA 的降级通道）。
//!
//! 设备侧实测版本（mifi44-ims / Android qmuxd）用自有 QMUX 客户端拉起 IMS PDN
//! 并直接走 UIM APDU；OpenWrt 上没有 qmuxd，但有两种等价通路：
//!
//! 1. `/dev/cdc-wdmN`（qmi_wwan 字符设备）——直接读写 QMUX 帧，无需代理；
//! 2. `@qmi-proxy`（libqmi 抽象 socket）——ModemManager 已占用设备时走这里，
//!    先发 `QMI_PROXY_OPEN(0xff00)` 打开设备，再正常发 QMUX 帧。
//!
//! 两条通路的帧格式完全一致（`[0x01][len u16][flags][svc][client][QMI...]`），
//! 编解码复用 `simadmin_device_runtime::qmi_uim` 里已经跑通的实现，避免第二套
//! 帧解析引入偏差。
//!
//! 服务号：CTL=0x00 / WDS=0x01 / DMS=0x02 / UIM=0x0b（**不是 0x03**，0x03 是
//! NAS，会把 UIM 消息回 DEVICE_UNSUPPORTED）。

use std::io::{Read, Write};
use std::time::Duration;

use simadmin_device_runtime::qmi_uim::{
    build_proxy_open_frame, decode_qmi_frame, encode_qmi_message, QmiMessage, QmiTlv,
};

pub const SVC_CTL: u8 = 0x00;
pub const SVC_WDS: u8 = 0x01;
pub const SVC_DMS: u8 = 0x02;
pub const SVC_UIM: u8 = 0x0b;

const CTL_ALLOCATE_CID: u16 = 0x0022;
const CTL_RELEASE_CID: u16 = 0x0023;
const QMI_PROXY_OPEN: u16 = 0xff00;

const WDS_SET_IP_FAMILY: u16 = 0x004d;
const WDS_START_NETWORK: u16 = 0x0020;
const WDS_GET_CURRENT_SETTINGS: u16 = 0x002d;
const WDS_BIND_MUX_DATA_PORT: u16 = 0x00a2;
const WDS_BIND_SUBSCRIPTION: u16 = 0x00af;
const DMS_GET_IMSI: u16 = 0x0043;
const UIM_OPEN_LOGICAL_CHANNEL: u16 = 0x0042;
const UIM_SEND_APDU: u16 = 0x003b;
const UIM_CLOSE_LOGICAL_CHANNEL: u16 = 0x003f;

const TLV_RESULT: u8 = 0x02;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(6);

// ---------------------------------------------------------------------------
// TLV 小工具
// ---------------------------------------------------------------------------

pub fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + v.len());
    out.push(t);
    out.extend_from_slice(&(v.len() as u16).to_le_bytes());
    out.extend_from_slice(v);
    out
}

pub fn each_tlv(b: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 3 <= b.len() {
        let t = b[i];
        let l = u16::from_le_bytes([b[i + 1], b[i + 2]]) as usize;
        if i + 3 + l > b.len() {
            break;
        }
        out.push((t, b[i + 3..i + 3 + l].to_vec()));
        i += 3 + l;
    }
    out
}

/// 解析 QMI 响应里的 result TLV（`result u16` + `error u16`）。
pub fn decode_result(tlvs: &[(u8, Vec<u8>)]) -> Option<(u16, u16)> {
    for (t, v) in tlvs {
        if *t == TLV_RESULT && v.len() >= 4 {
            return Some((
                u16::from_le_bytes([v[0], v[1]]),
                u16::from_le_bytes([v[2], v[3]]),
            ));
        }
    }
    None
}

/// `QmiMessage.tlvs` 已经解好帧了，这里只做形状转换，避免二次解析。
fn tlvs_of(msg: &QmiMessage) -> Vec<(u8, Vec<u8>)> {
    msg.tlvs
        .iter()
        .map(|t| (t.tlv_type, t.value.clone()))
        .collect()
}

fn result_ok(msg: &QmiMessage) -> Result<(), String> {
    match decode_result(&tlvs_of(msg)) {
        Some((0, _)) => Ok(()),
        Some((r, e)) => Err(format!("qmi_error result={r} err=0x{e:04x}")),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// 传输
// ---------------------------------------------------------------------------

enum Transport {
    Unix(std::os::unix::net::UnixStream),
    Dev(std::fs::File),
}

pub struct Qmux {
    transport: Transport,
    next_ctl: u16,
    next_service: u16,
}

impl Qmux {
    /// 打开一条 QMUX 通路。优先直接打开 `/dev/cdc-wdmN`（无代理开销），
    /// 被占用时退回 `@qmi-proxy`。
    pub fn open() -> Result<Self, String> {
        let device = find_qmi_device().ok_or_else(|| super::err::QMI_DEVICE_MISSING.to_string())?;
        match Self::open_device(&device) {
            Ok(client) => Ok(client),
            Err(direct_err) => {
                let proxy = std::env::var("SIMADMIN_QMI_PROXY")
                    .unwrap_or_else(|_| "@qmi-proxy".to_string());
                Self::open_proxy(&proxy, &device).map_err(|proxy_err| {
                    format!("qmi device {device}: direct={direct_err}; proxy={proxy_err}")
                })
            }
        }
    }

    /// 直接打开字符设备（qmux 帧直接读写）。
    pub fn open_device(path: &str) -> Result<Self, String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("open {path}: {e}"))?;
        Ok(Self {
            transport: Transport::Dev(file),
            next_ctl: 1,
            next_service: 1,
        })
    }

    /// 通过 libqmi 代理打开（ModemManager 占用设备时唯一可行路径）。
    pub fn open_proxy(socket: &str, device_path: &str) -> Result<Self, String> {
        let stream = connect_socket(socket)?;
        stream
            .set_read_timeout(Some(DEFAULT_TIMEOUT))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(DEFAULT_TIMEOUT))
            .map_err(|e| e.to_string())?;
        let mut client = Self {
            transport: Transport::Unix(stream),
            next_ctl: 1,
            next_service: 1,
        };
        let frame = build_proxy_open_frame(device_path, 1).map_err(|e| e.to_string())?;
        let response = client.send_recv(&frame, DEFAULT_TIMEOUT)?;
        if response.message_id != QMI_PROXY_OPEN {
            return Err("qmi proxy open: unexpected message".to_string());
        }
        result_ok(&response)?;
        Ok(client)
    }

    fn take_ctl(&mut self) -> u16 {
        let current = self.next_ctl;
        self.next_ctl = if current >= u8::MAX as u16 { 1 } else { current + 1 };
        current
    }

    fn take_service(&mut self) -> u16 {
        let current = self.next_service;
        self.next_service = if current == u16::MAX { 1 } else { current + 1 };
        current
    }

    fn send_recv(&mut self, frame: &[u8], timeout: Duration) -> Result<QmiMessage, String> {
        match &mut self.transport {
            Transport::Unix(stream) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|e| e.to_string())?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|e| e.to_string())?;
                stream.write_all(frame).map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
                read_frame(stream, timeout)
            }
            Transport::Dev(file) => {
                file.write_all(frame).map_err(|e| e.to_string())?;
                file.flush().map_err(|e| e.to_string())?;
                read_frame(file, timeout)
            }
        }
    }

    /// 发一条服务请求（自动分配 transaction id）。
    pub fn request(
        &mut self,
        service: u8,
        client_id: u8,
        message_id: u16,
        tlvs: &[u8],
        timeout: Duration,
    ) -> Result<QmiMessage, String> {
        let txn = if service == SVC_CTL {
            self.take_ctl()
        } else {
            self.take_service()
        };
        let message = QmiMessage {
            service,
            client_id,
            transaction_id: txn,
            message_id,
            tlvs: decode_tlvs(tlvs),
        };
        let frame = encode_qmi_message(&message).map_err(|e| e.to_string())?;
        self.send_recv(&frame, timeout)
    }

    /// 分配一个服务客户端 id（CTL 0x0022）。
    pub fn allocate_client(&mut self, service: u8) -> Result<u8, String> {
        let response = self.request(SVC_CTL, 0, CTL_ALLOCATE_CID, &tlv(0x01, &[service]), DEFAULT_TIMEOUT)?;
        if response.message_id != CTL_ALLOCATE_CID {
            return Err("ctl allocate: unexpected message".to_string());
        }
        result_ok(&response)?;
        for (t, v) in tlvs_of(&response) {
            if t == 0x01 && v.len() >= 2 {
                return Ok(v[1]);
            }
        }
        Err("ctl allocate: no client id".to_string())
    }

    /// 释放客户端 id（失败可忽略，进程退出后设备会回收）。
    pub fn release_client(&mut self, service: u8, client_id: u8) {
        let value = vec![service, client_id];
        let _ = self.request(
            SVC_CTL,
            0,
            CTL_RELEASE_CID,
            &tlv(0x01, &value),
            Duration::from_secs(3),
        );
    }

    // -----------------------------------------------------------------------
    // WDS：IMS PDN
    // -----------------------------------------------------------------------

    /// 把 WDS 客户端切到 IPv6 家族。
    pub fn wds_set_ip_family_v6(&mut self, client_id: u8) -> Result<(), String> {
        let response = self.request(
            SVC_WDS,
            client_id,
            WDS_SET_IP_FAMILY,
            &tlv(0x01, &[6u8]),
            DEFAULT_TIMEOUT,
        )?;
        result_ok(&response)
    }

    /// 绑定 mux 数据口（mux=2 → rmnet_data1，与 default-attach 的 mux1 分开）。
    pub fn wds_bind_mux(&mut self, client_id: u8, mux: u8) -> Result<(), String> {
        let response = self.request(
            SVC_WDS,
            client_id,
            WDS_BIND_MUX_DATA_PORT,
            &tlv(0x11, &[mux]),
            DEFAULT_TIMEOUT,
        )?;
        result_ok(&response)
    }

    /// 绑定 subscription（默认 sub 1）。
    pub fn wds_bind_subscription(&mut self, client_id: u8) -> Result<(), String> {
        let response = self.request(
            SVC_WDS,
            client_id,
            WDS_BIND_SUBSCRIPTION,
            &tlv(0x01, &1u32.to_le_bytes()),
            DEFAULT_TIMEOUT,
        )?;
        result_ok(&response)
    }

    /// 拉起 PDN。`profile` 为 0 时按参数里的 APN 直接下发（TLV 0x0e）。
    ///
    /// 先按 IPv6 家族请求；老固件或只开 IPv4 的 IMS APN 会拒绝 TLV 0x19，
    /// 这时去掉该 TLV 再试一次（让 Modem 用自身默认家族），尽量拿到承载。
    pub fn wds_start_network(
        &mut self,
        client_id: u8,
        apn: &str,
        profile: Option<u8>,
    ) -> Result<(), String> {
        match self.wds_start_network_family(client_id, apn, profile, Some(6)) {
            Ok(()) => Ok(()),
            Err(first) => match self.wds_start_network_family(client_id, apn, profile, None) {
                Ok(()) => Ok(()),
                Err(second) => Err(format!("{first}; 去掉 ip-family 重试: {second}")),
            },
        }
    }

    fn wds_start_network_family(
        &mut self,
        client_id: u8,
        apn: &str,
        profile: Option<u8>,
        family: Option<u8>,
    ) -> Result<(), String> {
        let mut tlvs = Vec::new();
        if let Some(family) = family {
            tlvs.extend(tlv(0x19, &[family])); // IP family
        }
        if let Some(index) = profile {
            tlvs.extend(tlv(0x31, &[index]));
        } else if !apn.is_empty() {
            // TLV 0x0e = APN 字符串（不带长度前缀）
            tlvs.extend(tlv(0x0e, apn.as_bytes()));
        }
        let response = self.request(
            SVC_WDS,
            client_id,
            WDS_START_NETWORK,
            &tlvs,
            Duration::from_secs(20),
        )?;
        result_ok(&response)
    }

    /// 读动态参数。mask 必须含 IP_ADDRESS（0x0100），默认 0x8210 拿不到本机地址。
    pub fn wds_current_settings(&mut self, client_id: u8) -> Result<WdsSettings, String> {
        let response = self.request(
            SVC_WDS,
            client_id,
            WDS_GET_CURRENT_SETTINGS,
            &tlv(0x10, &0x8310u32.to_le_bytes()),
            DEFAULT_TIMEOUT,
        )?;
        result_ok(&response)?;
        Ok(parse_wds_settings(&tlvs_of(&response)))
    }

    // -----------------------------------------------------------------------
    // DMS / UIM
    // -----------------------------------------------------------------------

    pub fn dms_imsi(&mut self, client_id: u8) -> Result<String, String> {
        let response = self.request(SVC_DMS, client_id, DMS_GET_IMSI, &[], DEFAULT_TIMEOUT)?;
        result_ok(&response)?;
        for (t, v) in tlvs_of(&response) {
            if t == 0x01 {
                if let Ok(s) = String::from_utf8(v) {
                    if !s.trim().is_empty() {
                        return Ok(s.trim().to_string());
                    }
                }
            }
        }
        Err(super::err::IMSI_MISSING.to_string())
    }

    /// 打开逻辑通道。`wide_aid` = AID 长度前缀用 u16（部分固件要求）。
    pub fn uim_open_channel(
        &mut self,
        client_id: u8,
        slot: u8,
        aid: &[u8],
        wide_aid: bool,
    ) -> Result<u8, String> {
        let mut aid_value = Vec::new();
        if wide_aid {
            aid_value.extend_from_slice(&(aid.len() as u16).to_le_bytes());
        } else {
            aid_value.push(aid.len() as u8);
        }
        aid_value.extend_from_slice(aid);
        let mut tlvs = tlv(0x01, &[slot]);
        tlvs.extend(tlv(0x10, &aid_value));
        let response = self.request(
            SVC_UIM,
            client_id,
            UIM_OPEN_LOGICAL_CHANNEL,
            &tlvs,
            Duration::from_secs(10),
        )?;
        result_ok(&response)?;
        for (t, v) in tlvs_of(&response) {
            if t == 0x10 && !v.is_empty() {
                return Ok(v[0]);
            }
        }
        Err("uim open-channel: no channel id".to_string())
    }

    pub fn uim_close_channel(
        &mut self,
        client_id: u8,
        slot: u8,
        channel: u8,
    ) -> Result<(), String> {
        let mut tlvs = tlv(0x01, &[slot]);
        tlvs.extend(tlv(0x11, &[channel]));
        let response = self.request(
            SVC_UIM,
            client_id,
            UIM_CLOSE_LOGICAL_CHANNEL,
            &tlvs,
            DEFAULT_TIMEOUT,
        )?;
        result_ok(&response)
    }

    /// 发 APDU，返回含状态字的完整响应。
    pub fn uim_send_apdu(
        &mut self,
        client_id: u8,
        slot: u8,
        channel: u8,
        apdu: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut apdu_value = (apdu.len() as u16).to_le_bytes().to_vec();
        apdu_value.extend_from_slice(apdu);
        let mut tlvs = tlv(0x01, &[slot]);
        tlvs.extend(tlv(0x02, &apdu_value));
        tlvs.extend(tlv(0x10, &[channel]));
        let response = self.request(
            SVC_UIM,
            client_id,
            UIM_SEND_APDU,
            &tlvs,
            Duration::from_secs(10),
        )?;
        result_ok(&response)?;
        for (t, v) in tlvs_of(&response) {
            if t == 0x10 {
                if v.len() >= 2 {
                    let n = u16::from_le_bytes([v[0], v[1]]) as usize;
                    if 2 + n == v.len() {
                        return Ok(v[2..].to_vec());
                    }
                }
                if !v.is_empty() && v[0] as usize + 1 == v.len() {
                    return Ok(v[1..].to_vec());
                }
                return Ok(v);
            }
        }
        Err("uim send-apdu: no response tlv".to_string())
    }
}

fn decode_tlvs(bytes: &[u8]) -> Vec<QmiTlv> {
    each_tlv(bytes)
        .into_iter()
        .map(|(t, value)| QmiTlv { tlv_type: t, value })
        .collect()
}

fn connect_socket(socket: &str) -> Result<std::os::unix::net::UnixStream, String> {
    if let Some(name) = socket.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixStream};
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).map_err(|e| e.to_string())?;
        UnixStream::connect_addr(&addr).map_err(|e| format!("connect @{name}: {e}"))
    } else {
        std::os::unix::net::UnixStream::connect(socket)
            .map_err(|e| format!("connect {socket}: {e}"))
    }
}

/// 读一整帧。Unix socket 与字符设备的头部布局一致（`[0x01][len u16]`）。
///
/// 字符设备（/dev/cdc-wdmN）不支持 SO_RCVTIMEO，所以统一用 `poll` 限时，
/// 避免 IMS 承载异常时把调用线程永久挂住。
fn read_frame<R: Read + std::os::unix::io::AsRawFd>(
    reader: &mut R,
    timeout: Duration,
) -> Result<QmiMessage, String> {
    wait_readable(reader.as_raw_fd(), timeout)?;
    let mut header = [0u8; 3];
    reader.read_exact(&mut header).map_err(|e| format!("qmi read: {e}"))?;
    if header[0] != 0x01 {
        return Err("qmi read: bad iftype".to_string());
    }
    let qmux_len = u16::from_le_bytes([header[1], header[2]]) as usize;
    if qmux_len < 5 || qmux_len > 8192 {
        return Err(format!("qmi read: bad length {qmux_len}"));
    }
    let mut frame = Vec::with_capacity(1 + qmux_len);
    frame.extend_from_slice(&header);
    frame.resize(1 + qmux_len, 0);
    wait_readable(reader.as_raw_fd(), timeout)?;
    reader
        .read_exact(&mut frame[3..])
        .map_err(|e| format!("qmi read body: {e}"))?;
    decode_qmi_frame(&frame).map_err(|e| format!("qmi decode: {e}"))
}

fn wait_readable(fd: i32, timeout: Duration) -> Result<(), String> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
    let rc = unsafe { libc::poll(&mut pfd, 1, millis) };
    if rc < 0 {
        return Err(format!("qmi poll: {}", std::io::Error::last_os_error()));
    }
    if rc == 0 {
        return Err("qmi timeout".to_string());
    }
    Ok(())
}

/// 找 QMI 控制口。
///
/// 两代命名并存：
///   - 老内核 / `qmi_wwan`：`/dev/cdc-wdm<N>`
///   - 新 `wwan` 子系统（msm8916 的 `bam-dmux` 等）：`/dev/wwan<N>qmi<M>`
///
/// 设备实测（ImmortalWrt 7.3 / msm8916 / bam-dmux）只有 `wwan0qmi0`，
/// 早期只扫 `cdc-wdm*` 会直接报 `volte_qmi_device_missing`。
fn find_qmi_device() -> Option<String> {
    for index in 0..4 {
        let path = format!("/dev/cdc-wdm{index}");
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }

    let mut found: Vec<(u32, u32, String)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy().to_string();
            if let Some((device, port)) = parse_wwan_qmi_name(&name) {
                found.push((device, port, format!("/dev/{name}")));
            }
        }
    }
    // 编号排序，避免 read_dir 顺序不定时选到非主口。
    found.sort();
    found.into_iter().next().map(|(_, _, path)| path)
}

/// 解析 `wwan<N>qmi<M>` 形式的设备名，返回 `(N, M)`。
fn parse_wwan_qmi_name(name: &str) -> Option<(u32, u32)> {
    let rest = name.strip_prefix("wwan")?;
    let (device, port) = rest.split_once("qmi")?;
    if device.is_empty() || port.is_empty() {
        return None;
    }
    Some((device.parse().ok()?, port.parse().ok()?))
}

// ---------------------------------------------------------------------------
// WDS Get Current Settings 解析
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WdsSettings {
    pub ipv6: Option<std::net::Ipv6Addr>,
    pub prefix: u8,
    pub gateway: Option<std::net::Ipv6Addr>,
    pub dns: Vec<std::net::Ipv6Addr>,
    pub ipv4: Option<std::net::Ipv4Addr>,
}

/// 解析 0x002D 响应。TLV 布局（libqmi 权威）：
/// 0x25 = IPv6 地址（16B + 1B 前缀）/ 0x26 = IPv6 网关（16B + 1B）
/// 0x27、0x28 = IPv6 DNS / 0x1e = IPv4 地址（4B + 1B 前缀 + 4B 网关 + 4B DNS）
pub fn parse_wds_settings(tlvs: &[(u8, Vec<u8>)]) -> WdsSettings {
    let mut out = WdsSettings { prefix: 64, ..Default::default() };
    for (t, v) in tlvs {
        match *t {
            0x25 if v.len() >= 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&v[..16]);
                out.ipv6 = Some(std::net::Ipv6Addr::from(b));
                if v.len() >= 17 && v[16] <= 128 {
                    out.prefix = v[16];
                }
            }
            0x26 if v.len() >= 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&v[..16]);
                out.gateway = Some(std::net::Ipv6Addr::from(b));
            }
            0x27 | 0x28 if v.len() >= 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&v[..16]);
                let addr = std::net::Ipv6Addr::from(b);
                if !out.dns.contains(&addr) {
                    out.dns.push(addr);
                }
            }
            0x1e if v.len() >= 4 => {
                out.ipv4 = Some(std::net::Ipv4Addr::new(v[0], v[1], v[2], v[3]));
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_roundtrip() {
        let mut bytes = tlv(0x01, &[6]);
        bytes.extend(tlv(0x31, &[4]));
        let parsed = each_tlv(&bytes);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], (0x01, vec![6]));
        assert_eq!(parsed[1], (0x31, vec![4]));
    }

    #[test]
    fn wwan_qmi_device_names() {
        // 设备实测：msm8916 + bam-dmux 只有 wwan 子系统命名
        assert_eq!(parse_wwan_qmi_name("wwan0qmi0"), Some((0, 0)));
        assert_eq!(parse_wwan_qmi_name("wwan1qmi0"), Some((1, 0)));
        assert_eq!(parse_wwan_qmi_name("wwan0qmi1"), Some((0, 1)));
        // AT 口、网络口、无关节点都不能被当成 QMI 控制口
        assert_eq!(parse_wwan_qmi_name("wwan0at0"), None);
        assert_eq!(parse_wwan_qmi_name("wwan0"), None);
        assert_eq!(parse_wwan_qmi_name("cdc-wdm0"), None);
        assert_eq!(parse_wwan_qmi_name("wwanqmi0"), None);
        assert_eq!(parse_wwan_qmi_name("wwan0qmi"), None);
    }

    #[test]
    fn result_tlv_decodes_success_and_error() {
        let ok = tlv(TLV_RESULT, &[0, 0, 0, 0]);
        assert_eq!(decode_result(&each_tlv(&ok)), Some((0, 0)));
        let err = tlv(TLV_RESULT, &[1, 0, 0x2e, 0]);
        assert_eq!(decode_result(&each_tlv(&err)), Some((1, 0x2e)));
    }

    #[test]
    fn parses_ipv6_current_settings() {
        let addr = "2408:8556:450:ccb1:31d6:d59c:3902:3148".parse::<std::net::Ipv6Addr>().unwrap();
        let gw = "2408:8556:450:ccb1:c49e:1bd7:12d4:e72d".parse::<std::net::Ipv6Addr>().unwrap();
        let mut value = addr.octets().to_vec();
        value.push(64);
        let mut bytes = tlv(0x25, &value);
        let mut gw_value = gw.octets().to_vec();
        gw_value.push(64);
        bytes.extend(tlv(0x26, &gw_value));
        let parsed = parse_wds_settings(&each_tlv(&bytes));
        assert_eq!(parsed.ipv6, Some(addr));
        assert_eq!(parsed.gateway, Some(gw));
        assert_eq!(parsed.prefix, 64);
    }
}
