//! 注册状态机与对外状态快照。
//!
//! 这一层只做状态记账：阶段、子步骤、失败原因、计数、时间戳。真正的
//! 网络动作（建承载、发 SIP、装 IPsec）由 `volte_manager` 驱动，状态变化
//! 通过本模块的方法记录，最终序列化成 `/api/volte/control` 的 `runtime` 段。
//!
//! 拆开的原因是：注册流程牵涉异步 I/O 与外部命令，很难在单元测试里跑通；
//! 而"失败之后状态该长什么样"是前端直接依赖的契约，必须能独立验证。

use chrono::Local;

use crate::models::VolteRuntimeStatus;
use crate::volte::Phase;

/// 运行时状态记账器。
#[derive(Debug, Clone)]
pub struct RuntimeState {
    phase: Phase,
    stage: String,
    enabled: bool,
    registered: bool,
    registration_mode: Option<String>,
    interface: Option<String>,
    family: Option<String>,
    local_ip: Option<String>,
    pcscf: Option<String>,
    session_started_at: Option<String>,
    registered_at: Option<String>,
    last_rx_at: Option<String>,
    last_tx_at: Option<String>,
    last_error: Option<String>,
    last_failure_at: Option<String>,
    next_retry_at: Option<String>,
    retry_after_secs: Option<u64>,
    degraded_reason: Option<String>,
    sent_count: u64,
    received_count: u64,
    duplicate_count: u64,
    reconnect_count: u64,
    failure_count: u64,
    data_path_mode: Option<String>,
    data_path_degraded_reason: Option<String>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            stage: String::new(),
            enabled: false,
            registered: false,
            registration_mode: None,
            interface: None,
            family: None,
            local_ip: None,
            pcscf: None,
            session_started_at: None,
            registered_at: None,
            last_rx_at: None,
            last_tx_at: None,
            last_error: None,
            last_failure_at: None,
            next_retry_at: None,
            retry_after_secs: None,
            degraded_reason: None,
            sent_count: 0,
            received_count: 0,
            duplicate_count: 0,
            reconnect_count: 0,
            failure_count: 0,
            data_path_mode: None,
            data_path_degraded_reason: None,
        }
    }
}

impl RuntimeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// 标记功能关闭。
    pub fn mark_disabled(&mut self) {
        self.phase = Phase::Idle;
        self.stage.clear();
        self.enabled = false;
        self.registered = false;
        self.registration_mode = None;
        self.interface = None;
        self.family = None;
        self.local_ip = None;
        self.pcscf = None;
        self.session_started_at = None;
        self.registered_at = None;
        self.degraded_reason = None;
        self.retry_after_secs = None;
        self.next_retry_at = None;
    }

    /// 开始一轮注册尝试。
    pub fn begin_session(&mut self, stage: &str) {
        self.phase = Phase::Starting;
        self.stage = stage.to_string();
        self.enabled = true;
        self.registered = false;
        self.session_started_at = Some(now());
        self.degraded_reason = None;
        self.retry_after_secs = None;
        self.next_retry_at = None;
    }

    /// 推进子步骤，不改变阶段。
    pub fn set_stage(&mut self, stage: &str) {
        self.stage = stage.to_string();
    }

    /// 承载就绪，记录地址族/网卡/本地地址/P-CSCF。
    pub fn mark_bearer_up(
        &mut self,
        interface: &str,
        family: &str,
        local_ip: &str,
        pcscf: Option<&str>,
        data_path_mode: &str,
    ) {
        self.interface = Some(interface.to_string());
        self.family = Some(family.to_string());
        self.local_ip = Some(local_ip.to_string());
        self.pcscf = pcscf.map(|s| s.to_string());
        self.data_path_mode = Some(data_path_mode.to_string());
        self.stage = "pcscf".to_string();
    }

    /// 记录注册方式（ipsec / udp）。
    pub fn mark_registration_mode(&mut self, mode: &str) {
        self.registration_mode = Some(mode.to_string());
        self.stage = "register".to_string();
    }

    /// 注册成功。
    pub fn mark_registered(&mut self) {
        self.phase = Phase::Registered;
        self.stage = "registered".to_string();
        self.enabled = true;
        self.registered = true;
        self.registered_at = Some(now());
        self.last_error = None;
        self.degraded_reason = None;
        self.retry_after_secs = None;
        self.next_retry_at = None;
    }

    /// 注册失败，进入降级并给出下次重试时间。
    pub fn mark_failed(
        &mut self,
        reason_code: &str,
        detail: &str,
        retry_after_secs: u64,
    ) {
        self.phase = Phase::Degraded;
        self.registered = false;
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_failure_at = Some(now());
        self.degraded_reason = Some(reason_code.to_string());
        self.last_error = Some(if detail.is_empty() {
            reason_code.to_string()
        } else {
            format!("{}:{}", reason_code, detail)
        });
        self.retry_after_secs = Some(retry_after_secs);
        self.next_retry_at = Some(now_plus(retry_after_secs));
    }

    pub fn mark_sent(&mut self) {
        self.sent_count = self.sent_count.saturating_add(1);
        self.last_tx_at = Some(now());
    }

    pub fn mark_received(&mut self) {
        self.received_count = self.received_count.saturating_add(1);
        self.last_rx_at = Some(now());
    }

    pub fn mark_duplicate(&mut self) {
        self.duplicate_count = self.duplicate_count.saturating_add(1);
    }

    pub fn mark_reconnect(&mut self) {
        self.reconnect_count = self.reconnect_count.saturating_add(1);
    }

    /// 数据通道降级。
    pub fn mark_data_path_degraded(&mut self, reason: &str) {
        self.data_path_degraded_reason = Some(reason.to_string());
    }

    /// 导出给 API 的快照。
    pub fn snapshot(&self) -> VolteRuntimeStatus {
        VolteRuntimeStatus {
            phase: self.phase.as_str().to_string(),
            stage: self.stage.clone(),
            enabled: self.enabled,
            registered: self.registered,
            registration_mode: self.registration_mode.clone(),
            interface: self.interface.clone(),
            family: self.family.clone(),
            local_ip: self.local_ip.clone(),
            pcscf: self.pcscf.clone(),
            session_started_at: self.session_started_at.clone(),
            registered_at: self.registered_at.clone(),
            last_rx_at: self.last_rx_at.clone(),
            last_tx_at: self.last_tx_at.clone(),
            last_error: self.last_error.clone(),
            last_failure_at: self.last_failure_at.clone(),
            next_retry_at: self.next_retry_at.clone(),
            retry_after_secs: self.retry_after_secs,
            registration_degraded_reason: self.degraded_reason.clone(),
            sent_count: self.sent_count,
            received_count: self.received_count,
            duplicate_count: self.duplicate_count,
            reconnect_count: self.reconnect_count,
            failure_count: self.failure_count,
            data_path_mode: self.data_path_mode.clone(),
            data_path_degraded_reason: self.data_path_degraded_reason.clone(),
        }
    }
}

fn now() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn now_plus(secs: u64) -> String {
    (Local::now() + chrono::Duration::seconds(secs as i64))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_snapshot_is_idle() {
        let s = RuntimeState::new().snapshot();
        assert_eq!(s.phase, "idle");
        assert!(!s.enabled);
        assert!(!s.registered);
        assert_eq!(s.failure_count, 0);
    }

    #[test]
    fn begin_session_moves_to_starting() {
        let mut st = RuntimeState::new();
        st.begin_session("modem");
        let s = st.snapshot();
        assert_eq!(s.phase, "starting");
        assert_eq!(s.stage, "modem");
        assert!(s.enabled);
        assert!(s.session_started_at.is_some());
    }

    #[test]
    fn bearer_up_records_interface_and_address() {
        let mut st = RuntimeState::new();
        st.begin_session("modem");
        st.mark_bearer_up("wwan0", "ipv6", "2408::1", Some("2408::2"), "secondary_qmi_data");
        let s = st.snapshot();
        assert_eq!(s.interface.as_deref(), Some("wwan0"));
        assert_eq!(s.family.as_deref(), Some("ipv6"));
        assert_eq!(s.local_ip.as_deref(), Some("2408::1"));
        assert_eq!(s.pcscf.as_deref(), Some("2408::2"));
        assert_eq!(s.stage, "pcscf");
        assert_eq!(s.data_path_mode.as_deref(), Some("secondary_qmi_data"));
    }

    #[test]
    fn failure_degrades_and_schedules_retry() {
        let mut st = RuntimeState::new();
        st.begin_session("modem");
        st.mark_failed("volte_udp_recv_timeout", "pcscf=2408::2", 120);
        let s = st.snapshot();
        assert_eq!(s.phase, "degraded");
        assert!(!s.registered);
        assert_eq!(s.failure_count, 1);
        assert_eq!(
            s.registration_degraded_reason.as_deref(),
            Some("volte_udp_recv_timeout")
        );
        assert_eq!(s.retry_after_secs, Some(120));
        assert!(s.last_error.unwrap().contains("pcscf=2408::2"));
        assert!(s.next_retry_at.is_some());
    }

    #[test]
    fn success_clears_failure_fields() {
        let mut st = RuntimeState::new();
        st.begin_session("modem");
        st.mark_failed("volte_udp_recv_timeout", "x", 120);
        st.mark_registered();
        let s = st.snapshot();
        assert_eq!(s.phase, "registered");
        assert!(s.registered);
        assert!(s.last_error.is_none());
        assert!(s.registration_degraded_reason.is_none());
        assert!(s.retry_after_secs.is_none());
        // 失败计数保留，便于观察历史
        assert_eq!(s.failure_count, 1);
    }

    #[test]
    fn counters_accumulate() {
        let mut st = RuntimeState::new();
        st.mark_sent();
        st.mark_sent();
        st.mark_received();
        st.mark_duplicate();
        st.mark_reconnect();
        let s = st.snapshot();
        assert_eq!(s.sent_count, 2);
        assert_eq!(s.received_count, 1);
        assert_eq!(s.duplicate_count, 1);
        assert_eq!(s.reconnect_count, 1);
    }

    #[test]
    fn disabled_clears_runtime_view() {
        let mut st = RuntimeState::new();
        st.begin_session("modem");
        st.mark_registered();
        st.mark_disabled();
        let s = st.snapshot();
        assert_eq!(s.phase, "idle");
        assert!(!s.enabled);
        assert!(!s.registered);
        assert!(s.interface.is_none());
        assert!(s.registered_at.is_none());
    }
}
