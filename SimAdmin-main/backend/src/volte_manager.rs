//! IMS / VoLTE 运行时管理器（进程内 supervisor）。
//!
//! 与旧版 `volte_manager.rs`（拉起 `volte_register.py` 子进程）不同，这里直接
//! 驱动 [`crate::volte::runtime`]：本进程就是 IMS 栈，没有外部 daemon、没有
//! python3、没有 IPC。
//!
//! 职责只有三件事：
//! 1. 按配置启停 runtime worker（`feature_enabled`）；
//! 2. 把 runtime 的 MT 短信落库 + 转发通知（`IncomingSms` 通道）；
//! 3. 对 HTTP 层暴露状态查询与 MO 发送入口。

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::{ConfigManager, VolteConfig};
use crate::db::{beijing_sms_now_string, normalize_sms_timestamp_for_display, Database, SmsMessage};
use crate::models::{
    VolteConfigView, VolteControlResponse, VolteRuntimeStatusResponse, VolteSettingsRequest,
};
use crate::notification::NotificationSender;
use crate::volte::runtime::{
    self, Command, IncomingSms, Phase, RuntimeConfig, SendOutcome, Shared, Status,
};
use crate::volte::err;

/// MO 发送等待上限：runtime 内部等 RP-ACK 35s，这里再留余量。
const SEND_TIMEOUT: Duration = Duration::from_secs(60);
/// 停止 worker 的等待上限。
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

struct Worker {
    commands: mpsc::Sender<Command>,
    task: JoinHandle<()>,
}

pub struct VolteManager {
    shared: Arc<Shared>,
    /// MT 入口，只被 import 任务取走一次。
    incoming: Mutex<Option<mpsc::Receiver<IncomingSms>>>,
    worker: Mutex<Option<Worker>>,
    import_task: Mutex<Option<JoinHandle<()>>>,
    config_manager: Arc<ConfigManager>,
    database: Arc<Database>,
    notifier: Arc<NotificationSender>,
}

impl VolteManager {
    pub fn new(
        config_manager: Arc<ConfigManager>,
        database: Arc<Database>,
        notifier: Arc<NotificationSender>,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(64);
        Arc::new(Self {
            shared: Shared::new(tx),
            incoming: Mutex::new(Some(rx)),
            worker: Mutex::new(None),
            import_task: Mutex::new(None),
            config_manager,
            database,
            notifier,
        })
    }

    // -----------------------------------------------------------------------
    // 状态
    // -----------------------------------------------------------------------

    pub async fn status(&self) -> Status {
        self.shared.status().await
    }

    /// 注册是否仍然有效（含过期判定）。
    pub async fn is_registered(&self) -> bool {
        if !self.config_manager.get_volte_config().feature_enabled {
            return false;
        }
        let now = now_unix();
        self.shared.status().await.live(now)
    }

    /// 是否可以用 IMS 发短信。
    pub async fn sms_capable(&self) -> bool {
        let cfg = self.config_manager.get_volte_config();
        cfg.feature_enabled && cfg.sms_enabled && self.is_registered().await
    }

    pub async fn control_response(&self) -> VolteControlResponse {
        let cfg = self.config_manager.get_volte_config();
        let st = self.shared.status().await;
        let live = cfg.feature_enabled && st.live(now_unix());
        VolteControlResponse {
            config: VolteConfigView {
                feature_enabled: cfg.feature_enabled,
                connection_enabled: cfg.feature_enabled,
                sms_enabled: cfg.sms_enabled,
                apn: cfg.apn.clone(),
                apn_protocol: cfg.apn_protocol.clone(),
                roaming_allowed: cfg.roaming_allowed,
                data_path_intent: cfg.data_path_intent.clone(),
                smsc: cfg.smsc.clone(),
                pcscf: cfg.pcscf.clone(),
                interface: cfg.interface.clone(),
                mux: cfg.mux,
                prefer_ipsec: cfg.prefer_ipsec,
                refresh_secs: cfg.refresh_secs,
            },
            runtime: VolteRuntimeStatusResponse {
                phase: st.phase.as_str().to_string(),
                stage: st.stage.as_str().to_string(),
                registration_mode: st.registration_mode.map(|m| m.as_str().to_string()),
                session_started_at: st.session_started_at,
                registered_at: st.registered_at,
                last_rx_at: st.last_rx_at,
                last_tx_at: st.last_tx_at,
                last_error: st.last_error.clone(),
                last_failure_at: st.last_failure_at,
                next_retry_at: st.next_retry_at,
                failure_count: st.failure_count,
                registered: live,
                sent_count: st.sent_count,
                received_count: st.received_count,
                duplicate_count: st.duplicate_count,
                reconnect_count: st.reconnect_count,
                data_path_mode: Some(cfg.data_path_intent.clone()),
                expires_at: st.expires_at,
                imsi: st.imsi,
                home_domain: st.home_domain,
                public_identity: st.public_identity,
                pcscf: st.pcscf,
                local_ip: st.ue_address.clone(),
                ue_address: st.ue_address,
                own_number: st.own_number,
                smsc: st.smsc,
                interface: st.interface,
                bearer_source: st.bearer_source,
                aka_transport: st.aka_transport,
            },
        }
    }

    // -----------------------------------------------------------------------
    // 配置变更
    // -----------------------------------------------------------------------

    pub async fn set_feature_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut cfg = self.config_manager.get_volte_config();
        cfg.feature_enabled = enabled;
        self.config_manager
            .set_volte_config(cfg)
            .map_err(|e| format!("保存 VoLTE 配置失败: {e}"))?;
        if enabled {
            self.start_worker().await;
        } else {
            self.stop_worker().await;
        }
        Ok(())
    }

    pub async fn set_sms_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut cfg = self.config_manager.get_volte_config();
        cfg.sms_enabled = enabled;
        self.config_manager
            .set_volte_config(cfg)
            .map_err(|e| format!("保存 VoLTE 短信开关失败: {e}"))?;
        // 收发开关只影响 MO 判断；MT 由 runtime 常驻接收，无需重启。
        Ok(())
    }

    pub async fn update_settings(&self, patch: VolteSettingsRequest) -> Result<(), String> {
        let mut cfg = self.config_manager.get_volte_config();
        let before = cfg.clone();
        apply_settings(&mut cfg, patch)?;
        if !settings_changed(&before, &cfg) {
            return Ok(());
        }
        let feature_on = cfg.feature_enabled;
        self.config_manager
            .set_volte_config(cfg)
            .map_err(|e| format!("保存 VoLTE 设置失败: {e}"))?;
        if feature_on {
            // 承载/SMSC 变更必须重建会话。
            self.stop_worker().await;
            self.start_worker().await;
        }
        Ok(())
    }

    /// 通过 AT 激活一次 IMS 上下文，学习网络下发的 P-CSCF，并写回配置。
    ///
    /// 为什么要拆成「学一次再注入」：
    ///   本网 P-CSCF 只能从 **AT 激活** 的上下文里读到（`AT+CGCONTRDP` 的第
    ///   8/9 字段），而承载又必须走 QMI —— AT 激活在 bam-dmux 上没有 mux
    ///   bind，数据面是死的。两者不能同时满足，所以分两步：AT 学地址 →
    ///   写进 `volte.pcscf` → QMI 建承载时直接用这个地址。
    ///
    /// 学之前要先停掉运行时：QMI 那条 IMS 承载还占着同一个 APN 的话，再 AT
    /// 激活一个会被网络以 `CallFailed` 拒掉（实测）。
    pub async fn discover_pcscf(&self) -> Result<Vec<String>, String> {
        let cfg = self.config_manager.get_volte_config();
        let apn = if cfg.apn.trim().is_empty() {
            "ims".to_string()
        } else {
            cfg.apn.clone()
        };

        // 用哪个 cid 去「借」一个上下文来学地址：不能拍一个固定值。
        // 1 是默认承载；2..=5 会被厂商 qmi-modem-410-init 在 ufi-wf2 上删掉，
        // 而且可能有 QMI 客户端占着（占着时 AT+CGACT 直接报 Unknown error）。
        // 所以按顺序试，哪个能激活就用哪个。
        const LEARN_CIDS: [u32; 3] = [4, 5, 6];

        if cfg.feature_enabled {
            self.stop_worker().await;
        }

        let mut last_err = String::from("没有可用的 PDP 上下文号");
        let mut learned: Option<Vec<std::net::IpAddr>> = None;
        for cid in LEARN_CIDS {
            match crate::volte::bearer::learn_pcscf_via_at(&apn, cid) {
                Ok(list) if !list.is_empty() => {
                    learned = Some(list);
                    break;
                }
                Ok(_) => {
                    // 激活成功但网络没下发 P-CSCF，换 cid 也没用，直接停。
                    last_err = "网络没有在 PCO 里下发 P-CSCF（AT+CGCONTRDP 里没有第 8/9 字段）"
                        .to_string();
                    break;
                }
                Err(e) => {
                    last_err = e;
                }
            }
        }

        let result = match learned {
            Some(list) => {
                let mut updated = cfg.clone();
                updated.pcscf = list[0].to_string();
                match self.config_manager.set_volte_config(updated) {
                    Ok(()) => Ok(list.iter().map(|a| a.to_string()).collect()),
                    Err(e) => Err(format!("保存 P-CSCF 失败: {e}")),
                }
            }
            None => Err(last_err),
        };

        // 不管学没学到，都把运行时拉回来 —— 不能让用户点一下按钮之后
        // IMS 就停在那儿了。
        if cfg.feature_enabled {
            self.start_worker().await;
        }

        result
    }

    // -----------------------------------------------------------------------
    // 控制
    // -----------------------------------------------------------------------

    pub async fn refresh(&self) -> Result<(), String> {
        if !self.config_manager.get_volte_config().feature_enabled {
            return Err(err::DISABLED.to_string());
        }
        let worker = self.worker.lock().await;
        let worker = worker
            .as_ref()
            .filter(|w| !w.task.is_finished())
            .ok_or_else(|| err::RUNTIME_NOT_RUNNING.to_string())?;
        worker
            .commands
            .try_send(Command::Refresh)
            .map_err(|_| err::RUNTIME_COMMAND_CLOSED.to_string())
    }

    /// 启动 runtime worker + MT 导入任务（幂等）。
    pub async fn spawn_worker(&self) {
        self.ensure_import_task().await;
        self.start_worker().await;
    }

    async fn ensure_import_task(&self) {
        let mut slot = self.import_task.lock().await;
        if slot.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let Some(receiver) = self.incoming.lock().await.take() else {
            return;
        };
        let database = Arc::clone(&self.database);
        let notifier = Arc::clone(&self.notifier);
        *slot = Some(tokio::spawn(async move {
            import_loop(receiver, database, notifier).await;
        }));
    }

    async fn start_worker(&self) {
        let cfg = self.config_manager.get_volte_config();
        if !cfg.feature_enabled {
            return;
        }
        let mut slot = self.worker.lock().await;
        if let Some(existing) = slot.as_ref() {
            if !existing.task.is_finished() {
                return;
            }
        }
        let (commands, rx) = mpsc::channel(16);
        let shared = Arc::clone(&self.shared);
        let runtime_cfg = runtime_config(&cfg);
        info!(
            target: "simadmin::volte",
            apn = %runtime_cfg.apn,
            mux = runtime_cfg.mux,
            prefer_ipsec = runtime_cfg.prefer_ipsec,
            "启动 IMS 运行时"
        );
        let task = tokio::spawn(async move {
            runtime::run(shared, runtime_cfg, rx).await;
        });
        *slot = Some(Worker { commands, task });
    }

    async fn stop_worker(&self) {
        let mut slot = self.worker.lock().await;
        if let Some(worker) = slot.take() {
            let _ = worker.commands.send(Command::Stop).await;
            if tokio::time::timeout(STOP_TIMEOUT, worker.task).await.is_err() {
                warn!(target: "simadmin::volte", "IMS 运行时停止超时，已放弃等待");
            }
        }
    }

    // -----------------------------------------------------------------------
    // 发送
    // -----------------------------------------------------------------------

    /// 通过 IMS 发送一条短信。返回 `SendOutcome`，其中 `delivery_unknown`
    /// 为真时**不可自动重发**（可能已到达网络侧）。
    pub async fn send_sms(&self, phone: &str, content: &str) -> Result<SendOutcome, String> {
        let cfg = self.config_manager.get_volte_config();
        if !cfg.feature_enabled {
            return Err(err::DISABLED.to_string());
        }
        if !cfg.sms_enabled {
            return Err("volte_sms_disabled".to_string());
        }
        if !self.is_registered().await {
            return Err(err::NOT_REGISTERED.to_string());
        }

        let (reply, wait) = oneshot::channel();
        {
            let worker = self.worker.lock().await;
            let worker = worker
                .as_ref()
                .filter(|w| !w.task.is_finished())
                .ok_or_else(|| err::RUNTIME_NOT_RUNNING.to_string())?;
            worker
                .commands
                .send(Command::Send {
                    phone: phone.to_string(),
                    text: content.to_string(),
                    reply,
                })
                .await
                .map_err(|_| err::RUNTIME_COMMAND_CLOSED.to_string())?;
        }

        match tokio::time::timeout(SEND_TIMEOUT, wait).await {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(_)) => Err(err::RUNTIME_COMMAND_CLOSED.to_string()),
            Err(_) => Err(err::SMS_DELIVERY_UNKNOWN.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// 配置映射
// ---------------------------------------------------------------------------

fn runtime_config(cfg: &VolteConfig) -> RuntimeConfig {
    RuntimeConfig {
        apn: cfg.apn.trim().to_string(),
        profile: None,
        mux: cfg.mux,
        interface: Some(cfg.interface.trim().to_string()).filter(|s| !s.is_empty()),
        pcscf: parse_pcscf(&cfg.pcscf),
        smsc: cfg.smsc.trim().to_string(),
        refresh_secs: cfg.refresh_secs.max(300),
        port_c: cfg.port_c,
        port_s: cfg.port_s,
        prefer_ipsec: cfg.prefer_ipsec,
        sms_enabled: cfg.sms_enabled,
    }
}

/// 手工配置的 P-CSCF。空串 / 非法值都当成「没有」——非法值在
/// `apply_settings` 里已经被拒了，这里只是兜底，避免旧配置文件把人卡住。
fn parse_pcscf(raw: &str) -> Option<std::net::IpAddr> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    match t.parse() {
        Ok(addr) => Some(addr),
        Err(_) => {
            tracing::warn!(target: "simadmin::volte", value = %t, "配置的 P-CSCF 无法解析，忽略");
            None
        }
    }
}

fn apply_settings(cfg: &mut VolteConfig, patch: VolteSettingsRequest) -> Result<(), String> {
    if let Some(apn) = patch.apn {
        cfg.apn = apn.trim().to_string();
    }
    if let Some(protocol) = patch.apn_protocol {
        let upper = protocol.to_ascii_uppercase();
        if !matches!(upper.as_str(), "IP" | "IPV4" | "IPV6" | "IPV4V6") {
            return Err(format!("不支持的 APN 协议: {protocol}"));
        }
        cfg.apn_protocol = upper;
    }
    if let Some(roaming) = patch.roaming_allowed {
        cfg.roaming_allowed = roaming;
    }
    if let Some(intent) = patch.data_path_intent {
        if !matches!(intent.as_str(), "independent_wwan1" | "secondary_qmi_data") {
            return Err(format!("不支持的数据槽位模式: {intent}"));
        }
        cfg.data_path_intent = intent;
    }
    if let Some(smsc) = patch.smsc {
        let digits: String = smsc
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '+')
            .collect();
        if !smsc.trim().is_empty() && digits.chars().filter(char::is_ascii_digit).count() < 5 {
            return Err("短信中心号码格式无效".to_string());
        }
        cfg.smsc = digits;
    }
    if let Some(pcscf) = patch.pcscf {
        let t = pcscf.trim();
        if !t.is_empty() && t.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("P-CSCF 不是合法的 IP 地址: {pcscf}"));
        }
        cfg.pcscf = t.to_string();
    }
    if let Some(interface) = patch.interface {
        cfg.interface = interface.trim().to_string();
    }
    if let Some(mux) = patch.mux {
        if mux > 8 {
            return Err(format!("mux 超出范围: {mux}"));
        }
        cfg.mux = mux;
    }
    if let Some(prefer) = patch.prefer_ipsec {
        cfg.prefer_ipsec = prefer;
    }
    if let Some(refresh) = patch.refresh_secs {
        cfg.refresh_secs = refresh.clamp(300, 86_400);
    }
    Ok(())
}

fn settings_changed(before: &VolteConfig, after: &VolteConfig) -> bool {
    before.apn != after.apn
        || before.apn_protocol != after.apn_protocol
        || before.roaming_allowed != after.roaming_allowed
        || before.data_path_intent != after.data_path_intent
        || before.smsc != after.smsc
        // 漏掉这一项时，单独改 P-CSCF 会被判成「没变化」直接 return Ok，
        // 于是既不落盘也不重启会话——接口返回成功，配置却没变。
        // 实测就是靠这条踩出来的：POST {"pcscf":"2408:..."} 之后
        // GET /api/volte/control 里还是空串。
        || before.pcscf != after.pcscf
        || before.interface != after.interface
        || before.mux != after.mux
        || before.prefer_ipsec != after.prefer_ipsec
        || before.refresh_secs != after.refresh_secs
}

// ---------------------------------------------------------------------------
// MT 导入
// ---------------------------------------------------------------------------

async fn import_loop(
    mut receiver: mpsc::Receiver<IncomingSms>,
    database: Arc<Database>,
    notifier: Arc<NotificationSender>,
) {
    while let Some(sms) = receiver.recv().await {
        match persist_incoming(&database, &sms) {
            Ok(Some(message)) => {
                let notifier = Arc::clone(&notifier);
                tokio::spawn(async move {
                    let _ = notifier.forward_sms(&message).await;
                });
            }
            Ok(None) => {
                info!(target: "simadmin::volte", marker = %sms.marker, "IMS 短信重复，已忽略");
            }
            Err(error) => {
                warn!(target: "simadmin::volte", error = %error, "IMS 短信落库失败");
            }
        }
    }
    warn!(target: "simadmin::volte", "IMS MT 通道已关闭");
}

fn persist_incoming(db: &Database, sms: &IncomingSms) -> Result<Option<SmsMessage>, String> {
    if sms.marker.trim().is_empty() {
        return Err("IMS 短信缺少去重标记".to_string());
    }
    if db
        .sms_exists_by_pdu(&sms.marker)
        .map_err(|e| format!("IMS 短信去重查询失败: {e}"))?
    {
        return Ok(None);
    }
    let timestamp = normalize_sms_timestamp_for_display(&sms.timestamp)
        .unwrap_or_else(beijing_sms_now_string);
    let id = db
        .insert_sms_at(
            "incoming",
            &sms.sender,
            &sms.text,
            &timestamp,
            "received",
            Some(&sms.marker),
        )
        .map_err(|e| format!("IMS 短信写入失败: {e}"))?;
    Ok(Some(SmsMessage {
        id,
        direction: "incoming".to_string(),
        phone_number: sms.sender.clone(),
        content: sms.text.clone(),
        timestamp,
        status: "received".to_string(),
        pdu: Some(sms.marker.clone()),
        verification_code: None,
    }))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 给其它模块用的一句话状态（日志/事件）。
pub async fn phase_label(status: &Status) -> &'static str {
    match status.phase {
        Phase::Disabled => "disabled",
        Phase::Starting => "starting",
        Phase::Registered => "registered",
        Phase::Degraded => "degraded",
        Phase::Stopping => "stopping",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> VolteConfig {
        VolteConfig::default()
    }

    #[test]
    fn runtime_config_filters_blank_fields() {
        let mut c = cfg();
        c.interface = "   ".to_string();
        c.smsc = " +8613800678910 ".to_string();
        c.refresh_secs = 60;
        let rc = runtime_config(&c);
        assert!(rc.interface.is_none());
        assert_eq!(rc.smsc, "+8613800678910");
        assert_eq!(rc.refresh_secs, 300, "刷新周期下限 300s");
    }

    #[test]
    fn settings_changed_detects_pcscf() {
        // 单独改 P-CSCF 必须被认成「变了」。
        //
        // 漏掉这一项时 update_settings 会在 settings_changed 那里提前
        // return Ok，既不落盘也不重建会话，而 HTTP 仍然返回成功 ——
        // 表现为「设置保存了但没生效」，实测踩过。
        let before = cfg();
        let mut after = cfg();
        after.pcscf = "2408:8142:6001:1007::1".to_string();
        assert!(settings_changed(&before, &after));
    }

    #[test]
    fn settings_changed_is_false_for_identical_config() {
        assert!(!settings_changed(&cfg(), &cfg()));
    }

    #[test]
    fn settings_reject_bad_values() {
        let mut c = cfg();
        let err = apply_settings(
            &mut c,
            VolteSettingsRequest {
                apn: None,
                apn_protocol: Some("IPX".into()),
                roaming_allowed: None,
                data_path_intent: None,
                smsc: None,
                pcscf: None,
                interface: None,
                mux: None,
                prefer_ipsec: None,
                refresh_secs: None,
            },
        )
        .unwrap_err();
        assert!(err.contains("APN 协议"));

        let err = apply_settings(
            &mut c,
            VolteSettingsRequest {
                apn: None,
                apn_protocol: None,
                roaming_allowed: None,
                data_path_intent: None,
                smsc: Some("abc".into()),
                pcscf: None,
                interface: None,
                mux: None,
                prefer_ipsec: None,
                refresh_secs: None,
            },
        )
        .unwrap_err();
        assert!(err.contains("短信中心"));
    }

    #[test]
    fn settings_reject_non_ip_pcscf() {
        let mut c = cfg();
        let err = apply_settings(
            &mut c,
            VolteSettingsRequest {
                apn: None,
                apn_protocol: None,
                roaming_allowed: None,
                data_path_intent: None,
                smsc: None,
                pcscf: Some("pcscf.example.com".into()),
                interface: None,
                mux: None,
                prefer_ipsec: None,
                refresh_secs: None,
            },
        )
        .unwrap_err();
        assert!(err.contains("P-CSCF"), "实际错误: {err}");

        // 留空是合法的，表示回到自动发现。
        apply_settings(
            &mut c,
            VolteSettingsRequest {
                apn: None,
                apn_protocol: None,
                roaming_allowed: None,
                data_path_intent: None,
                smsc: None,
                pcscf: Some("   ".into()),
                interface: None,
                mux: None,
                prefer_ipsec: None,
                refresh_secs: None,
            },
        )
        .unwrap();
        assert!(c.pcscf.is_empty());
        assert!(runtime_config(&c).pcscf.is_none());
    }

    #[test]
    fn manual_pcscf_reaches_the_bearer_config() {
        let mut c = cfg();
        c.pcscf = " 2408:8142:6001:1:: ".to_string();
        let rc = runtime_config(&c);
        assert_eq!(
            rc.pcscf,
            Some("2408:8142:6001:1::".parse::<std::net::IpAddr>().unwrap())
        );
    }

    #[test]
    fn settings_normalise_smsc_and_protocol() {
        let mut c = cfg();
        apply_settings(
            &mut c,
            VolteSettingsRequest {
                apn: Some(" ims ".into()),
                apn_protocol: Some("ipv4v6".into()),
                roaming_allowed: Some(true),
                data_path_intent: Some("secondary_qmi_data".into()),
                smsc: Some("+86 138 0067 8910".into()),
                pcscf: Some(" 10.54.0.1 ".into()),
                interface: Some(" wwan0.2 ".into()),
                mux: Some(3),
                prefer_ipsec: Some(false),
                refresh_secs: Some(10),
            },
        )
        .unwrap();
        assert_eq!(c.apn, "ims");
        assert_eq!(c.apn_protocol, "IPV4V6");
        assert!(c.roaming_allowed);
        assert_eq!(c.data_path_intent, "secondary_qmi_data");
        assert_eq!(c.smsc, "+8613800678910");
        assert_eq!(c.pcscf, "10.54.0.1", "P-CSCF 两侧空白要被去掉");
        assert_eq!(c.interface, "wwan0.2");
        assert_eq!(c.mux, 3);
        assert!(!c.prefer_ipsec);
        assert_eq!(c.refresh_secs, 300);
    }

    #[test]
    fn control_response_serialises_config_and_runtime() {
        // 内嵌 React 前端读 data.config.* 与 data.runtime.*，形状不能拍平。
        let resp = VolteControlResponse {
            config: VolteConfigView {
                feature_enabled: true,
                connection_enabled: true,
                sms_enabled: true,
                ..Default::default()
            },
            runtime: VolteRuntimeStatusResponse {
                phase: "registered".to_string(),
                registered: true,
                ..Default::default()
            },
        };
        let value = serde_json::to_value(&resp).unwrap();
        assert_eq!(value["config"]["feature_enabled"], serde_json::json!(true));
        assert_eq!(
            value["config"]["connection_enabled"],
            serde_json::json!(true)
        );
        assert_eq!(value["runtime"]["registered"], serde_json::json!(true));
        assert_eq!(value["runtime"]["phase"], serde_json::json!("registered"));
        assert!(value["runtime"]["local_ip"].is_null());
        assert!(value.get("feature_enabled").is_none(), "顶层不能有平铺字段");
    }

    #[test]
    fn incoming_is_persisted_once_per_marker() {
        let db = Database::new(std::path::PathBuf::from(":memory:")).unwrap();
        let sms = IncomingSms {
            sender: "+8613000000000".to_string(),
            text: "验证码 123456".to_string(),
            timestamp: "2026-11-02T10:00:00Z".to_string(),
            marker: "ims:test-marker".to_string(),
        };
        let first = persist_incoming(&db, &sms).unwrap().unwrap();
        assert_eq!(first.phone_number, "+8613000000000");
        assert_eq!(first.status, "received");
        assert!(persist_incoming(&db, &sms).unwrap().is_none());

        let mut blank = sms.clone();
        blank.marker = "  ".to_string();
        assert!(persist_incoming(&db, &blank).is_err());
    }
}
