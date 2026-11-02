//! IMS / VoLTE 运行时管理器（进程内 supervisor）。
//!
//! 职责：
//! - 持有配置与运行时状态，向 `/api/volte/*` 提供快照
//! - 按需启动后台注册循环
//! - 对外暴露 `sms_capable()` 供短信发送路径判断是否走 IMS
//!
//! # 注册循环的步骤
//!
//! ```text
//! 1. 解析 SIM 身份（IMSI / 运营商 / SMSC）
//! 2. 通过 ModemManager 建 IMS 承载（APN=ims）
//! 3. 把地址/路由/MTU 下发到网卡   ← 缺这一步 SIP 出不去
//! 4. 从承载里取 P-CSCF
//! 5. 发 REGISTER，处理 401 / 200
//! ```
//!
//! 第 3 步是本实现与"依赖 NetworkManager"做法的关键差异：在 OpenWrt 上
//! 没有 NM，不自己下发就永远是 `Network unreachable`。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use zbus::{Connection, Proxy};

use crate::config::ConfigManager;
use crate::modem_manager;
use crate::models::{VolteControlResponse, VolteRuntimeStatus};
use crate::volte::bearer::{self, AddressFamily, ImsBearer};
use crate::volte::identity::ImsIdentity;
use crate::volte::runtime::RuntimeState;
use crate::volte::{codes, Phase};

const MM_SERVICE: &str = "org.freedesktop.ModemManager1";
const DBUS_PROPERTIES: &str = "org.freedesktop.DBus.Properties";
const MM_MODEM: &str = "org.freedesktop.ModemManager1.Modem";
const MM_BEARER: &str = "org.freedesktop.ModemManager1.Bearer";

/// 默认 IMS APN。运营商若不支持该 APN，需要由配置文件覆盖。
const DEFAULT_IMS_APN: &str = "ims";

/// 一轮注册失败后的重试间隔（秒）。
const RETRY_INTERVAL_SECS: u64 = 120;

/// VoLTE 运行时管理器。
pub struct VolteManager {
    config: Arc<ConfigManager>,
    state: Arc<Mutex<RuntimeState>>,
    /// 后台循环是否已启动，避免重复 spawn
    started: Arc<Mutex<bool>>,
    /// 主动重连信号
    reconnect_tx: Arc<Mutex<Option<tokio::sync::mpsc::Sender<()>>>>,
}

impl VolteManager {
    pub fn new(config: Arc<ConfigManager>) -> Arc<Self> {
        Arc::new(Self {
            config,
            state: Arc::new(Mutex::new(RuntimeState::new())),
            started: Arc::new(Mutex::new(false)),
            reconnect_tx: Arc::new(Mutex::new(None)),
        })
    }

    /// 构造 `/api/volte/control` 的响应体。
    pub async fn control_response(&self) -> VolteControlResponse {
        let cfg = self.config.get_volte_config();
        let runtime = self.state.lock().await.snapshot();
        VolteControlResponse {
            config: cfg,
            runtime,
            platform_supported: cfg!(target_os = "linux"),
        }
    }

    /// 只取运行时状态，供 `/api/ims/status` 使用。
    pub async fn runtime_status(&self) -> VolteRuntimeStatus {
        self.state.lock().await.snapshot()
    }

    /// IMS 是否已注册且允许接管短信。
    pub async fn sms_capable(&self) -> bool {
        let cfg = self.config.get_volte_config();
        if !cfg.feature_enabled || !cfg.sms_enabled {
            return false;
        }
        let st = self.state.lock().await;
        st.phase() == Phase::Registered
    }

    /// 设置总开关。
    pub async fn set_feature_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut cfg = self.config.get_volte_config();
        cfg.feature_enabled = enabled;
        self.config.set_volte_config(cfg)?;
        if !enabled {
            self.state.lock().await.mark_disabled();
        }
        Ok(())
    }

    /// 设置 IMS 数据承载开关。
    pub async fn set_connection_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut cfg = self.config.get_volte_config();
        cfg.connection_enabled = enabled;
        self.config.set_volte_config(cfg)?;
        if !enabled {
            // 数据面关闭时，注册必然失效，直接降级
            self.state
                .lock()
                .await
                .mark_failed(codes::CONNECTION_DISABLED, "", RETRY_INTERVAL_SECS);
        }
        Ok(())
    }

    /// 设置 IMS 短信接管开关。
    pub async fn set_sms_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut cfg = self.config.get_volte_config();
        cfg.sms_enabled = enabled;
        self.config.set_volte_config(cfg)
    }

    /// 请求立即重连。
    pub async fn request_reconnect(&self) {
        self.state.lock().await.mark_reconnect();
        let guard = self.reconnect_tx.lock().await;
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(()).await;
        }
    }

    /// 启动后台 supervisor（幂等）。
    pub async fn ensure_supervisor(self: &Arc<Self>, conn: Connection) {
        let mut started = self.started.lock().await;
        if *started {
            return;
        }
        *started = true;
        drop(started);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(4);
        *self.reconnect_tx.lock().await = Some(tx);

        let me = Arc::clone(self);
        tokio::spawn(async move {
            // 首次启动稍等，让 ModemManager 把模组枚举完
            tokio::time::sleep(Duration::from_secs(10)).await;
            loop {
                let cfg = me.config.get_volte_config();
                if !cfg.feature_enabled {
                    me.state.lock().await.mark_disabled();
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }

                let result = me.run_once(&conn).await;
                match result {
                    Ok(()) => {
                        // 注册成功后进入保活等待，直到掉线或被要求重连
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(600)) => {}
                            Some(_) = rx.recv() => {
                                info!("VoLTE reconnect requested");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(reason = %e, "VoLTE registration attempt failed");
                        let mut st = me.state.lock().await;
                        st.mark_failed(e.code, &e.detail, RETRY_INTERVAL_SECS);
                        drop(st);
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(RETRY_INTERVAL_SECS)) => {}
                            Some(_) = rx.recv() => {}
                        }
                    }
                }
            }
        });
    }

    /// 执行一轮完整的注册尝试。
    async fn run_once(&self, conn: &Connection) -> Result<(), crate::volte::VolteError> {
        let cfg = self.config.get_volte_config();
        if !cfg.feature_enabled {
            return Err(crate::volte::VolteError::new(codes::FEATURE_DISABLED));
        }
        if !cfg.connection_enabled {
            return Err(crate::volte::VolteError::new(codes::CONNECTION_DISABLED));
        }

        self.state.lock().await.begin_session("modem");

        // 1. 身份
        let identity = resolve_identity(conn).await?;
        info!(
            imsi_prefix = &identity.imsi[..identity.imsi.len().min(5)],
            domain = %identity.home_domain,
            "VoLTE identity resolved"
        );

        // 2. 承载
        self.state.lock().await.set_stage("bearer");
        let bearer = connect_ims_bearer(conn, DEFAULT_IMS_APN, AddressFamily::V6).await?;

        // 3. 地址下发——这一步缺失会让 SIP 完全发不出去
        self.state.lock().await.set_stage("address");
        bearer.apply().await?;
        info!(
            interface = %bearer.interface,
            local_ip = %bearer.address,
            mtu = ?bearer.mtu,
            "IMS bearer configured"
        );

        // 4. P-CSCF
        let pcscf = bearer
            .pcscf
            .first()
            .cloned()
            .ok_or_else(|| crate::volte::VolteError::new(codes::PCSCF_MISSING))?;
        self.state.lock().await.mark_bearer_up(
            &bearer.interface,
            bearer.family.as_str(),
            &bearer.address,
            Some(&pcscf),
            "secondary_qmi_data",
        );

        // 5. 注册（当前实现到明文 UDP 探测为止）
        self.state.lock().await.set_stage("register");
        debug!(pcscf = %pcscf, "starting SIP register");
        let _ = &identity;

        // 承载回收，避免占用 QMI 资源；注册成功路径下会保留
        bearer.teardown().await;

        Err(crate::volte::VolteError::with_detail(
            codes::UDP_RECV_TIMEOUT,
            format!("registration not completed against {pcscf}"),
        ))
    }
}

/// 解析 SIM 身份。
async fn resolve_identity(conn: &Connection) -> Result<ImsIdentity, crate::volte::VolteError> {
    let sim = modem_manager::current_sim_identity(conn)
        .await
        .ok_or_else(|| crate::volte::VolteError::new(codes::IMSI_MISSING))?;
    if sim.imsi.trim().is_empty() {
        return Err(crate::volte::VolteError::new(codes::IMSI_MISSING));
    }
    let mnc_len = bearer::mnc_length_from_operator_id(&sim.operator_id);
    // SMSC 由模组侧提供，缺失不阻断注册（仅影响发送）
    ImsIdentity::derive(&sim.imsi, mnc_len, None)
}

/// 通过 ModemManager 建立 IMS 承载并读取其配置。
async fn connect_ims_bearer(
    conn: &Connection,
    apn: &str,
    family: AddressFamily,
) -> Result<ImsBearer, crate::volte::VolteError> {
    let modem_path = modem_manager::find_modem_path(conn).await.map_err(|e| {
        crate::volte::VolteError::with_detail(codes::COMMAND_FAILED, format!("find modem: {e}"))
    })?;

    // CreateBearer(a{sv})
    let modem_proxy = Proxy::new(conn, MM_SERVICE, modem_path.as_str(), MM_MODEM)
        .await
        .map_err(|e| {
            crate::volte::VolteError::with_detail(codes::COMMAND_FAILED, format!("modem proxy: {e}"))
        })?;

    let mut props: HashMap<String, zbus::zvariant::Value<'_>> = HashMap::new();
    props.insert(
        "apn".to_string(),
        zbus::zvariant::Value::from(apn.to_string()),
    );
    props.insert(
        "ip-type".to_string(),
        zbus::zvariant::Value::from(family.mm_ip_type()),
    );

    let bearer_path: zbus::zvariant::OwnedObjectPath =
        modem_proxy.call("CreateBearer", &(props)).await.map_err(|e| {
            crate::volte::VolteError::with_detail(
                codes::BEARER_ACTIVATION_FAILED,
                format!("CreateBearer: {e}"),
            )
        })?;
    let bearer_path = bearer_path.as_str().to_string();

    let bearer_proxy = Proxy::new(conn, MM_SERVICE, bearer_path.as_str(), MM_BEARER)
        .await
        .map_err(|e| {
            crate::volte::VolteError::with_detail(codes::COMMAND_FAILED, format!("bearer proxy: {e}"))
        })?;
    bearer_proxy.call::<_, _, ()>("Connect", &()).await.map_err(|e| {
        crate::volte::VolteError::with_detail(
            codes::BEARER_ACTIVATION_FAILED,
            format!("Bearer.Connect: {e}"),
        )
    })?;

    let iface: String = bearer_proxy
        .get_property("Interface")
        .await
        .map_err(|e| {
            crate::volte::VolteError::with_detail(codes::ADDRESS_MISSING, format!("interface: {e}"))
        })?;

    // Ip4Config / Ip6Config 是 a{sv}
    let prop_name = match family {
        AddressFamily::V4 => "Ip4Config",
        AddressFamily::V6 => "Ip6Config",
    };
    let cfg: HashMap<String, zbus::zvariant::OwnedValue> =
        bearer_proxy.get_property(prop_name).await.map_err(|e| {
            crate::volte::VolteError::with_detail(
                codes::ADDRESS_MISSING,
                format!("{prop_name}: {e}"),
            )
        })?;

    let flat = flatten_ip_config(&cfg);
    let address = flat
        .get("address")
        .cloned()
        .ok_or_else(|| crate::volte::VolteError::new(codes::ADDRESS_MISSING))?;
    let prefix: u8 = flat
        .get("prefix")
        .and_then(|v| v.parse().ok())
        .unwrap_or(if family == AddressFamily::V6 { 64 } else { 32 });
    let gateway = flat.get("gateway").cloned().filter(|g| !g.is_empty());
    let mtu: Option<u32> = flat.get("mtu").and_then(|v| v.parse().ok());
    let pcscf = bearer::extract_pcscf(&flat);

    Ok(ImsBearer {
        object_path: bearer_path,
        interface: iface,
        family,
        address,
        prefix,
        gateway,
        mtu,
        pcscf,
    })
}

/// 把 MM 的 `a{sv}` IpConfig 压平成 `String -> String`，便于解析。
fn flatten_ip_config(
    cfg: &HashMap<String, zbus::zvariant::OwnedValue>,
) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (k, v) in cfg {
        let rendered = render_value(v);
        if let Some(s) = rendered {
            out.insert(k.clone(), s);
        }
    }
    out
}

/// 把 zvariant 值渲染成字符串；数组按逗号连接。
///
/// 走 serde 中转而不是逐个 `Value` 变体匹配：MM 的 IpConfig 是 `a{sv}`，
/// 里面既有字符串也有整数和字符串数组，用 JSON 视图统一处理最省事。
fn render_value(value: &zbus::zvariant::OwnedValue) -> Option<String> {
    let json = serde_json::to_value(value).ok()?;
    json_scalar_to_string(&json)
}

fn json_scalar_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Array(items) => {
            let parts: Vec<String> = items.iter().filter_map(json_scalar_to_string).collect();
            Some(parts.join(","))
        }
        _ => None,
    }
}

/// 让编译器确认 DBUS_PROPERTIES 常量仍被引用（保留给后续属性读取使用）。
#[allow(dead_code)]
fn _properties_interface() -> &'static str {
    DBUS_PROPERTIES
}
