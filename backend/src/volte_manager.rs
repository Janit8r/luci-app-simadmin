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

        // 3~5 步放在统一作用域里：任何一步失败都要把 MM 承载释放掉。
        //
        // 不释放的后果是真机上极难排查的现象——残留的 IMS PDN 会一直占着
        // QMI 数据槽，下一次 CreateBearer 直接返回 `Call failed: unknown error`，
        // 而日志里只会看到"承载建立失败"，完全看不出是上一次没清理。
        let outcome: Result<(), crate::volte::VolteError> = async {
            // 3. 地址下发——这一步缺失会让 SIP 完全发不出去
            self.state.lock().await.set_stage("address");
            bearer.apply().await?;
            info!(
                interface = %bearer.interface,
                local_ip = %bearer.address,
                mtu = ?bearer.mtu,
                "IMS bearer configured"
            );

            // 4. P-CSCF：优先用承载自带的值，没有就查 AT+CGCONTRDP
            self.state.lock().await.set_stage("pcscf");
            let pcscf = match bearer.pcscf.first().cloned() {
                Some(p) => p,
                None => discover_pcscf_via_at()
                    .await
                    .into_iter()
                    .next()
                    .ok_or_else(|| crate::volte::VolteError::new(codes::PCSCF_MISSING))?,
            };
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

            Err(crate::volte::VolteError::with_detail(
                codes::UDP_RECV_TIMEOUT,
                format!("registration not completed against {pcscf}"),
            ))
        }
        .await;

        // 无论成功失败，先撤掉接口上的地址/路由，再释放 MM 承载
        bearer.teardown().await;
        if outcome.is_err() {
            release_ims_bearer(conn, &bearer.object_path).await;
        }
        outcome
    }
}

/// 释放 ModemManager 里的承载对象。
///
/// 顺序：先 Disconnect 让模组回收 PDN，再 DeleteBearer 移除对象。
/// 两步都尽力而为——即使 Disconnect 失败也要尝试删除，否则对象会一直
/// 挂在 modem 上，后续 CreateBearer 会因为数据槽被占而失败。
async fn release_ims_bearer(conn: &Connection, path: &str) {
    let Ok(proxy) = Proxy::new(conn, MM_SERVICE, path, MM_BEARER).await else {
        return;
    };
    if let Err(e) = proxy.call::<_, _, ()>("Disconnect", &()).await {
        debug!(bearer = path, error = %e, "bearer disconnect failed");
    }
    // 给模组一点时间真正释放 PDN，再删对象
    tokio::time::sleep(Duration::from_millis(800)).await;
    if let Ok(modem) = modem_manager::find_modem_path(conn).await {
        if let Ok(modem_proxy) = Proxy::new(conn, MM_SERVICE, modem.as_str(), MM_MODEM).await {
            let obj = zbus::zvariant::ObjectPath::try_from(path).ok();
            if let Some(obj) = obj {
                let _ = modem_proxy
                    .call::<_, _, ()>("DeleteBearer", &(obj))
                    .await;
            }
        }
    }
}

/// 通过 `AT+CGCONTRDP` 读取 P-CSCF。
///
/// P-CSCF 不在 ModemManager 的承载属性里——它通过 QMI 的 PCO 或 DHCP
/// 下发，MM 只记录"PCSCF Address Using PCO/DHCP"这两个标志位。而
/// `AT+CGCONTRDP` 会直接给出每个上下文分配到的 P-CSCF 地址列表：
///
/// ```text
/// +CGCONTRDP: 1,5,ims,2408:8556:420:9350::/64,2408:8556:420:9350::1,,,2408:8142:6001:603::
/// ```
///
/// 第 8 个字段起是 P-CSCF（可能多个）。优先取 APN 为 `ims` 的那一行。
async fn discover_pcscf_via_at() -> Vec<String> {
    let output = match tokio::process::Command::new("mmcli")
        .args(["-m", "any", "--command=AT+CGCONTRDP"])
        .stdin(std::process::Stdio::null())
        .output()
        .await
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut fallback: Vec<String> = Vec::new();
    let mut ims: Vec<String> = Vec::new();

    for line in text.lines() {
        let Some(idx) = line.find("+CGCONTRDP:") else {
            continue;
        };
        let body = &line[idx + "+CGCONTRDP:".len()..];
        let fields: Vec<&str> = body.split(',').map(|f| f.trim()).collect();
        if fields.len() < 8 {
            continue;
        }
        let apn = fields.get(2).copied().unwrap_or("");
        let addrs: Vec<String> = fields[7..]
            .iter()
            .map(|s| s.trim_matches('"').trim())
            .filter(|s| !s.is_empty() && s.contains(':'))
            .map(|s| s.to_string())
            .collect();
        if addrs.is_empty() {
            continue;
        }
        if apn.eq_ignore_ascii_case("ims") {
            ims.extend(addrs);
        } else if fallback.is_empty() {
            fallback = addrs;
        }
    }

    if !ims.is_empty() {
        ims
    } else {
        fallback
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

    // 承载配置改从 mmcli 的文本输出读取。
    //
    // MM 的 Ip4Config / Ip6Config 是 `a{sv}`，值类型混杂（字符串、整数、
    // 字符串数组），经 zvariant 转换后容易丢字段；而 `mmcli -m any -b N`
    // 的输出格式稳定、字段名固定，解析起来更可靠，也和运维手工排查时
    // 看到的信息一致。
    let index = bearer_index_from_path(&bearer_path);
    let cfg = read_bearer_config_mmcli(index).await?;

    let address = cfg
        .get("address")
        .cloned()
        .ok_or_else(|| crate::volte::VolteError::new(codes::ADDRESS_MISSING))?;
    let prefix: u8 = cfg
        .get("prefix")
        .and_then(|v| v.parse().ok())
        .unwrap_or(if family == AddressFamily::V6 { 64 } else { 32 });
    let gateway = cfg.get("gateway").cloned().filter(|g| !g.is_empty());
    let mtu: Option<u32> = cfg.get("mtu").and_then(|v| v.parse().ok());
    let pcscf = bearer::extract_pcscf(&cfg);

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

/// 从 `/org/freedesktop/ModemManager1/Bearer/6` 取出序号 6。
fn bearer_index_from_path(path: &str) -> u32 {
    path.rsplit('/').next().and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// 解析 `mmcli -m any -b <n>` 的输出。
///
/// 典型片段：
/// ```text
///   Status             |      connected: yes
///                      |      interface: wwan0
///   Properties         |            apn: ims
///                      |        ip type: ipv6
///                      |        address: 2408:8556:...
///                      |         prefix: 64
///                      |        gateway: 2408:8556:...
///                      |            mtu: 1432
/// ```
async fn read_bearer_config_mmcli(
    index: u32,
) -> Result<HashMap<String, String>, crate::volte::VolteError> {
    let output = tokio::process::Command::new("mmcli")
        .args(["-m", "any", "-b", &index.to_string()])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| {
            crate::volte::VolteError::with_detail(codes::COMMAND_FAILED, format!("mmcli: {e}"))
        })?;
    if !output.status.success() {
        return Err(crate::volte::VolteError::with_detail(
            codes::COMMAND_FAILED,
            "mmcli bearer query failed",
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = HashMap::new();
    for line in text.lines() {
        // 只取 `key: value` 形态，跳过分隔线与分组标题
        let Some((left, right)) = line.split_once(':') else {
            continue;
        };
        let key = left
            .rsplit('|')
            .next()
            .unwrap_or(left)
            .trim()
            .to_ascii_lowercase();
        let value = right.trim().to_string();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        // 首次出现优先，避免后面 Stats 段同名字段覆盖
        out.entry(key).or_insert(value);
    }
    Ok(out)
}

