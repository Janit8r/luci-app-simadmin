//! IMS 运行时：注册状态机 + SIP 双 socket + MO/MT 短信。
//!
//! 流程（与设备侧实测的 mifi44-ims 一致）：
//!
//! ```text
//!   IMSI/AID ─→ IMS PDN（qmicli 优先，裸 QMUX 降级）─→ P-CSCF + 主机路由
//!        └→ REGISTER#1（空 Digest + Security-Client）
//!              └→ 401 ─→ USIM AKA（qmi-proxy 优先，裸 QMUX 降级）
//!                    └→ ip xfrm 无缝换装 ─→ REGISTER#2（Authorization + Security-Client + Security-Verify）
//!                          └→ 200 OK ─→ 常驻收包（port_c + port_s）
//! ```
//!
//! IPsec 任何一步失败都退回纯 UDP 重注册（`Supported: path`，不带 sec-agree），
//! 这样在 iproute2/xfrm 不可用的固件上短信仍然可用。
//!
//! MO：SMS-SUBMIT → RP-DATA → SIP MESSAGE，等 2xx + 同 reference 的 RP-ACK。
//! MT：200 OK（空体）+ 单独一条带 RP-ACK 体的 MESSAGE，再落库/通知。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

use super::aka::{self, AkaResult};
use super::bearer::{self, BearerConfig, ImsBearer};
use super::identity::{self, ImsIdentity};
use super::ipsec::{self, IpsecContext, SecurityClient};
use super::sip::{self, MessageParams, RegisterParams};
use super::sms::{self, Concat, MultipartCache, MultipartOutcome, RpType};
use super::usim;
use super::{err, ImsFamily};

// ---------------------------------------------------------------------------
// 状态模型（字段与 /api/volte/control 的 runtime 段一一对应）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Disabled,
    Starting,
    Registered,
    Degraded,
    Stopping,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Disabled => "disabled",
            Phase::Starting => "starting",
            Phase::Registered => "registered",
            Phase::Degraded => "degraded",
            Phase::Stopping => "stopping",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Starting,
    Identity,
    IdentityAka,
    Radio,
    Bearer,
    Pcscf,
    RegisterIpsec,
    RegisterUdp,
    Registered,
    Stopping,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Starting => "starting",
            Stage::Identity => "identity",
            Stage::IdentityAka => "identity_aka",
            Stage::Radio => "radio",
            Stage::Bearer => "bearer",
            Stage::Pcscf => "pcscf",
            Stage::RegisterIpsec => "register_ipsec",
            Stage::RegisterUdp => "register_udp",
            Stage::Registered => "registered",
            Stage::Stopping => "stopping",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    Ipsec,
    PlainUdp,
}

impl RegistrationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RegistrationMode::Ipsec => "register_ipsec",
            RegistrationMode::PlainUdp => "register_udp",
        }
    }
}

/// 对外状态快照。
#[derive(Debug, Clone)]
pub struct Status {
    pub phase: Phase,
    pub stage: Stage,
    pub registration_mode: Option<RegistrationMode>,
    pub registered_at: Option<u64>,
    pub last_rx_at: Option<u64>,
    pub last_tx_at: Option<u64>,
    pub last_error: Option<String>,
    pub last_failure_at: Option<u64>,
    pub next_retry_at: Option<u64>,
    /// 连续失败次数（成功注册后清零）。
    pub failure_count: u64,
    pub sent_count: u64,
    pub received_count: u64,
    pub duplicate_count: u64,
    pub reconnect_count: u64,
    pub imsi: Option<String>,
    pub home_domain: Option<String>,
    pub public_identity: Option<String>,
    pub pcscf: Option<String>,
    pub ue_address: Option<String>,
    pub own_number: Option<String>,
    pub interface: Option<String>,
    pub bearer_source: Option<String>,
    pub aka_transport: Option<String>,
    /// 实际使用的短信中心号码。
    pub smsc: Option<String>,
    /// 本次会话开始时间（unix 秒）。
    pub session_started_at: Option<u64>,
    /// 注册过期时间（unix 秒），manager 用它判断状态是否还新鲜。
    pub expires_at: Option<u64>,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            phase: Phase::Disabled,
            stage: Stage::Starting,
            registration_mode: None,
            registered_at: None,
            last_rx_at: None,
            last_tx_at: None,
            last_error: None,
            last_failure_at: None,
            next_retry_at: None,
            failure_count: 0,
            sent_count: 0,
            received_count: 0,
            duplicate_count: 0,
            reconnect_count: 0,
            imsi: None,
            home_domain: None,
            public_identity: None,
            pcscf: None,
            ue_address: None,
            own_number: None,
            interface: None,
            bearer_source: None,
            aka_transport: None,
            smsc: None,
            session_started_at: None,
            expires_at: None,
        }
    }
}

impl Status {
    pub fn live(&self, now: u64) -> bool {
        self.phase == Phase::Registered
            && self.expires_at.map(|exp| exp > now + 5).unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// 配置 / 命令 / 结果
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// IMS APN；空 = 由 IMSI 推导（`ims.epc.mncXXX.mccXXX.gprs`）。
    pub apn: String,
    /// QMI profile 索引（0/None = 不用 profile）。
    pub profile: Option<u8>,
    pub mux: u8,
    pub interface: Option<String>,
    pub pcscf: Option<IpAddr>,
    /// SMSC（空 = 运行时自动探测）。
    pub smsc: String,
    /// 重新注册周期。
    pub refresh_secs: u64,
    pub port_c: u16,
    pub port_s: u16,
    /// 是否尝试 IPsec；false 时直接用纯 UDP。
    pub prefer_ipsec: bool,
    /// 是否接管短信（关掉只注册不收发）。
    pub sms_enabled: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            apn: String::new(),
            profile: None,
            mux: 2,
            interface: None,
            pcscf: None,
            smsc: String::new(),
            refresh_secs: 1800,
            port_c: super::UE_PORT_C_DEFAULT,
            port_s: super::UE_PORT_S_DEFAULT,
            prefer_ipsec: true,
            sms_enabled: true,
        }
    }
}

/// 收到的短信（交给 manager 落库 + 通知）。
#[derive(Debug, Clone)]
pub struct IncomingSms {
    pub sender: String,
    pub text: String,
    pub timestamp: String,
    /// 去重标记（`ims:<md5>`），直接写进 DB 的 pdu 列。
    pub marker: String,
}

#[derive(Debug)]
pub enum Command {
    Refresh,
    Send {
        phone: String,
        text: String,
        reply: oneshot::Sender<SendOutcome>,
    },
    Stop,
}

#[derive(Debug, Clone, Default)]
pub struct SendOutcome {
    pub sent: bool,
    pub sip_accepted: bool,
    pub rp_ack: bool,
    pub status: Option<String>,
    pub error: Option<String>,
    pub delivery_unknown: bool,
}

impl SendOutcome {
    fn fail(message: impl Into<String>) -> Self {
        Self {
            error: Some(message.into()),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// 会话（注册成功后持有的全部东西）
// ---------------------------------------------------------------------------

struct Session {
    identity: ImsIdentity,
    bearer: ImsBearer,
    pcscf: IpAddr,
    /// 明文 5060 端口。
    pc_plain: SocketAddr,
    /// 受保护请求去向（Security-Server 的 port-s）。
    pc_prot: SocketAddr,
    /// P-CSCF 发往 UE 的源端口（port-c）。
    pc_reply_port: u16,
    cli: Arc<UdpSocket>,
    srv: Arc<UdpSocket>,
    mode: RegistrationMode,
    call_id: String,
    from_tag: String,
    cseq: u32,
    impu: String,
    service_routes: Vec<String>,
    own_number: Option<String>,
    smsc: String,
    ipsec: Option<IpsecContext>,
    sec_client: SecurityClient,
    aka_transport: Option<usim::AkaTransport>,
}

impl Session {
    fn contact_host(&self) -> String {
        format!("[{}]", self.bearer.local)
    }

    /// 发往 P-CSCF 受保护端口的请求。
    async fn send_prot(&self, packet: &[u8]) -> Result<(), String> {
        self.cli
            .send_to(packet, self.pc_prot)
            .await
            .map(|_| ())
            .map_err(|e| format!("sip send: {e}"))
    }

    fn next_cseq(&mut self) -> u32 {
        self.cseq = self.cseq.wrapping_add(1);
        self.cseq
    }
}

// ---------------------------------------------------------------------------
// 共享状态
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Pending {
    reference: u8,
    sip_accepted: bool,
    rp_ack: bool,
    error: Option<String>,
    status: Option<String>,
    done: Option<oneshot::Sender<SendOutcome>>,
}

impl Pending {
    fn complete_if_ready(&mut self) {
        if self.error.is_some() || (self.sip_accepted && self.rp_ack) {
            if let Some(tx) = self.done.take() {
                let _ = tx.send(SendOutcome {
                    sent: self.error.is_none() && self.sip_accepted && self.rp_ack,
                    sip_accepted: self.sip_accepted,
                    rp_ack: self.rp_ack,
                    status: self.status.clone(),
                    error: self.error.clone(),
                    delivery_unknown: self.error.is_none() && self.sip_accepted && !self.rp_ack,
                });
            }
        }
    }
}

pub struct Shared {
    status: RwLock<Status>,
    session: RwLock<Option<Arc<Session>>>,
    pending: Mutex<HashMap<String, Pending>>,
    multipart: MultipartCache,
    /// MT 事件出口（manager 消费）。
    incoming: mpsc::Sender<IncomingSms>,
    /// 最近处理过的 MT 去重标记 → 时间（TTL 10 分钟）。
    seen: Mutex<HashMap<String, Instant>>,
    seq: AtomicU64,
}

impl Shared {
    pub fn new(incoming: mpsc::Sender<IncomingSms>) -> Arc<Self> {
        Arc::new(Self {
            status: RwLock::new(Status::default()),
            session: RwLock::new(None),
            pending: Mutex::new(HashMap::new()),
            multipart: MultipartCache::new(),
            incoming,
            seen: Mutex::new(HashMap::new()),
            seq: AtomicU64::new(1),
        })
    }

    pub async fn status(&self) -> Status {
        self.status.read().await.clone()
    }

    async fn set_status(&self, update: impl FnOnce(&mut Status)) {
        let mut status = self.status.write().await;
        update(&mut status);
    }

    /// 供 manager 侧查询当前会话（诊断用）。
    #[allow(dead_code)]
    async fn session(&self) -> Option<Arc<Session>> {
        self.session.read().await.clone()
    }

    fn next_u64(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// 主循环
// ---------------------------------------------------------------------------

/// 运行到收到 [`Command::Stop`] 为止。返回后所有 socket/SA 都已清理。
pub async fn run(shared: Arc<Shared>, cfg: RuntimeConfig, mut commands: mpsc::Receiver<Command>) {
    let mut backoff = 2u64;
    let mut current: Option<Arc<Session>> = None;

    loop {
        if current.is_none() {
            shared
                .set_status(|s| {
                    s.phase = Phase::Starting;
                    s.stage = Stage::Starting;
                    s.last_error = None;
                })
                .await;
            match establish(Arc::clone(&shared), &cfg, None).await {
                Ok(session) => {
                    let session = Arc::new(session);
                    *shared.session.write().await = Some(Arc::clone(&session));
                    publish_registered(&shared, &session, &cfg).await;
                    tracing::info!(
                        target: "simadmin::volte",
                        pcscf = %session.pcscf,
                        mode = session.mode.as_str(),
                        interface = %session.bearer.interface,
                        "IMS REGISTER 200 OK — 短信通道已接管"
                    );
                    current = Some(session);
                    backoff = 2;
                }
                Err(error) => {
                    mark_degraded(&shared, &error, backoff).await;
                }
            }
        }

        if let Some(session) = current.clone() {
            match serve(Arc::clone(&shared), Arc::clone(&session), &cfg, &mut commands).await {
                ServeOutcome::Stop => break,
                ServeOutcome::Failed(error) => {
                    *shared.session.write().await = None;
                    current = None;
                    mark_degraded(&shared, &error, backoff).await;
                }
                ServeOutcome::Refresh => {
                    match refresh(&shared, &cfg, &session).await {
                        Ok(refreshed) => {
                            *shared.session.write().await = Some(Arc::clone(&refreshed));
                            publish_registered(&shared, &refreshed, &cfg).await;
                            current = Some(refreshed);
                            backoff = 2;
                            continue;
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: "simadmin::volte",
                                error = %error,
                                "IMS 刷新失败，重建会话"
                            );
                            *shared.session.write().await = None;
                            current = None;
                            mark_degraded(&shared, &error, 3).await;
                        }
                    }
                }
            }
        }

        // 退避等待，期间允许 Stop / 手动刷新。
        let wait = tokio::time::sleep(Duration::from_secs(backoff));
        tokio::pin!(wait);
        let mut stop = false;
        loop {
            tokio::select! {
                _ = &mut wait => break,
                command = commands.recv() => match command {
                    Some(Command::Stop) | None => { stop = true; break; }
                    Some(Command::Refresh) => break,
                    Some(Command::Send { reply, .. }) => {
                        let _ = reply.send(SendOutcome::fail(err::NOT_REGISTERED));
                    }
                }
            }
        }
        if stop {
            break;
        }
        backoff = (backoff * 2).min(120);
    }

    shared
        .set_status(|s| {
            s.phase = Phase::Stopping;
            s.stage = Stage::Stopping;
            s.expires_at = None;
        })
        .await;
    if let Some(session) = shared.session.write().await.take() {
        cleanup_ipsec(&session).await;
    }
    shared
        .set_status(|s| {
            s.phase = Phase::Disabled;
            s.registered_at = None;
        })
        .await;
    tracing::info!(target: "simadmin::volte", "IMS 运行时已停止");
}

async fn publish_registered(shared: &Arc<Shared>, session: &Arc<Session>, cfg: &RuntimeConfig) {
    shared
        .set_status(|s| {
            s.phase = Phase::Registered;
            s.stage = Stage::Registered;
            s.registration_mode = Some(session.mode);
            s.registered_at = Some(now_unix());
            s.expires_at = Some(now_unix() + cfg.refresh_secs + 60);
            s.last_error = None;
            s.next_retry_at = None;
            s.failure_count = 0;
            s.imsi = Some(session.identity.imsi.clone());
            s.home_domain = Some(session.identity.home_domain.clone());
            s.public_identity = Some(session.impu.clone());
            s.pcscf = Some(session.pcscf.to_string());
            s.ue_address = Some(session.bearer.local.to_string());
            s.interface = Some(session.bearer.interface.clone());
            s.bearer_source = Some(session.bearer.source.as_str().to_string());
            s.aka_transport = session.aka_transport.map(|t| t.as_str().to_string());
            s.smsc = Some(session.smsc.clone()).filter(|v| !v.trim().is_empty());
            if s.session_started_at.is_none() {
                s.session_started_at = Some(now_unix());
            }
            if session.own_number.is_some() {
                s.own_number = session.own_number.clone();
            }
        })
        .await;
}

async fn mark_degraded(shared: &Arc<Shared>, error: &str, backoff: u64) {
    let now = now_unix();
    shared
        .set_status(|s| {
            s.phase = Phase::Degraded;
            s.last_error = Some(sanitize(error));
            s.last_failure_at = Some(now);
            s.next_retry_at = Some(now + backoff);
            s.failure_count = s.failure_count.saturating_add(1);
            s.expires_at = None;
        })
        .await;
    tracing::warn!(target: "simadmin::volte", error = %sanitize(error), backoff, "IMS 运行时降级");
}

enum ServeOutcome {
    Refresh,
    Stop,
    Failed(String),
}

// ---------------------------------------------------------------------------
// 建立会话
// ---------------------------------------------------------------------------

async fn establish(
    shared: Arc<Shared>,
    cfg: &RuntimeConfig,
    previous: Option<&IpsecContext>,
) -> Result<Session, String> {
    // 1) 身份：IMSI / AID / home domain
    shared.set_status(|s| s.stage = Stage::Identity).await;
    let (imsi, aid) = tokio::task::spawn_blocking(read_identity_inputs)
        .await
        .map_err(|e| format!("identity task: {e}"))??;
    let ident = identity::build(&imsi, None, None, Some(aid), Some(cfg.smsc.clone()))?;

    // 2) 承载
    shared.set_status(|s| s.stage = Stage::Bearer).await;
    let bearer_cfg = BearerConfig {
        apn: if cfg.apn.is_empty() {
            ident.apn.clone()
        } else {
            cfg.apn.clone()
        },
        profile: cfg.profile,
        mux: cfg.mux,
        interface: cfg.interface.clone(),
        pcscf: cfg.pcscf,
    };
    let bearer = tokio::task::spawn_blocking(move || bearer::bring_up(&bearer_cfg))
        .await
        .map_err(|e| format!("bearer task: {e}"))??;
    tracing::info!(
        target: "simadmin::volte",
        interface = %bearer.interface,
        local = %bearer.local,
        source = bearer.source.as_str(),
        "IMS 承载就绪"
    );

    // 3) P-CSCF + 主机路由
    shared.set_status(|s| s.stage = Stage::Pcscf).await;
    let pcscf = bearer
        .pcscf
        .first()
        .copied()
        .ok_or_else(|| err::RUNTIME_ALL_PCSCF_FAILED.to_string())?;
    {
        let bearer = bearer.clone();
        tokio::task::spawn_blocking(move || bearer::install_pcscf_route(&bearer, pcscf))
            .await
            .map_err(|e| format!("route task: {e}"))??;
    }

    // 4) SIP socket（绑定 IMS 承载地址，尽量绑定设备）
    let (cli, srv) = bind_sockets(&bearer, cfg).await?;

    let pc_plain = match pcscf {
        IpAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(addr, 5060, 0, 0)),
        IpAddr::V4(addr) => SocketAddr::V4(std::net::SocketAddrV4::new(addr, 5060)),
    };

    let mut session = Session {
        identity: ident,
        bearer,
        pcscf,
        pc_plain,
        pc_prot: pc_plain,
        pc_reply_port: 5060,
        cli: Arc::new(cli),
        srv: Arc::new(srv),
        mode: RegistrationMode::PlainUdp,
        call_id: format!("{:016x}@simadmin", shared.next_u64()),
        from_tag: format!("{:012x}", shared.next_u64()),
        cseq: 0,
        impu: String::new(),
        service_routes: Vec::new(),
        own_number: None,
        smsc: String::new(),
        ipsec: previous.cloned(),
        sec_client: SecurityClient {
            spi_c: 0,
            spi_s: 0,
            port_c: cfg.port_c,
            port_s: cfg.port_s,
        },
        aka_transport: None,
    };
    session.impu = session.identity.public_identity.clone();

    // 5) 注册：先 IPsec，失败退纯 UDP
    if cfg.prefer_ipsec {
        shared
            .set_status(|s| s.stage = Stage::RegisterIpsec)
            .await;
        match register_rounds(&shared, &mut session, RegistrationMode::Ipsec).await {
            Ok(()) => {
                session.mode = RegistrationMode::Ipsec;
            }
            Err(error) => {
                tracing::warn!(
                    target: "simadmin::volte",
                    error = %error,
                    "IPsec 注册失败，回落纯 UDP SIP"
                );
                let _ = cleanup_ipsec(&session).await;
                shared.set_status(|s| s.stage = Stage::RegisterUdp).await;
                register_rounds(&shared, &mut session, RegistrationMode::PlainUdp).await?;
                session.mode = RegistrationMode::PlainUdp;
            }
        }
    } else {
        shared.set_status(|s| s.stage = Stage::RegisterUdp).await;
        register_rounds(&shared, &mut session, RegistrationMode::PlainUdp).await?;
        session.mode = RegistrationMode::PlainUdp;
    }

    // 6) SMSC：配置 → AT+CSCA? → EF_SMSC
    session.smsc = resolve_smsc(&session.identity).await;
    if session.smsc.is_empty() {
        tracing::warn!(
            target: "simadmin::volte",
            "未取到短信中心号码，MO 发送会失败（可在配置里指定 volte.smsc）"
        );
    }

    Ok(session)
}

async fn bind_sockets(
    bearer: &ImsBearer,
    cfg: &RuntimeConfig,
) -> Result<(UdpSocket, UdpSocket), String> {
    let local = bearer.local;
    let interface = bearer.interface.clone();
    let (port_c, port_s) = (cfg.port_c, cfg.port_s);
    let (cli, srv) = tokio::task::spawn_blocking(move || {
        let cli = bind_udp(local, port_c, &interface)?;
        let srv = bind_udp(local, port_s, &interface)?;
        Ok::<_, String>((cli, srv))
    })
    .await
    .map_err(|e| format!("bind task: {e}"))??;
    Ok((cli, srv))
}

fn bind_udp(local: IpAddr, port: u16, interface: &str) -> Result<UdpSocket, String> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if local.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("socket: {e}"))?;
    if local.is_ipv6() {
        let _ = socket.set_only_v6(true);
    }
    // 绑定到 IMS 承载，避免默认路由把 SIP 带去 default-attach。
    if let Err(error) = socket.bind_device(Some(interface.as_bytes())) {
        tracing::debug!(
            target: "simadmin::volte",
            interface,
            error = %error,
            "SO_BINDTODEVICE 失败，改用地址绑定"
        );
    }
    let addr: SocketAddr = SocketAddr::new(local, port);
    socket
        .bind(&addr.into())
        .map_err(|e| format!("bind {addr}: {e}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| format!("nonblocking: {e}"))?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).map_err(|e| format!("tokio udp: {e}"))
}

// ---------------------------------------------------------------------------
// 注册两轮
// ---------------------------------------------------------------------------

async fn register_rounds(
    shared: &Arc<Shared>,
    session: &mut Session,
    mode: RegistrationMode,
) -> Result<(), String> {
    let sec_agree = mode == RegistrationMode::Ipsec;
    let uri = format!("sip:{}", session.identity.home_domain);
    let sec_client = SecurityClient {
        spi_c: random_u32(shared),
        spi_s: random_u32(shared),
        port_c: session.bearer_port_c(),
        port_s: session.bearer_port_s(),
    };
    session.sec_client = sec_client;
    let sec_client_header = sec_client.to_header();

    // 首轮：空 Digest（部分 P-CSCF 需要 IMPI 才能选认证向量）。
    let empty_auth = format!(
        "Digest username=\"{}\",realm=\"{}\",nonce=\"\",uri=\"{}\",response=\"\",algorithm=AKAv1-MD5",
        session.identity.private_identity, session.identity.home_domain, uri
    );

    let mut server: Option<ipsec::SecurityServer> = None;
    let mut cseq = session.next_cseq();
    let mut branch = format!("z9hG4bK{:016x}", shared.next_u64());
    let contact_host = session.contact_host();
    let request = sip::build_register(&RegisterParams {
        home_domain: &session.identity.home_domain,
        public_identity: &session.identity.public_identity,
        contact_host: &contact_host,
        contact_user: Some(&session.identity.imsi),
        contact_port: session.bearer_port_s(),
        call_id: &session.call_id,
        cseq,
        from_tag: &session.from_tag,
        branch: &branch,
        authorization: Some(&empty_auth),
        security_client: sec_agree.then_some(sec_client_header.as_str()),
        security_verify: None,
        preferred_identity: Some(&session.identity.public_identity),
        smsip: true,
        sec_agree,
        unregister: false,
        transport: "UDP",
    });

    let first = send_and_wait(shared, session, request.into_bytes(), session.pc_plain, 10).await?;
    if first.status == 200 {
        apply_acceptance(session, &first);
        return Ok(());
    }
    if first.status != 401 {
        return Err(format!(
            "{}: REGISTER#1 -> {} {}",
            err::REGISTER_REJECTED,
            first.status,
            first.reason
        ));
    }

    // 401 → AKA
    let www = first
        .header("WWW-Authenticate")
        .ok_or_else(|| err::DIGEST_CHALLENGE_MISSING.to_string())?;
    let chal = aka::parse_challenge(www)?;
    if !chal.algorithm.is_aka() {
        return Err(err::DIGEST_ALGORITHM_UNSUPPORTED.to_string());
    }
    if let Some(header) = first.header("Security-Server") {
        server = ipsec::parse_security_server(header).ok();
        if let Some(server) = server.as_ref() {
            session.pc_prot = with_port(session.pcscf, server.port_s);
            session.pc_reply_port = server.port_c;
        }
    }
    // 401 一定带 challenge，因此这里直接初始化；AUTS 重同步分支会覆盖它。
    let mut challenge: Option<aka::DigestChallenge> = Some(chal.clone());

    shared.set_status(|s| s.stage = Stage::IdentityAka).await;
    let aka_challenge = aka::aka_challenge_from_nonce(&chal.nonce)?;
    let aid = session.identity.usim_aid.clone();
    let (result, transport) = tokio::task::spawn_blocking(move || {
        usim::authenticate(&aka_challenge, &aid)
    })
    .await
    .map_err(|e| format!("aka task: {e}"))??;
    session.aka_transport = Some(transport);

    let (res, ck, ik) = match result {
        AkaResult::Resync { auts } => {
            // TS 33.102 重同步：带 auts 明文重发首轮，网络回新 nonce 的 401。
            tracing::warn!(
                target: "simadmin::volte",
                "USIM 返回 AUTS，发起 AKA 重同步"
            );
            let cnonce = format!("{:016x}", shared.next_u64());
            let response = aka::digest_response(
                &session.identity.private_identity,
                &chal.realm,
                &auts,
                "REGISTER",
                &uri,
                &chal.nonce_b64,
                chal.qop.as_deref(),
                aka::NONCE_COUNT,
                &cnonce,
            );
            let auts_b64 = aka::base64_encode(&auts);
            let auth = aka::authorization_header(
                &session.identity.private_identity,
                &chal.realm,
                &uri,
                &chal.nonce_b64,
                &response,
                chal.algorithm,
                chal.qop.as_deref(),
                Some(&cnonce),
                chal.opaque.as_deref(),
                Some(&auts_b64),
            );
            cseq = session.next_cseq();
            branch = format!("z9hG4bK{:016x}", shared.next_u64());
            let request = sip::build_register(&RegisterParams {
                home_domain: &session.identity.home_domain,
                public_identity: &session.identity.public_identity,
                contact_host: &contact_host,
                contact_user: Some(&session.identity.imsi),
                contact_port: session.bearer_port_s(),
                call_id: &session.call_id,
                cseq,
                from_tag: &session.from_tag,
                branch: &branch,
                authorization: Some(&auth),
                security_client: sec_agree.then_some(sec_client_header.as_str()),
                security_verify: None,
                preferred_identity: Some(&session.identity.public_identity),
                smsip: true,
                sec_agree,
                unregister: false,
                transport: "UDP",
            });
            let retry =
                send_and_wait(shared, session, request.into_bytes(), session.pc_plain, 10).await?;
            if retry.status == 200 {
                apply_acceptance(session, &retry);
                return Ok(());
            }
            if retry.status != 401 {
                return Err(format!(
                    "{}: REGISTER#1(auts) -> {}",
                    err::REGISTER_REJECTED,
                    retry.status
                ));
            }
            let www = retry
                .header("WWW-Authenticate")
                .ok_or_else(|| err::DIGEST_CHALLENGE_MISSING.to_string())?;
            let chal = aka::parse_challenge(www)?;
            let aka_challenge = aka::aka_challenge_from_nonce(&chal.nonce)?;
            let aid = session.identity.usim_aid.clone();
            let (result, transport) =
                tokio::task::spawn_blocking(move || usim::authenticate(&aka_challenge, &aid))
                    .await
                    .map_err(|e| format!("aka task: {e}"))??;
            session.aka_transport = Some(transport);
            challenge = Some(chal);
            match result {
                AkaResult::Success { res, ck, ik } => (res, ck, ik),
                AkaResult::Resync { .. } => {
                    return Err(format!("{}: AKA 重同步后仍然失步", err::USIM_AKA_FAILED))
                }
            }
        }
        AkaResult::Success { res, ck, ik } => (res, ck, ik),
    };

    let chal = challenge.ok_or_else(|| err::DIGEST_CHALLENGE_MISSING.to_string())?;
    aka::validate_aka_result(
        &AkaResult::Success {
            res: res.clone(),
            ck: ck.clone(),
            ik: ik.clone(),
        },
        sec_agree,
    )?;

    // IPsec：先装 SA 再发二轮（顺序错了包会被策略丢弃）。
    let mut verify_header: Option<String> = None;
    if sec_agree {
        let Some(server) = server.clone() else {
            return Err(err::SECURITY_SERVER_MISSING.to_string());
        };
        if ik.len() < 16 {
            return Err(err::IPSEC_IK_INVALID.to_string());
        }
        let ue_addr = match session.bearer.local {
            IpAddr::V6(addr) => addr,
            IpAddr::V4(_) => return Err(err::IPSEC_REQUIRES_IPV6.to_string()),
        };
        let pcscf_addr = match session.pcscf {
            IpAddr::V6(addr) => addr,
            IpAddr::V4(_) => return Err(err::IPSEC_REQUIRES_IPV6.to_string()),
        };
        let ctx = IpsecContext {
            ue_addr,
            pcscf_addr,
            client: sec_client,
            server: server.clone(),
            ik: ik.clone(),
        };
        let previous = session.ipsec.clone();
        let ctx_for_task = ctx.clone();
        let previous_for_task = previous.clone();
        tokio::task::spawn_blocking(move || {
            install_xfrm(&ctx_for_task, previous_for_task.as_ref())
        })
        .await
        .map_err(|e| format!("xfrm task: {e}"))??;
        session.ipsec = Some(ctx);
        verify_header = Some(ipsec::security_verify_header(&server));
    }

    // 二轮：Authorization + Security-Client + Security-Verify
    let password = aka::digest_password(chal.algorithm, &res, &ck, &ik);
    let cnonce = format!("{:016x}", shared.next_u64());
    let response = aka::digest_response(
        &session.identity.private_identity,
        &chal.realm,
        &password,
        "REGISTER",
        &uri,
        &chal.nonce_b64,
        chal.qop.as_deref(),
        aka::NONCE_COUNT,
        &cnonce,
    );
    let auth = aka::authorization_header(
        &session.identity.private_identity,
        &chal.realm,
        &uri,
        &chal.nonce_b64,
        &response,
        chal.algorithm,
        chal.qop.as_deref(),
        Some(&cnonce),
        chal.opaque.as_deref(),
        None,
    );

    cseq = session.next_cseq();
    branch = format!("z9hG4bK{:016x}", shared.next_u64());
    let request = sip::build_register(&RegisterParams {
        home_domain: &session.identity.home_domain,
        public_identity: &session.identity.public_identity,
        contact_host: &contact_host,
        contact_user: Some(&session.identity.imsi),
        contact_port: session.bearer_port_s(),
        call_id: &session.call_id,
        cseq,
        from_tag: &session.from_tag,
        branch: &branch,
        authorization: Some(&auth),
        security_client: sec_agree.then_some(sec_client_header.as_str()),
        security_verify: verify_header.as_deref(),
        preferred_identity: Some(&session.identity.public_identity),
        smsip: true,
        sec_agree,
        unregister: false,
        transport: "UDP",
    });

    let second = send_and_wait(
        shared,
        session,
        request.into_bytes(),
        session.pc_prot,
        10,
    )
    .await?;
    if second.status == 200 {
        apply_acceptance(session, &second);
        return Ok(());
    }
    Err(format!(
        "{}: REGISTER#2 -> {} {}",
        err::REGISTER_REJECTED,
        second.status,
        second.reason
    ))
}

fn apply_acceptance(session: &mut Session, response: &sip::Response) {
    let acceptance = sip::acceptance_headers(response);
    for uri in &acceptance.associated_uri {
        if let Some(number) = identity::own_number_from_p_associated_uri(uri) {
            session.own_number = Some(number);
        }
        if session.impu.is_empty() {
            if let Some(sip_uri) = uri
                .split(',')
                .map(|part| part.trim().trim_start_matches('<').trim_end_matches('>'))
                .find(|part| part.starts_with("sip:"))
            {
                session.impu = sip_uri.to_string();
            }
        }
    }
    session.service_routes = acceptance
        .service_route
        .iter()
        .flat_map(|value| value.split(','))
        .map(|part| {
            part.trim()
                .trim_start_matches('<')
                .trim_end_matches('>')
                .to_string()
        })
        .filter(|part| !part.is_empty())
        .collect();
    if !acceptance.contact_smsip {
        tracing::warn!(
            target: "simadmin::volte",
            "REGISTER 200 的 Contact 未回显 +g.3gpp.smsip，MT 可能收不到"
        );
    }
}

fn with_port(addr: IpAddr, port: u16) -> SocketAddr {
    match addr {
        IpAddr::V6(a) => SocketAddr::V6(SocketAddrV6::new(a, port, 0, 0)),
        IpAddr::V4(a) => SocketAddr::V4(std::net::SocketAddrV4::new(a, port)),
    }
}

fn install_xfrm(ctx: &IpsecContext, previous: Option<&IpsecContext>) -> Result<(), String> {
    let commands = ipsec::install_seamless(ctx, previous)?;
    let mut failures = 0;
    for argv in &commands {
        if argv.is_empty() {
            continue;
        }
        match std::process::Command::new(&argv[0]).args(&argv[1..]).output() {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                // 删除旧 SA/策略时目标可能已不存在，不算致命。
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if argv.contains(&"del".to_string()) {
                    tracing::debug!(
                        target: "simadmin::volte",
                        cmd = %argv.join(" "),
                        error = %stderr,
                        "xfrm 清理未命中"
                    );
                } else {
                    failures += 1;
                    tracing::warn!(
                        target: "simadmin::volte",
                        cmd = %argv.join(" "),
                        error = %stderr,
                        "xfrm 安装失败"
                    );
                }
            }
            Err(error) => {
                failures += 1;
                tracing::warn!(target: "simadmin::volte", error = %error, "xfrm 命令无法执行");
            }
        }
    }
    if failures > 0 {
        return Err(format!("{}: {failures} 条 xfrm 规则安装失败", err::IPSEC_IK_INVALID));
    }
    Ok(())
}

async fn cleanup_ipsec(session: &Session) {
    let Some(ctx) = session.ipsec.clone() else {
        return;
    };
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(commands) = ipsec::install_seamless(&ctx, Some(&ctx)) {
            // install_seamless(prev=self) 会生成 4 条 state del + 4 条 policy del。
            for argv in commands.iter().filter(|a| a.contains(&"del".to_string())) {
                let _ = std::process::Command::new(&argv[0]).args(&argv[1..]).output();
            }
        }
    })
    .await;
}

// ---------------------------------------------------------------------------
// 常驻收包
// ---------------------------------------------------------------------------

async fn serve(
    shared: Arc<Shared>,
    session: Arc<Session>,
    cfg: &RuntimeConfig,
    commands: &mut mpsc::Receiver<Command>,
) -> ServeOutcome {
    let refresh_at = tokio::time::Instant::now() + Duration::from_secs(cfg.refresh_secs.max(120));
    let refresh = tokio::time::sleep_until(refresh_at);
    tokio::pin!(refresh);
    let mut cli_buf = vec![0u8; 65536];
    let mut srv_buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            _ = &mut refresh => return ServeOutcome::Refresh,
            command = commands.recv() => match command {
                None | Some(Command::Stop) => return ServeOutcome::Stop,
                Some(Command::Refresh) => return ServeOutcome::Refresh,
                Some(Command::Send { phone, text, reply }) => {
                    if !cfg.sms_enabled {
                        let _ = reply.send(SendOutcome::fail("IMS 短信已关闭"));
                        continue;
                    }
                    let shared = Arc::clone(&shared);
                    let session = Arc::clone(&session);
                    tokio::spawn(async move {
                        let outcome = send_sms(shared, session, phone, text).await;
                        let _ = reply.send(outcome);
                    });
                }
            },
            result = session.cli.recv_from(&mut cli_buf) => {
                match result {
                    Ok((len, peer)) => {
                        handle_datagram(&shared, &session, &cli_buf[..len], peer, true).await;
                    }
                    Err(error) => {
                        return ServeOutcome::Failed(format!("cli socket: {error}"));
                    }
                }
            }
            result = session.srv.recv_from(&mut srv_buf) => {
                match result {
                    Ok((len, peer)) => {
                        handle_datagram(&shared, &session, &srv_buf[..len], peer, false).await;
                    }
                    Err(error) => {
                        return ServeOutcome::Failed(format!("srv socket: {error}"));
                    }
                }
            }
        }
    }
}

async fn handle_datagram(
    shared: &Arc<Shared>,
    session: &Arc<Session>,
    raw: &[u8],
    peer: SocketAddr,
    from_cli: bool,
) {
    let text = String::from_utf8_lossy(raw);
    let first_line = text.lines().next().unwrap_or("").to_string();

    if first_line.starts_with("SIP/2.0") {
        handle_response(shared, session, raw).await;
        return;
    }
    if !first_line.starts_with("MESSAGE ") {
        // OPTIONS / NOTIFY 等：一律 200 OK。
        let _ = reply_ok(session, raw, from_cli, peer).await;
        return;
    }

    let body = split_body(raw);
    let rp_type = RpType::from_octet(body.first().copied().unwrap_or(0));

    // 先回 200 OK（空体），再按 RP 类型处理。
    let _ = reply_ok(session, raw, from_cli, peer).await;

    match rp_type {
        Some(RpType::DataNetwork) => {
            let Ok(rp) = sms::decode_rp_data(body) else {
                return;
            };
            let Ok(deliver) = sms::decode_sms_deliver(&rp.tpdu) else {
                return;
            };
            let outcome = shared.multipart.offer(&deliver);
            let (sender, content) = match outcome {
                Ok(MultipartOutcome::Complete { sender, text }) => (sender, text),
                Ok(MultipartOutcome::Buffered { .. }) => {
                    let _ = send_rp_ack(session, raw, rp.reference).await;
                    return;
                }
                Err(_) => return,
            };
            // MT 确认：单独一条带 RP-ACK 体的 MESSAGE。
            let _ = send_rp_ack(session, raw, rp.reference).await;

            let timestamp = scts_to_local_string(&deliver.scts);
            let marker = sms::duplicate_key(&sender, &deliver.scts, &content);
            let marker = format!("ims:{}", md5_hex(marker.as_bytes()));

            {
                let mut seen = shared.seen.lock().await;
                seen.retain(|_, at| at.elapsed() < Duration::from_secs(600));
                if seen.contains_key(&marker) {
                    shared
                        .set_status(|s| s.duplicate_count = s.duplicate_count.saturating_add(1))
                        .await;
                    return;
                }
                seen.insert(marker.clone(), Instant::now());
            }

            shared
                .set_status(|s| {
                    s.last_rx_at = Some(now_unix());
                    s.received_count = s.received_count.saturating_add(1);
                })
                .await;

            let _ = shared
                .incoming
                .send(IncomingSms {
                    sender,
                    text: content,
                    timestamp,
                    marker,
                })
                .await;
        }
        Some(RpType::AckNetwork) | Some(RpType::AckMs) => {
            let reference = body.get(1).copied().unwrap_or(0);
            let mut pending = shared.pending.lock().await;
            for entry in pending.values_mut() {
                if entry.reference == reference {
                    entry.rp_ack = true;
                    entry.complete_if_ready();
                }
            }
        }
        Some(RpType::ErrorNetwork) | Some(RpType::ErrorMs) => {
            let reference = body.get(1).copied().unwrap_or(0);
            let mut pending = shared.pending.lock().await;
            for entry in pending.values_mut() {
                if entry.reference == reference {
                    entry.error = Some("RP-ERROR".to_string());
                    entry.complete_if_ready();
                }
            }
        }
        _ => {}
    }
}

async fn handle_response(shared: &Arc<Shared>, _session: &Arc<Session>, raw: &[u8]) {
    let Ok(response) = sip::parse_response(raw) else {
        return;
    };
    let Some(call_id) = response.header("Call-ID") else {
        return;
    };
    let call_id = call_id.to_string();
    let mut pending = shared.pending.lock().await;
    if let Some(entry) = pending.get_mut(&call_id) {
        entry.status = Some(format!("{} {}", response.status, response.reason));
        if (200..300).contains(&response.status) {
            entry.sip_accepted = true;
        } else if response.status >= 300 {
            entry.error = Some(format!(
                "SIP {} {}",
                response.status, response.reason
            ));
        }
        entry.complete_if_ready();
    }
}

async fn reply_ok(
    session: &Arc<Session>,
    raw: &[u8],
    from_cli: bool,
    peer: SocketAddr,
) -> Result<(), String> {
    let head = Head::parse(raw);
    let mut out = String::from("SIP/2.0 200 OK\r\n");
    for via in head.all("Via") {
        out.push_str(&format!("Via: {via}\r\n"));
    }
    let from = head.header("From").unwrap_or("");
    let to = head.header("To").unwrap_or("");
    let call_id = head.header("Call-ID").unwrap_or("");
    let cseq = head.header("CSeq").unwrap_or("");
    out.push_str(&format!("From: {from}\r\n"));
    if to.to_ascii_lowercase().contains("tag=") {
        out.push_str(&format!("To: {to}\r\n"));
    } else {
        out.push_str(&format!("To: {to};tag={:08x}\r\n", random_u32_local()));
    }
    out.push_str(&format!("Call-ID: {call_id}\r\n"));
    out.push_str(&format!("CSeq: {cseq}\r\n"));
    out.push_str(&format!(
        "Contact: <sip:{}:{}>\r\n",
        session.contact_host(),
        session.bearer_port_s()
    ));
    out.push_str("Content-Length: 0\r\n\r\n");

    // 回给 Via 的地址（RFC 3581 rport）。端口决定走哪条关联。
    let destination = via_target(&head.text).unwrap_or(peer);
    let socket = if from_cli || destination.port() == session.pc_prot.port() {
        &session.cli
    } else {
        &session.srv
    };
    socket
        .send_to(out.as_bytes(), destination)
        .await
        .map(|_| ())
        .map_err(|e| format!("sip 200: {e}"))
}

async fn send_rp_ack(session: &Arc<Session>, raw: &[u8], reference: u8) -> Result<(), String> {
    let head = Head::parse(raw);
    let from = head.header("From").unwrap_or("");
    let origin = sip_uri(from).ok_or_else(|| "MT 请求缺少 From".to_string())?;
    let orig_call_id = head.header("Call-ID").unwrap_or("").to_string();

    let routes = route_set(session);
    let body = sms::encode_rp_ack(reference);
    let call_id = format!("{:016x}@simadmin", random_u32_local() as u64);
    let (head_text, body_bytes) = sip::build_message(&MessageParams {
        home_domain: &session.identity.home_domain,
        public_identity: &session.impu,
        request_uri: &origin,
        contact_host: &session.contact_host(),
        contact_port: session.bearer_port_s(),
        call_id: &call_id,
        cseq: 1,
        from_tag: &session.from_tag,
        branch: &format!("z9hG4bK{:016x}", random_u32_local()),
        transport: "UDP",
        routes: &routes,
        body: &body,
    });
    let mut packet = head_text.into_bytes();
    if !orig_call_id.is_empty() {
        // 在 CSeq 行后插 In-Reply-To，方便网络侧关联。
        let mut rebuilt = String::new();
        let mut inserted = false;
        for line in String::from_utf8_lossy(&packet).lines() {
            rebuilt.push_str(line);
            rebuilt.push_str("\r\n");
            if !inserted && line.to_ascii_lowercase().starts_with("cseq:") {
                rebuilt.push_str(&format!("In-Reply-To: {orig_call_id}\r\n"));
                inserted = true;
            }
        }
        let mut bytes = rebuilt.into_bytes();
        bytes.extend_from_slice(&body_bytes);
        packet = bytes;
    } else {
        packet.extend_from_slice(&body_bytes);
    }
    session.send_prot(&packet).await
}

// ---------------------------------------------------------------------------
// MO 发送
// ---------------------------------------------------------------------------

async fn send_sms(
    shared: Arc<Shared>,
    session: Arc<Session>,
    phone: String,
    text: String,
) -> SendOutcome {
    let smsc: String = session
        .smsc
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect();
    if smsc.is_empty() {
        return SendOutcome::fail(err::SMSC_MISSING);
    }

    let dcs = sms::choose_dcs(&text);
    let segments = sms::segment_text(&text, dcs);
    let total = segments.len() as u8;
    let concat_ref = (shared.next_u64() & 0xFFFF) as u16;
    let routes = route_set(&session);

    let mut uris: Vec<String> = vec![format!(
        "sip:{}@{};user=phone",
        smsc, session.identity.home_domain
    )];
    uris.extend(sip::recipient_variants(&phone, &session.identity.home_domain));

    let mut reference = (shared.next_u64() & 0xFF) as u8;
    for (index, segment) in segments.iter().enumerate() {
        let concat = (total > 1).then_some(Concat {
            reference: concat_ref,
            total,
            sequence: (index as u8) + 1,
        });
        let tpdu = match sms::encode_sms_submit(reference, &phone, segment, dcs, concat) {
            Ok(tpdu) => tpdu,
            Err(error) => return SendOutcome::fail(error),
        };
        let rpdu = match sms::encode_rp_data_mo(reference, &smsc, &tpdu) {
            Ok(rpdu) => rpdu,
            Err(error) => return SendOutcome::fail(error),
        };

        let mut accepted = false;
        let mut last_error: Option<String> = None;
        for uri in &uris {
            let call_id = format!("{:016x}@simadmin", shared.next_u64());
            let (head, body) = sip::build_message(&MessageParams {
                home_domain: &session.identity.home_domain,
                public_identity: &session.impu,
                request_uri: uri,
                contact_host: &session.contact_host(),
                contact_port: session.bearer_port_s(),
                call_id: &call_id,
                cseq: 1,
                from_tag: &session.from_tag,
                branch: &format!("z9hG4bK{:016x}", shared.next_u64()),
                transport: "UDP",
                routes: &routes,
                body: &rpdu,
            });
            let mut packet = head.into_bytes();
            packet.extend_from_slice(&body);

            let (tx, rx) = oneshot::channel();
            {
                let mut pending = shared.pending.lock().await;
                pending.insert(
                    call_id.clone(),
                    Pending {
                        reference,
                        sip_accepted: false,
                        rp_ack: false,
                        error: None,
                        status: None,
                        done: Some(tx),
                    },
                );
            }
            if let Err(error) = session.send_prot(&packet).await {
                shared.pending.lock().await.remove(&call_id);
                last_error = Some(error);
                continue;
            }
            shared
                .set_status(|s| s.last_tx_at = Some(now_unix()))
                .await;

            match tokio::time::timeout(Duration::from_secs(35), rx).await {
                Ok(Ok(outcome)) => {
                    shared.pending.lock().await.remove(&call_id);
                    if outcome.sent {
                        accepted = true;
                        break;
                    }
                    last_error = outcome.error.clone();
                    if outcome.sip_accepted {
                        // SIP 已接受但 RP-ACK 没来：不再换 URI 重发（可能重复送达）。
                        return SendOutcome {
                            sent: false,
                            sip_accepted: true,
                            rp_ack: false,
                            status: outcome.status,
                            error: Some(err::SMS_DELIVERY_UNKNOWN.to_string()),
                            delivery_unknown: true,
                        };
                    }
                }
                Ok(Err(_)) => {
                    shared.pending.lock().await.remove(&call_id);
                    last_error = Some("发送任务被取消".to_string());
                }
                Err(_) => {
                    shared.pending.lock().await.remove(&call_id);
                    return SendOutcome {
                        sent: false,
                        sip_accepted: false,
                        rp_ack: false,
                        status: None,
                        error: Some(err::SMS_RP_ACK_TIMEOUT.to_string()),
                        delivery_unknown: true,
                    };
                }
            }
        }

        if !accepted {
            return SendOutcome {
                sent: false,
                sip_accepted: false,
                rp_ack: false,
                status: None,
                error: Some(last_error.unwrap_or_else(|| err::REGISTER_REJECTED.to_string())),
                delivery_unknown: false,
            };
        }
        reference = reference.wrapping_add(1);
    }

    shared
        .set_status(|s| s.sent_count = s.sent_count.saturating_add(1))
        .await;
    SendOutcome {
        sent: true,
        sip_accepted: true,
        rp_ack: true,
        status: Some("confirmed".to_string()),
        error: None,
        delivery_unknown: false,
    }
}

fn route_set(session: &Session) -> Vec<String> {
    let mut routes = vec![format!(
        "sip:{}:{};lr",
        session.contact_host(),
        session.pc_prot.port()
    )];
    // P-CSCF 主机地址应取真实地址而不是 UE 地址。
    routes[0] = format!("sip:[{}]:{};lr", session.pcscf, session.pc_prot.port());
    routes.extend(session.service_routes.iter().cloned());
    routes
}

// ---------------------------------------------------------------------------
// 刷新
// ---------------------------------------------------------------------------

async fn refresh(
    shared: &Arc<Shared>,
    cfg: &RuntimeConfig,
    session: &Arc<Session>,
) -> Result<Arc<Session>, String> {
    // 刷新会换 SPI/IK，所以必须复用同一 Session 重新走两轮。
    // Session 用 Arc 共享，这里用内部可变性最小化：重建一个可写副本。
    let mut working = Session {
        identity: session.identity.clone(),
        bearer: session.bearer.clone(),
        pcscf: session.pcscf,
        pc_plain: session.pc_plain,
        pc_prot: session.pc_prot,
        pc_reply_port: session.pc_reply_port,
        cli: Arc::clone(&session.cli),
        srv: Arc::clone(&session.srv),
        mode: session.mode,
        call_id: session.call_id.clone(),
        from_tag: session.from_tag.clone(),
        cseq: session.cseq,
        impu: session.impu.clone(),
        service_routes: session.service_routes.clone(),
        own_number: session.own_number.clone(),
        smsc: session.smsc.clone(),
        ipsec: session.ipsec.clone(),
        sec_client: session.sec_client,
        aka_transport: session.aka_transport,
    };
    shared
        .set_status(|s| s.stage = Stage::RegisterIpsec)
        .await;
    register_rounds(shared, &mut working, session.mode).await?;
    // 刷新会换 SPI/IK，后续收发必须用新上下文，因此返回一份新会话。
    let _ = cfg;
    Ok(Arc::new(working))
}

// ---------------------------------------------------------------------------
// 身份 / SMSC
// ---------------------------------------------------------------------------

/// 读 IMSI 与 USIM AID（阻塞）。
fn read_identity_inputs() -> Result<(String, Vec<u8>), String> {
    // IMSI：AT+CIMI（有 MM 时最稳）→ 裸 QMUX DMS
    let mut imsi = String::new();
    if let Ok(output) = std::process::Command::new("mmcli")
        .args(["-m", "any", "--command=AT+CIMI"])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout).to_string();
            imsi = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .find(|line| line.chars().all(|c| c.is_ascii_digit()) && line.len() >= 6)
                .unwrap_or("")
                .to_string();
        }
    }
    if imsi.is_empty() {
        let mut qmux = super::qmi_raw::Qmux::open()?;
        let dms = qmux.allocate_client(super::qmi_raw::SVC_DMS)?;
        let result = qmux.dms_imsi(dms);
        qmux.release_client(super::qmi_raw::SVC_DMS, dms);
        imsi = result?;
    }
    if imsi.is_empty() {
        return Err(err::IMSI_MISSING.to_string());
    }

    // USIM AID：qmicli 卡状态 → 内置 fallback
    let aid = read_usim_aid().unwrap_or_else(|| identity::FALLBACK_USIM_AID.to_vec());
    Ok((imsi, aid))
}

fn read_usim_aid() -> Option<Vec<u8>> {
    let device = (0..4)
        .map(|i| format!("/dev/cdc-wdm{i}"))
        .find(|path| std::path::Path::new(path).exists())?;
    let output = std::process::Command::new("qmicli")
        .args(["-d", &device, "--device-open-proxy", "--uim-get-card-status"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    identity::parse_usim_aid(&text).ok()
}

async fn resolve_smsc(ident: &ImsIdentity) -> String {
    if !ident.smsc.trim().is_empty() {
        return ident.smsc.trim().to_string();
    }
    let from_at = tokio::task::spawn_blocking(read_smsc_via_at)
        .await
        .ok()
        .flatten();
    if let Some(smsc) = from_at {
        return smsc;
    }
    tokio::task::spawn_blocking(usim::read_ef_smsc)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

fn read_smsc_via_at() -> Option<String> {
    let output = std::process::Command::new("mmcli")
        .args(["-m", "any", "--command=AT+CSCA?"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("+CSCA:") {
            let value = rest.split(',').next().unwrap_or("").trim().trim_matches('"');
            let digits: String = value
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '+')
                .collect();
            if digits.chars().filter(char::is_ascii_digit).count() >= 5 {
                return Some(digits);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

async fn send_and_wait(
    shared: &Arc<Shared>,
    session: &Session,
    packet: Vec<u8>,
    destination: SocketAddr,
    timeout_secs: u64,
) -> Result<sip::Response, String> {
    session
        .cli
        .send_to(&packet, destination)
        .await
        .map_err(|e| format!("sip send: {e}"))?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    // 两条通路各用一份缓冲：`select!` 里同一个 `&mut` 只能借一次。
    let mut cli_buf = vec![0u8; 65536];
    let mut srv_buf = vec![0u8; 65536];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("SIP 响应超时".to_string());
        }
        let received = tokio::time::timeout(remaining, async {
            tokio::select! {
                result = session.cli.recv_from(&mut cli_buf) => Some((result, true)),
                result = session.srv.recv_from(&mut srv_buf) => Some((result, false)),
            }
        })
        .await
        .map_err(|_| "SIP 响应超时".to_string())?;

        let Some((result, from_cli)) = received else {
            continue;
        };
        let Ok((len, peer)) = result else {
            continue;
        };
        let data = if from_cli {
            &cli_buf[..len]
        } else {
            &srv_buf[..len]
        };
        if !data.starts_with(b"SIP/2.0") {
            // 注册期间的 MT/其它请求：顺手应答，别丢。
            let _ = reply_ok(&Arc::new(clone_session(session)), data, from_cli, peer).await;
            continue;
        }
        let response = sip::parse_response(data)?;
        let _ = shared;
        return Ok(response);
    }
}

/// 注册阶段需要临时构造 `Arc<Session>` 来复用 `reply_ok`，这里做浅拷贝。
fn clone_session(session: &Session) -> Session {
    Session {
        identity: session.identity.clone(),
        bearer: session.bearer.clone(),
        pcscf: session.pcscf,
        pc_plain: session.pc_plain,
        pc_prot: session.pc_prot,
        pc_reply_port: session.pc_reply_port,
        cli: Arc::clone(&session.cli),
        srv: Arc::clone(&session.srv),
        mode: session.mode,
        call_id: session.call_id.clone(),
        from_tag: session.from_tag.clone(),
        cseq: session.cseq,
        impu: session.impu.clone(),
        service_routes: session.service_routes.clone(),
        own_number: session.own_number.clone(),
        smsc: session.smsc.clone(),
        ipsec: session.ipsec.clone(),
        sec_client: session.sec_client,
        aka_transport: session.aka_transport,
    }
}


/// 轻量 SIP 头部解析（请求与响应通用；`sip::parse_response` 只吃响应）。
struct Head {
    text: String,
    start: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn parse(raw: &[u8]) -> Self {
        let text = String::from_utf8_lossy(raw).to_string();
        let head_end = text.find("\r\n\r\n").unwrap_or(text.len());
        let head = &text[..head_end];
        let mut lines = head.split("\r\n");
        let start = lines.next().unwrap_or("").to_string();
        let mut headers: Vec<(String, String)> = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                if let Some(last) = headers.last_mut() {
                    last.1.push(' ');
                    last.1.push_str(line.trim());
                }
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }
        Self {
            text: head.to_string(),
            start,
            headers,
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    #[allow(dead_code)]
    fn method(&self) -> &str {
        self.start.split(' ').next().unwrap_or("")
    }
}

fn split_body(raw: &[u8]) -> &[u8] {
    for (index, window) in raw.windows(4).enumerate() {
        if window == b"\r\n\r\n" {
            return &raw[index + 4..];
        }
    }
    for (index, window) in raw.windows(2).enumerate() {
        if window == b"\n\n" {
            return &raw[index + 2..];
        }
    }
    &[]
}

fn via_target(head: &str) -> Option<SocketAddr> {
    for line in head.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.starts_with("via:") {
            continue;
        }
        let value = line.split_once(':')?.1.trim();
        // 取 [addr]:port 或 addr:port
        let start = value.find('[')?;
        let end = value[start..].find(']')? + start;
        let host = &value[start + 1..end];
        let rest = &value[end + 1..];
        let port = rest
            .strip_prefix(':')
            .map(|tail| tail.split(';').next().unwrap_or(""))?;
        // rport=NNNN 优先（RFC 3581）
        let rport = value
            .split(';')
            .find_map(|part| part.trim().strip_prefix("rport="))
            .and_then(|value| value.parse::<u16>().ok());
        let port = rport.or_else(|| port.parse::<u16>().ok())?;
        let addr: Ipv6Addr = host.parse().ok()?;
        return Some(SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0)));
    }
    None
}

fn sip_uri(header_value: &str) -> Option<String> {
    let value = header_value.trim();
    if let (Some(start), Some(end)) = (value.find('<'), value.find('>')) {
        let inner = &value[start + 1..end];
        if inner.starts_with("sip:") || inner.starts_with("tel:") {
            return Some(inner.to_string());
        }
    }
    let value = value.split(';').next().unwrap_or("").trim();
    if value.starts_with("sip:") || value.starts_with("tel:") {
        return Some(value.to_string());
    }
    None
}

/// SCTS（7 个半八位组）→ `YYYY-MM-DD HH:MM:SS`（SMSC 本地时间）。
fn scts_to_local_string(scts: &[u8; 7]) -> String {
    let mut digits = [0u8; 14];
    let mut index = 0usize;
    for byte in scts.iter().take(6) {
        let low = byte & 0x0F;
        let high = (byte >> 4) & 0x0F;
        if index < digits.len() {
            digits[index] = low;
            index += 1;
        }
        if index < digits.len() {
            digits[index] = high;
            index += 1;
        }
    }
    if index < 12 {
        return beijing_now_string();
    }
    let year = 2000 + digits[0] as u32 * 10 + digits[1] as u32;
    let month = digits[2] as u32 * 10 + digits[3] as u32;
    let day = digits[4] as u32 * 10 + digits[5] as u32;
    let hour = digits[6] as u32 * 10 + digits[7] as u32;
    let minute = digits[8] as u32 * 10 + digits[9] as u32;
    let second = digits[10] as u32 * 10 + digits[11] as u32;
    if !(2000..2100).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return beijing_now_string();
    }
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

fn beijing_now_string() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let beijing = now + 8 * 3600;
    let days = beijing / 86400;
    let secs = beijing % 86400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Howard Hinnant 的 civil_from_days。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn md5_hex(data: &[u8]) -> String {
    let digest = md5::compute(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_u32(shared: &Arc<Shared>) -> u32 {
    let mut value = shared.next_u64();
    // xorshift 打散，避免连续编号导致 SPI 相邻。
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    (value >> 16) as u32
}

fn random_u32_local() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9);
    (nanos ^ (std::process::id() as u64) << 16) as u32
}

fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect::<String>()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Session {
    fn bearer_port_c(&self) -> u16 {
        self.sec_client.port_c
    }

    fn bearer_port_s(&self) -> u16 {
        self.sec_client.port_s
    }
}

/// 供 manager 判断 P-CSCF 是否已发现。
#[allow(dead_code)]
pub fn family_of(addr: IpAddr) -> ImsFamily {
    if addr.is_ipv6() {
        ImsFamily::V6
    } else {
        ImsFamily::V4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scts_decodes_to_local_time() {
        // 2026-10-14 17:20:30 → 26/10/41 71:02:03 (semi-octets)
        let scts = [0x62, 0x01, 0x41, 0x71, 0x02, 0x03, 0x32];
        assert_eq!(scts_to_local_string(&scts), "2026-10-14 17:20:30");
    }

    #[test]
    fn scts_falls_back_on_garbage() {
        let scts = [0xFF; 7];
        let value = scts_to_local_string(&scts);
        assert_eq!(value.len(), 19);
    }

    #[test]
    fn beijing_now_is_formatted() {
        let value = beijing_now_string();
        assert_eq!(value.len(), 19);
        assert!(value.starts_with("20"));
    }

    #[test]
    fn via_target_prefers_rport() {
        let head = "MESSAGE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP [2408::1]:9999;branch=z9hG4bK;rport=1234\r\n";
        let addr = via_target(head).unwrap();
        assert_eq!(addr.port(), 1234);
    }

    #[test]
    fn sip_uri_extracts_angle_brackets() {
        assert_eq!(
            sip_uri("<sip:+8613800000000@ims.mnc001.mcc460.3gppnetwork.org>;tag=abc").as_deref(),
            Some("sip:+8613800000000@ims.mnc001.mcc460.3gppnetwork.org")
        );
    }

    #[test]
    fn head_and_body_split() {
        let raw = b"MESSAGE sip:x SIP/2.0\r\nCall-ID: c\r\n\r\n\x01\x02";
        assert_eq!(split_body(raw), &[0x01, 0x02]);
        let head = Head::parse(raw);
        assert_eq!(head.method(), "MESSAGE");
        assert_eq!(head.header("call-id"), Some("c"));
    }
}
