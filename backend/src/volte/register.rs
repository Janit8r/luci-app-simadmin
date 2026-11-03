//! IMS 注册流程：明文 REGISTER → 401 → AKA → IPsec → 认证 REGISTER。
//!
//! 这一层只做编排，具体的报文构造、AKA 计算、xfrm 命令生成都在各自模块里，
//! 便于单独测试。流程上严格按 TS 24.229 的初始注册走：
//!
//! 1. 不带 Authorization 的 REGISTER，同时带 `Security-Client` 声明本端 IPsec 能力
//! 2. 收到 401，从 `WWW-Authenticate` 取 nonce，从 `Security-Server` 取对端 SPI/端口
//! 3. nonce 拆出 RAND/AUTN，交给 USIM 做 AKA，得到 RES/CK/IK
//! 4. 用 CK||IK 装 4 组 xfrm SA（实际只需要 client 侧两向）
//! 5. 带 `Authorization` + `Security-Verify` 重发 REGISTER，这次走加密通道
//! 6. 收到 200 OK 即注册成功

use std::path::PathBuf;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::volte::aka::{build_authorization, build_digest_response, parse_challenge_nonce, AkaOutcome};
use crate::volte::bearer::ImsBearer;
use crate::volte::identity::ImsIdentity;
use crate::volte::ipsec::{self, SaSpec};
use crate::volte::sip::{self, IpsecMechanism, RegisterContext};
use crate::volte::transport::SipTransport;
use crate::volte::{codes, VolteError};

/// P-Access-Network-Info 里的接入技术描述。
///
/// E-UTRAN-FDD 是中国联通 LTE 的实际接入类型；cell id 用全 0 占位，
/// 网络侧不校验这个字段，但缺了会被某些 P-CSCF 直接 400。
const ACCESS_INFO: &str = "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=00000000";

/// 首次 REGISTER 的等待时间。真机上 P-CSCF 通常 100ms 内就回 401，
/// 给到 6 秒是为了容忍跨网绕路与重传。
const REGISTER_TIMEOUT: Duration = Duration::from_secs(6);
/// 加密 REGISTER 的等待时间，IPsec 建链后首包可能触发一次额外的 IKE-less 重传。
const SECURE_REGISTER_TIMEOUT: Duration = Duration::from_secs(10);

/// 注册成功后需要长期持有的上下文。
pub struct Registration {
    pub pcscf: String,
    pub transport: SipTransport,
    /// 已安装的 SA，用于注销时清理
    pub sas: Vec<SaSpec>,
    /// 注册时协商出的 P-CSCF 服务端口
    pub pcscf_port_s: u16,
    /// 本端客户端端口
    pub ue_port_c: u16,
}

/// 依次尝试候选 P-CSCF，第一个能回 401 的即为可用节点。
pub async fn register(
    identity: &ImsIdentity,
    bearer: &ImsBearer,
    candidates: &[String],
) -> Result<Registration, VolteError> {
    if candidates.is_empty() {
        return Err(VolteError::new(codes::PCSCF_MISSING));
    }
    let impus = impu_variants(identity).await;
    let mut last: Option<VolteError> = None;

    for candidate in candidates {
        let mut responded = false;
        for impu in &impus {
            match try_register(identity, bearer, candidate, impu).await {
                Ok(reg) => return Ok(reg),
                Err(e) => {
                    // 只有超时才说明这个 P-CSCF 不通；其它错误说明网络已应答，
                    // 换 P-CSCF 没有意义，直接在同一个节点上换 IMPU 重试。
                    if e.code != codes::UDP_RECV_TIMEOUT {
                        responded = true;
                    }
                    warn!(pcscf = %candidate, impu = %impu, reason = %e, "registration attempt failed");
                    last = Some(e);
                }
            }
        }
        if responded {
            break;
        }
    }
    Err(last.unwrap_or_else(|| VolteError::new(codes::PCSCF_MISSING)))
}

/// 公有身份的候选列表。
///
/// 中国联通的 IMS 核心对 IMSI 形式的 IMPU 会直接回
/// `403 Forbidden` + `Warning: "Authentication Failure"`，
/// 必须用 MSISDN 形式。号码从模组的 `OwnNumbers` 读，读不到就退回 IMSI。
async fn impu_variants(identity: &ImsIdentity) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(number) = read_own_number().await {
        let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            out.push(format!("sip:{}@{}", digits, identity.home_domain));
            out.push(format!("sip:+{}@{}", digits, identity.home_domain));
        }
    }
    out.push(identity.public_identity.clone());
    out.dedup();
    out
}

/// 从 `mmcli -m any` 的 `Numbers | own: <号码>` 行取本机号。
async fn read_own_number() -> Option<String> {
    let output = tokio::process::Command::new("mmcli")
        .args(["-m", "any"])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let Some((_, right)) = line.split_once(':') else {
            continue;
        };
        if line.to_ascii_lowercase().contains("own") {
            let value = right.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

async fn try_register(
    identity: &ImsIdentity,
    bearer: &ImsBearer,
    pcscf: &str,
    impu: &str,
) -> Result<Registration, VolteError> {
    let call_id = format!("{}@{}", random_hex(12)?, bearer.address);
    let uri = format!("sip:{}", identity.home_domain);

    // ---- 第一步：明文 REGISTER，声明 Security-Client ----
    //
    // port-c 与 port-s 必须是两个不同的端口（TS 33.203 的四组 SA 需要区分
    // 客户端方向与服务端方向）。两者相同会让 P-CSCF 建出互相冲突的 SA，
    // 表现为加密 REGISTER 被静默丢弃。
    let port_c: u16 = std::env::var("SIMADMIN_VOLTE_PORT_C")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5062);
    let port_s: u16 = std::env::var("SIMADMIN_VOLTE_PORT_S")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5064);
    let transport = SipTransport::bind(&bearer.address, port_c).await?;
    let proposal = IpsecMechanism {
        alg: "hmac-md5-96".into(),
        ealg: "null".into(),
        prot: "esp".into(),
        mode: "trans".into(),
        spi_c: random_u32()?,
        spi_s: random_u32()?,
        port_c: transport.local_port(),
        port_s,
    };
    debug!(
        pcscf = %pcscf,
        local_port = transport.local_port(),
        spi_c = proposal.spi_c,
        "sending initial REGISTER"
    );

    // 首个 REGISTER 必须带一个"空"的 AKA Authorization。
    //
    // 中国联通的 S-CSCF 对不带 Authorization 的 REGISTER 直接回
    // `403 Forbidden` + `Warning: "Authentication Failure"`，不会下发挑战。
    // 带上 username=IMPI、nonce=""、response="" 的空头，才会正常回 401
    // 并给出 nonce 与 Security-Server。官方二进制也是这么做的。
    let empty_auth = format!(
        "Digest username=\"{}@{}\",realm=\"{}\",nonce=\"\",uri=\"sip:{}\",response=\"\",algorithm=AKAv1-MD5",
        identity.imsi, identity.home_domain, identity.home_domain, identity.home_domain
    );
    let challenge = build_register(
        identity,
        bearer,
        pcscf,
        impu,
        &call_id,
        1,
        transport.local_port(),
        Some(&empty_auth),
        Some(&proposal),
        None,
    );
    let response = transport
        .exchange(pcscf, 5060, &challenge, 1, REGISTER_TIMEOUT)
        .await?;

    if response.is_success() {
        // 极少数网络允许无鉴权注册（测试网），直接当成功处理
        info!(pcscf = %pcscf, "REGISTER accepted without authentication");
        return Ok(Registration {
            pcscf: pcscf.to_string(),
            transport,
            sas: Vec::new(),
            pcscf_port_s: 5060,
            ue_port_c: 0,
        });
    }
    if response.status != 401 {
        return Err(VolteError::with_detail(
            codes::REGISTER_REJECTED,
            format!("status {} from {pcscf}", response.status),
        ));
    }

    let www = response
        .header("www-authenticate")
        .ok_or_else(|| {
            VolteError::with_detail(codes::REGISTER_AUTH_FAILED, "401 without WWW-Authenticate")
        })?
        .to_string();
    let digest = sip::parse_digest_challenge(&www);
    let nonce = digest
        .get("nonce")
        .cloned()
        .ok_or_else(|| VolteError::with_detail(codes::REGISTER_AUTH_FAILED, "no nonce in challenge"))?;
    let realm = digest
        .get("realm")
        .cloned()
        .unwrap_or_else(|| identity.home_domain.clone());
    let algorithm = digest
        .get("algorithm")
        .cloned()
        .unwrap_or_else(|| "AKAv1-MD5".to_string());

    // ---- 第二步：AKA ----
    let aka_challenge = parse_challenge_nonce(&nonce)?;
    let aka = usim_authenticate(&aka_challenge.rand, &aka_challenge.autn).await?;
    if aka.res.is_empty() {
        return Err(VolteError::with_detail(
            codes::IPSEC_AKA_EMPTY,
            if aka.auts.is_some() { "sync failure" } else { "empty RES" },
        ));
    }
    debug!(res_len = aka.res.len(), ck_len = aka.ck.len(), "USIM AKA completed");

    // ---- 第三步：IPsec ----
    let server_mech = response
        .header("security-server")
        .and_then(sip::parse_security_server);
    // TS 33.203 规定 IPsec 密钥为 CK||IK。个别实现对完整性只用 IK，
    // 留一个开关便于对端行为不同时切换。
    let key_mode = std::env::var("SIMADMIN_VOLTE_IPSEC_KEY").unwrap_or_else(|_| "ckik".into());
    let key = if key_mode.eq_ignore_ascii_case("ik") {
        aka.ik.clone()
    } else if key_mode.eq_ignore_ascii_case("ikck") {
        let mut k = Vec::with_capacity(32);
        k.extend_from_slice(&aka.ik);
        k.extend_from_slice(&aka.ck);
        k
    } else {
        ipsec::derive_ipsec_key(&aka.ck, &aka.ik)
    };

    let (transport, sas, pcscf_port_s, effective) = match server_mech {
        Some(mech) => {
            // 端口与 SPI 用「本端提议值」还是「对端 Security-Server 值」。
            //
            // P-CSCF 是按**我们 Security-Client 里提议的** port-c / spi-c 建它的
            // 入向 SA 的。如果第二次 REGISTER 改用 Security-Server 里的
            // port-c(=9950) 和 spi-c 发出去，源端口与 SPI 都和 P-CSCF 手里的 SA
            // 对不上，ESP 会被静默丢弃——抓包表现为只有 Out 没有 In。
            //
            // 所以默认走 client 模式：沿用本端提议的端口与 SPI。
            // 保留 server 模式（用对端值）以便对端行为不同时切换。
            // SPI 来源与端口来源可以独立选择，四种组合都能试：
            //   client/client —— 全用本端提议值
            //   server/server —— 全用 Security-Server 值
            //   server/client —— 用对端 SPI + 本端端口（RFC 3329 的字面读法）
            //   client/server —— 用本端 SPI + 对端端口
            let legacy = std::env::var("SIMADMIN_VOLTE_IPSEC_MODE")
                .unwrap_or_else(|_| "client".to_string());
            let spi_mode = std::env::var("SIMADMIN_VOLTE_IPSEC_SPI")
                .unwrap_or_else(|_| legacy.clone());
            let port_mode = std::env::var("SIMADMIN_VOLTE_IPSEC_PORT")
                .unwrap_or_else(|_| legacy.clone());
            let spi_server = spi_mode.eq_ignore_ascii_case("server");
            // swapped: 出向用对端 spi-s、入向用对端 spi-c（SPI 命名若以对端视角命名）
            let spi_swapped = spi_mode.eq_ignore_ascii_case("swapped");
            let port_server = port_mode.eq_ignore_ascii_case("server");

            // 受保护 REGISTER 的目标端口与本地源端口都允许覆盖：
            // 不同 P-CSCF 实现对接收入向 SA 的端口约定不一致。
            let pcscf_port_s = std::env::var("SIMADMIN_VOLTE_PROTECTED_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(if mech.port_s == 0 { 5060 } else { mech.port_s });
            let local_port = std::env::var("SIMADMIN_VOLTE_PROTECTED_LOCAL_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(if port_server && mech.port_c != 0 {
                    mech.port_c
                } else {
                    transport.local_port()
                });
            let out_spi = if spi_server && mech.spi_c != 0 {
                mech.spi_c
            } else if spi_swapped && mech.spi_s != 0 {
                mech.spi_s
            } else {
                proposal.spi_c
            };
            let in_spi = if spi_server && mech.spi_s != 0 {
                mech.spi_s
            } else if spi_swapped && mech.spi_c != 0 {
                mech.spi_c
            } else {
                proposal.spi_s
            };

            let transport = if local_port != transport.local_port() {
                SipTransport::bind(&bearer.address, local_port).await?
            } else {
                transport
            };

            let out_spec = SaSpec {
                local_ip: bearer.address.clone(),
                remote_ip: pcscf.to_string(),
                local_port: transport.local_port(),
                remote_port: pcscf_port_s,
                local_spi: out_spi,
                remote_spi: in_spi,
                key: key.clone(),
            };
            let in_spec = SaSpec {
                local_ip: bearer.address.clone(),
                remote_ip: pcscf.to_string(),
                local_port: transport.local_port(),
                remote_port: pcscf_port_s,
                local_spi: in_spi,
                remote_spi: out_spi,
                key: key.clone(),
            };
            install_sa_pair(&out_spec, &in_spec, bearer.family.ip_flag()).await?;
            info!(
                spi_mode = %spi_mode,
                port_mode = %port_mode,
                out_spi = format!("0x{out_spi:x}"),
                in_spi = format!("0x{in_spi:x}"),
                local_port = transport.local_port(),
                pcscf_port_s,
                server_spi_c = format!("0x{:x}", mech.spi_c),
                server_spi_s = format!("0x{:x}", mech.spi_s),
                "IPsec SA installed"
            );

            // Security-Client 必须保持与首个 REGISTER 完全一致（RFC 3329），
            // 协商结果只放在 Security-Verify 里。改成对端值会让 P-CSCF 认为
            // 提议变了，直接丢弃。
            let effective = IpsecMechanism {
                port_c: transport.local_port(),
                ..proposal.clone()
            };
            (transport, vec![out_spec, in_spec], pcscf_port_s, effective)
        }
        None => {
            warn!("no Security-Server in 401; continuing without IPsec");
            (transport, Vec::new(), 5060, proposal.clone())
        }
    };

    // ---- 第四步：认证 REGISTER ----
    //
    // username 必须是 IMPI（IMSI@归属域），不是裸 IMSI。
    // 它参与 HA1 计算，写错会让 S-CSCF 算出不同的 digest 直接判鉴权失败。
    let impi = format!("{}@{}", identity.imsi, identity.home_domain);
    let digest_response = build_digest_response(
        &impi,
        &realm,
        &aka.res,
        &nonce,
        &uri,
        "REGISTER",
    );
    let authorization = build_authorization(
        &impi,
        &realm,
        &nonce,
        &uri,
        &digest_response,
        &algorithm,
        aka.auts.as_deref(),
    );
    let security_verify = response
        .header("security-server")
        .map(|v| v.to_string());

    let secure = build_register(
        identity,
        bearer,
        pcscf,
        impu,
        &call_id,
        2,
        transport.local_port(),
        Some(&authorization),
        Some(&effective),
        security_verify.as_deref(),
    );
    info!(len = secure.len(), mtu = ?bearer.mtu, "authenticated REGISTER size");
    // 落盘一份明文，便于和抓到的 ESP 对照排查
    let _ = tokio::fs::write("/tmp/volte_register_last.txt", secure.as_bytes()).await;
    let final_response = transport
        .exchange(pcscf, pcscf_port_s, &secure, 2, SECURE_REGISTER_TIMEOUT)
        .await?;

    if final_response.is_success() {
        info!(pcscf = %pcscf, status = final_response.status, "IMS registration succeeded");
        Ok(Registration {
            pcscf: pcscf.to_string(),
            transport,
            sas,
            pcscf_port_s,
            ue_port_c: 0,
        })
    } else {
        Err(VolteError::with_detail(
            codes::REGISTER_REJECTED,
            format!("authenticated REGISTER returned {}", final_response.status),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn build_register(
    identity: &ImsIdentity,
    bearer: &ImsBearer,
    pcscf: &str,
    impu: &str,
    call_id: &str,
    cseq: u32,
    local_port: u16,
    authorization: Option<&str>,
    security_client: Option<&IpsecMechanism>,
    security_verify: Option<&str>,
) -> String {
    let ctx = RegisterContext {
        home_domain: &identity.home_domain,
        impu,
        local_ip: &bearer.address,
        local_port,
        pcscf,
        call_id,
        cseq,
        authorization: authorization.map(|s| s.to_string()),
        security_client: security_client.map(sip::render_security_client),
        security_verify: security_verify.map(|s| s.to_string()),
        access_info: ACCESS_INFO,
    };
    sip::build_register(&ctx)
}

/// 安装出/入向 SA 与配套策略。
///
/// 顺序很重要：先装 state 再装 policy，否则策略生效瞬间找不到 SA，
/// 首个报文会被丢弃并留下 `XfrmOutNoStates` 计数。
async fn install_sa_pair(out: &SaSpec, inb: &SaSpec, family: &str) -> Result<(), VolteError> {
    // 先清掉上一轮遗留的 SA 与策略。
    //
    // 不清的话第二次注册会直接 `RTNETLINK answers: File exists`——
    // 而注册本来就要重试好几次，不清理等于只能成功一次。
    let _ = run_command(&[
        "ip".into(),
        family.into(),
        "xfrm".into(),
        "state".into(),
        "flush".into(),
    ])
    .await;
    let _ = run_command(&[
        "ip".into(),
        family.into(),
        "xfrm".into(),
        "policy".into(),
        "flush".into(),
    ])
    .await;

    let commands = vec![
        ipsec::build_state_out(out, family),
        ipsec::build_state_in(inb, family),
        ipsec::build_policy_out(out, family),
        ipsec::build_policy_in(inb, family),
    ];
    for cmd in commands {
        run_command(&cmd).await?;
    }
    Ok(())
}

async fn run_command(cmd: &[String]) -> Result<(), VolteError> {
    let output = tokio::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| {
            VolteError::with_detail(codes::IPSEC_INSTALL_FAILED, format!("{}: {e}", cmd.join(" ")))
        })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(VolteError::with_detail(
        codes::IPSEC_INSTALL_FAILED,
        format!("{} -> {stderr}", cmd.join(" ")),
    ))
}

/// 调用 USIM 做 AKA。
///
/// 走 `@qmi-proxy` 抽象套接字（ModemManager 起的代理），比直接读写
/// `/dev/wwan0qmi0` 稳——后者会和 MM 抢设备，实测会把模组写挂。
async fn usim_authenticate(rand: &[u8], autn: &[u8]) -> Result<AkaOutcome, VolteError> {
    // 走 qmicli 的 UIM APDU 接口。
    //
    // 没有用 simadmin-device-runtime 里的 QmiProxyApduTransport：它在这台模组上
    // 解析响应帧时校验 message_id 失败（`invalid QMI frame`），而 qmicli 走同样的
    // qmi-proxy 却能正常工作。厂商自己的 simadmin-data 也是用 qmicli。
    let device = discover_qmi_device();

    // 1. 拿一个不释放的 UIM 客户端——逻辑通道绑定在客户端上，
    //    分多次调用必须复用同一个 client id。
    let out = run_qmicli(&device, &["--uim-get-card-status", "--client-no-release-cid"]).await?;
    let cid = find_after(&out, "CID: '")
        .ok_or_else(|| VolteError::with_detail(codes::REGISTER_AUTH_FAILED, "no uim cid"))?;

    // 2. 打开 USIM 逻辑通道
    let aid = "A0000000871002";
    let open_arg = format!("--uim-open-logical-channel=1,{aid}");
    let cid_arg = format!("--client-cid={cid}");
    let out = run_qmicli(
        &device,
        &[&open_arg, &cid_arg, "--client-no-release-cid"],
    )
    .await?;
    let channel = find_after(&out, "completed: ")
        .ok_or_else(|| VolteError::with_detail(codes::REGISTER_AUTH_FAILED, "open channel failed"))?;

    // 3. 发 AKA APDU（含 61xx / 6Cxx 处理）
    //
    // 数据域是 `10 <RAND> 10 <AUTN>`，两个长度字节都要有，Lc=0x22。
    let mut command = vec![0x01u8, 0x88, 0x00, 0x81, 0x22, 0x10];
    command.extend_from_slice(rand);
    command.push(0x10);
    command.extend_from_slice(autn);
    command.push(0x00);

    let mut body: Vec<u8> = Vec::new();
    let mut status = [0u8, 0u8];
    for _ in 0..4 {
        let response = send_apdu(&device, &cid, &channel, &command).await?;
        if response.len() < 2 {
            return Err(VolteError::with_detail(codes::AKA_MATERIAL_INVALID, "short apdu"));
        }
        let (data, sw) = response.split_at(response.len() - 2);
        body.extend_from_slice(data);
        status = [sw[0], sw[1]];
        match status[0] {
            // 还有数据，用 GET RESPONSE 取回
            0x61 => command = vec![0x01, 0xC0, 0x00, 0x00, status[1]],
            // Le 不对，按卡给的重新发一次
            0x6C => {
                if let Some(last) = command.last_mut() {
                    *last = status[1];
                }
            }
            _ => break,
        }
    }

    // 4. 关闭通道（尽力而为）
    let close_arg = format!("--uim-close-logical-channel=1,{channel}");
    let _ = run_qmicli(&device, &[&close_arg, &cid_arg, "--client-no-release-cid"]).await;

    parse_aka_response(&body)
}

/// 在已打开的逻辑通道上发一条 APDU，返回原始响应字节。
async fn send_apdu(
    device: &str,
    cid: &str,
    channel: &str,
    command: &[u8],
) -> Result<Vec<u8>, VolteError> {
    let hex: String = command.iter().map(|b| format!("{b:02X}")).collect();
    let arg = format!("--uim-send-apdu=1,{channel},{hex}");
    let cid_arg = format!("--client-cid={cid}");
    let out = run_qmicli(device, &[&arg, &cid_arg, "--client-no-release-cid"]).await?;
    let text = find_after(&out, "completed: ")
        .ok_or_else(|| VolteError::with_detail(codes::REGISTER_AUTH_FAILED, "apdu failed"))?;
    parse_hex(&text)
        .ok_or_else(|| VolteError::with_detail(codes::AKA_MATERIAL_INVALID, "bad apdu hex"))
}


/// 解析 USIM AKA 响应。
///
/// 实测格式（联通卡）：
/// ```text
/// DB 08 <RES 8B> <CK 16B> <IK 16B> ...
/// ```
/// 长度字节是 **RES 的长度**，不是 RES+CK+IK 的总和——这一点和部分文档
/// 写的不一致，按总和算会得到 `res_len invalid`。
fn parse_aka_response(bytes: &[u8]) -> Result<AkaOutcome, VolteError> {
    if bytes.len() < 3 {
        return Err(VolteError::with_detail(codes::AKA_MATERIAL_INVALID, "too short"));
    }
    tracing::info!(
        raw = %bytes.iter().map(|b| format!("{b:02X}")).collect::<String>(),
        "USIM AKA response"
    );

    // 同步失败：DC <AUTS_len> <AUTS 14B>
    if bytes[0] == 0xDC {
        let len = bytes[1] as usize;
        let auts = bytes.get(2..2 + len.min(14)).map(|v| v.to_vec());
        return Ok(AkaOutcome {
            res: Vec::new(),
            ck: Vec::new(),
            ik: Vec::new(),
            auts,
        });
    }
    if bytes[0] != 0xDB {
        return Err(VolteError::with_detail(
            codes::AKA_MATERIAL_INVALID,
            format!("unexpected tag {:02X}", bytes[0]),
        ));
    }
    let res_len = bytes[1] as usize;
    let payload = &bytes[2..];
    if res_len == 0 || payload.len() < res_len + 32 {
        return Err(VolteError::with_detail(
            codes::AKA_MATERIAL_INVALID,
            format!("payload {} < {} + 32", payload.len(), res_len),
        ));
    }
    Ok(AkaOutcome {
        res: payload[..res_len].to_vec(),
        ck: payload[res_len..res_len + 16].to_vec(),
        ik: payload[res_len + 16..res_len + 32].to_vec(),
        auts: None,
    })
}

async fn run_qmicli(device: &str, args: &[&str]) -> Result<String, VolteError> {
    let output = tokio::process::Command::new("qmicli")
        .arg("-d")
        .arg(device)
        .arg("-p")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| VolteError::with_detail(codes::COMMAND_FAILED, format!("qmicli: {e}")))?;
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(text)
}

/// 取 `marker` 之后到行尾的内容。
fn find_after(text: &str, marker: &str) -> Option<String> {
    let idx = text.find(marker)? + marker.len();
    let rest = &text[idx..];
    let end = rest.find(['\n', '\r']).unwrap_or(rest.len());
    let value = rest[..end].trim().trim_matches('\'').trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn discover_qmi_device() -> String {
    let mut candidates: Vec<PathBuf> = std::fs::read_dir("/dev")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.starts_with("cdc-wdm") || (name.starts_with("wwan") && name.contains("qmi"))
        })
        .collect();
    candidates.sort();
    candidates
        .into_iter()
        .next()
        .unwrap_or_else(|| PathBuf::from("/dev/cdc-wdm0"))
        .to_string_lossy()
        .to_string()
}

fn random_hex(bytes: usize) -> Result<String, VolteError> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut buf = vec![0u8; bytes];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| VolteError::with_detail(codes::REGISTER_AUTH_FAILED, "rng failure"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn random_u32() -> Result<u32, VolteError> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut buf = [0u8; 4];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| VolteError::with_detail(codes::REGISTER_AUTH_FAILED, "rng failure"))?;
    let v = u32::from_be_bytes(buf);
    // SPI 0 在 xfrm 里非法
    Ok(if v == 0 { 0x1000_0000 } else { v })
}
