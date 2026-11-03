//! SIP over UDP 的最小传输层。
//!
//! 只做三件事：绑到承载地址、发一个请求、按 CSeq 收回本次事务的响应。
//! 没有引现成 SIP 栈，因为这里只需要 REGISTER / MESSAGE 两种事务，
//! 而完整栈会把 IPsec 传输层、NAT 探测、DNS 发现一起带进来，
//! 反而更难对齐运营商的实际行为。

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::volte::sip::{parse_response, SipResponse};
use crate::volte::{codes, VolteError};

/// 绑定在 IMS 承载地址上的 UDP 套接字。
pub struct SipTransport {
    socket: UdpSocket,
    local_ip: String,
    local_port: u16,
}

impl SipTransport {
    /// 绑定到指定地址。
    ///
    /// `port` 为 0 时由内核挑端口；端口被占用时也会退回临时端口——
    /// 首次 REGISTER 用哪个端口无所谓，最终端口由 Security-Server 的
    /// `port-c` 决定，之后会重新绑定。
    pub async fn bind(local_ip: &str, port: u16) -> Result<Self, VolteError> {
        let addr = socket_addr(local_ip, port)?;
        let socket = match UdpSocket::bind(addr).await {
            Ok(s) => s,
            Err(first) => {
                let fallback = socket_addr(local_ip, 0)?;
                UdpSocket::bind(fallback).await.map_err(|e| {
                    VolteError::with_detail(
                        codes::UDP_RECV_TIMEOUT,
                        format!("bind [{local_ip}]:{port} -> {first}; fallback -> {e}"),
                    )
                })?
            }
        };
        let local_port = socket
            .local_addr()
            .map_err(|e| VolteError::with_detail(codes::UDP_RECV_TIMEOUT, format!("local_addr: {e}")))?
            .port();
        Ok(Self {
            socket,
            local_ip: local_ip.to_string(),
            local_port,
        })
    }

    pub fn local_ip(&self) -> &str {
        &self.local_ip
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// 发一个请求并等响应。
    ///
    /// 只接受 CSeq 匹配的响应——同一个套接字上可能先到上一次尝试的迟到
    /// 响应（例如 401 的重传），按 CSeq 过滤可以避免把旧响应当成本次的。
    pub async fn exchange(
        &self,
        target: &str,
        port: u16,
        payload: &str,
        cseq: u32,
        timeout: Duration,
    ) -> Result<SipResponse, VolteError> {
        let dest = socket_addr(target, port)?;
        self.socket.send_to(payload.as_bytes(), dest).await.map_err(|e| {
            VolteError::with_detail(
                codes::UDP_RECV_TIMEOUT,
                format!("send -> [{target}]:{port}: {e}"),
            )
        })?;

        let deadline = tokio::time::Instant::now() + timeout;
        let mut buf = vec![0u8; 8192];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(VolteError::with_detail(
                    codes::UDP_RECV_TIMEOUT,
                    format!("no SIP response from [{target}]:{port}"),
                ));
            }
            let received = match tokio::time::timeout(remaining, self.socket.recv_from(&mut buf)).await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    return Err(VolteError::with_detail(
                        codes::UDP_RECV_TIMEOUT,
                        format!("recv: {e}"),
                    ))
                }
                Err(_) => {
                    return Err(VolteError::with_detail(
                        codes::UDP_RECV_TIMEOUT,
                        format!("no SIP response from [{target}]:{port}"),
                    ))
                }
            };
            let (n, from) = received;
            let text = String::from_utf8_lossy(&buf[..n]).to_string();
            let Some(resp) = parse_response(&text) else {
                continue;
            };
            if let Some(value) = resp.header("cseq") {
                let first = value.split_whitespace().next().unwrap_or_default();
                if first != cseq.to_string() {
                    // 迟到响应，继续等本次事务
                    continue;
                }
            }
            tracing::debug!(
                from = %from,
                status = resp.status,
                "SIP response"
            );
            return Ok(resp);
        }
    }

    /// 只发不收，用于注册成功后的保活场景。
    pub async fn send(&self, target: &str, port: u16, payload: &str) -> Result<(), VolteError> {
        let dest = socket_addr(target, port)?;
        self.socket
            .send_to(payload.as_bytes(), dest)
            .await
            .map(|_| ())
            .map_err(|e| {
                VolteError::with_detail(
                    codes::UDP_RECV_TIMEOUT,
                    format!("send -> [{target}]:{port}: {e}"),
                )
            })
    }
}

/// 把裸 IPv6 地址拼成 `SocketAddr`，顺带做括号与字面量校验。
fn socket_addr(ip: &str, port: u16) -> Result<SocketAddr, VolteError> {
    let trimmed = ip.trim().trim_start_matches('[').trim_end_matches(']');
    format!("[{trimmed}]:{port}").parse().map_err(|e| {
        VolteError::with_detail(
            codes::PCSCF_MISSING,
            format!("invalid address {ip}: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_addr_accepts_bare_and_bracketed_ipv6() {
        let a = socket_addr("2408:8142:6001:603::", 5060).unwrap();
        let b = socket_addr("[2408:8142:6001:603::]", 5060).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.port(), 5060);
    }

    #[test]
    fn socket_addr_rejects_garbage() {
        assert!(socket_addr("not-an-ip", 5060).is_err());
    }
}
