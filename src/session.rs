//! Одиночная TURN+DTLS сессия.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use webrtc_dtls::config::Config as DtlsConfig;
use webrtc_dtls::config::ExtendedMasterSecretType;
use webrtc_dtls::conn::DTLSConn;
use webrtc_dtls::cipher_suite::CipherSuiteId;
use webrtc_util::conn::Conn;

use crate::config::TurnParams;
use crate::creds::Credentials;
use crate::dispatcher::{Dispatcher, WorkerSlot};
use crate::stats::Stats;
use crate::stun;

const READ_BUF: usize = 1600;
const WORKER_SEND_BUF: usize = 48;
const CHANNEL_NUM: u16 = 0x4000;

pub async fn run_session(
    tp: &TurnParams,
    peer: SocketAddr,
    dispatcher: &Arc<Dispatcher>,
    local_port: &str,
    use_tcp: bool,
    get_config: bool,
    config_tx: &Option<mpsc::Sender<String>>,
    session_id: usize,
    creds: &Credentials,
    device_id: &str,
    password: &str,
    shutdown: &Arc<AtomicBool>,
    stats: &Arc<Stats>,
) -> Result<(), String> {
    if shutdown.load(Ordering::Relaxed) {
        return Err("shutdown".into());
    }

    // Парсим TURN адрес
    let (url_host, url_port) = parse_host_port(&creds.turn_url)?;
    let turn_host = if tp.host.is_empty() {
        url_host
    } else {
        tp.host.clone()
    };
    let turn_port = if tp.port.is_empty() {
        url_port
    } else {
        tp.port.clone()
    };
    let turn_addr_str = format!("{}:{}", turn_host, turn_port);

    let proto_label = if use_tcp { "TCP" } else { "UDP" };
    log::info!("[СЕССИЯ #{}] TURN {} ({})", session_id, turn_addr_str, proto_label);

    let turn_addr: SocketAddr = tokio::net::lookup_host(&turn_addr_str)
        .await
        .map_err(|e| format!("Resolve TURN: {}", e))?
        .next()
        .ok_or("No address for TURN")?;

    // Абстракция транспорта: TCP или UDP
    let transport: Box<dyn TurnTransport> = if use_tcp {
        let stream = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(turn_addr),
        )
        .await
        .map_err(|_| "TCP connect timeout".to_string())?
        .map_err(|e| format!("TCP connect: {}", e))?;
        stream.set_nodelay(true).ok();
        Box::new(TcpTurnTransport::new(stream))
    } else {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("Bind UDP: {}", e))?;
        sock.connect(turn_addr)
            .await
            .map_err(|e| format!("Connect UDP: {}", e))?;
        Box::new(UdpTurnTransport(sock))
    };

    // === TURN Allocate ===

    // Step 1: Unauth allocate -> get realm/nonce
    let (msg, _) = stun::build_allocate_unauth();
    transport.turn_send(&msg).await?;

    let mut buf = vec![0u8; 4096];
    let n = transport.turn_recv(&mut buf, Duration::from_secs(10)).await?;
    let parsed = stun::parse_stun(&buf[..n])?;

    if parsed.msg_type != stun::ALLOCATE_ERROR {
        return Err(format!("Expected 401, got 0x{:04x}", parsed.msg_type));
    }

    let (realm_opt, nonce_opt) = stun::extract_realm_nonce(&parsed);
    let realm = realm_opt.ok_or("No realm in 401")?;
    let nonce = nonce_opt.ok_or("No nonce in 401")?;

    // Step 2: Auth allocate
    let (msg, _) = stun::build_allocate_auth(&creds.user, &creds.pass, &realm, &nonce);
    transport.turn_send(&msg).await?;

    let n = transport.turn_recv(&mut buf, Duration::from_secs(10)).await?;
    let parsed = stun::parse_stun(&buf[..n])?;

    if parsed.msg_type == stun::ALLOCATE_ERROR {
        if let Some((code, reason)) = stun::extract_error_code(&parsed) {
            if code == 486 {
                return Err(format!("TURN квота: {}", reason));
            }
            if code == 401 {
                return Err(format!("Креды мертвы: {}", reason));
            }
            return Err(format!("Allocate error {}: {}", code, reason));
        }
        return Err("Allocate failed".into());
    }

    if parsed.msg_type != stun::ALLOCATE_SUCCESS {
        return Err(format!("Unexpected: 0x{:04x}", parsed.msg_type));
    }

    let relay_addr =
        stun::extract_xor_relayed_addr(&parsed).ok_or("No relay address")?;

    log::info!("[СЕССИЯ #{}] Relay: {}", session_id, relay_addr);

    // Step 3: Create Permission
    let (msg, _) =
        stun::build_create_permission(peer, &creds.user, &creds.pass, &realm, &nonce);
    transport.turn_send(&msg).await?;

    let n = transport.turn_recv(&mut buf, Duration::from_secs(10)).await?;
    let parsed = stun::parse_stun(&buf[..n])?;
    if parsed.msg_type != stun::CREATE_PERM_SUCCESS {
        return Err(format!("Permission failed: 0x{:04x}", parsed.msg_type));
    }

    // Step 4: Channel Bind
    let (msg, _) = stun::build_channel_bind(
        peer,
        CHANNEL_NUM,
        &creds.user,
        &creds.pass,
        &realm,
        &nonce,
    );
    transport.turn_send(&msg).await?;

    let n = transport.turn_recv(&mut buf, Duration::from_secs(10)).await?;
    let use_channel = match stun::parse_stun(&buf[..n]) {
        Ok(p) => p.msg_type == stun::CHANNEL_BIND_SUCCESS,
        Err(_) => false,
    };

    log::info!(
        "[СЕССИЯ #{}] ChannelBind: {}",
        session_id,
        if use_channel { "OK" } else { "fallback to SendIndication" }
    );

    // === DTLS через TURN relay ===
    let transport = Arc::new(transport);
    let session_shutdown = Arc::new(AtomicBool::new(false));

    // Внутренний UDP pipe для DTLS
    let dtls_local = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("Bind dtls local: {}", e))?,
    );
    let dtls_remote = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("Bind dtls remote: {}", e))?,
    );

    let local_addr = dtls_local.local_addr().map_err(|e| format!("{}", e))?;
    let remote_addr = dtls_remote.local_addr().map_err(|e| format!("{}", e))?;

    dtls_local
        .connect(remote_addr)
        .await
        .map_err(|e| format!("Connect dtls local: {}", e))?;
    dtls_remote
        .connect(local_addr)
        .await
        .map_err(|e| format!("Connect dtls remote: {}", e))?;

    // Для демультиплексирования STUN-ответов -> keepalive
    let (stun_resp_tx, mut stun_resp_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

    let ts1 = transport.clone();
    let dr1 = dtls_remote.clone();
    let ss1 = session_shutdown.clone();
    let relay_reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            if ss1.load(Ordering::Relaxed) {
                return;
            }
            let result = ts1.turn_recv(&mut buf, Duration::from_secs(2)).await;
            match result {
                Ok(n) => {
                    let data = &buf[..n];
                    if let Some((_ch, payload)) = stun::parse_channel_data(data) {
                        let _ = dr1.send(payload).await;
                    } else if let Ok(msg) = stun::parse_stun(data) {
                        if msg.msg_type == stun::DATA_INDICATION {
                            if let Some(payload) = stun::extract_data_from_indication(&msg) {
                                let _ = dr1.send(&payload).await;
                            }
                        } else {
                            // Остальные STUN сообщения (ответы на Refresh, CreatePermission) -> в keepalive
                            let _ = stun_resp_tx.try_send(data.to_vec());
                        }
                    }
                }
                Err(_) => {
                    if ss1.load(Ordering::Relaxed) {
                        return;
                    }
                }
            }
        }
    });

    // Relay: dtls_remote -> TURN transport
    let ts2 = transport.clone();
    let dr2 = dtls_remote.clone();
    let ss2 = session_shutdown.clone();
    let peer_for_relay = peer;
    let relay_writer = tokio::spawn(async move {
        let mut buf = vec![0u8; READ_BUF];
        loop {
            if ss2.load(Ordering::Relaxed) {
                return;
            }
            let result = tokio::time::timeout(Duration::from_secs(2), dr2.recv(&mut buf)).await;
            match result {
                Ok(Ok(n)) => {
                    let data = &buf[..n];
                    let msg = if use_channel {
                        stun::build_channel_data(CHANNEL_NUM, data)
                    } else {
                        stun::build_send_indication(peer_for_relay, data)
                    };
                    let _ = ts2.turn_send(&msg).await;
                }
                Ok(Err(_)) => {
                    if ss2.load(Ordering::Relaxed) {
                        return;
                    }
                }
                Err(_) => {}
            }
        }
    });

    // Keepalive: обновляем TURN allocation, permission, channel bind
    // RFC 5766: allocation ~10min, permission ~5min, channelbind ~10min
    let ts3 = transport.clone();
    let ss3 = session_shutdown.clone();
    let creds_ka = creds.clone();
    let realm_ka = realm.clone();
    let nonce_ka = nonce.clone();
    let keepalive = tokio::spawn(async move {
        let mut tick = 0u64;
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut current_nonce = nonce_ka;
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if ss3.load(Ordering::Relaxed) {
                        return;
                    }
                    tick += 1;

                    // Каждые 30с: Binding Request (базовый keepalive)
                    let (msg, _) = stun::build_binding_request();
                    let _ = ts3.turn_send(&msg).await;

                    // Каждые 120с (2 мин): Permission Refresh (истекает через 5 мин)
                    if tick % 4 == 0 {
                        let (msg, _) = stun::build_create_permission(
                            peer, &creds_ka.user, &creds_ka.pass, &realm_ka, &current_nonce,
                        );
                        let _ = ts3.turn_send(&msg).await;
                    }

                    // Каждые 180с (3 мин): TURN Refresh (продлевает allocation) + ChannelBind
                    if tick % 6 == 0 {
                        let (msg, _) = stun::build_refresh(
                            &creds_ka.user, &creds_ka.pass, &realm_ka, &current_nonce, 600,
                        );
                        let _ = ts3.turn_send(&msg).await;

                        if use_channel {
                            let (msg, _) = stun::build_channel_bind(
                                peer, CHANNEL_NUM,
                                &creds_ka.user, &creds_ka.pass, &realm_ka, &current_nonce,
                            );
                            let _ = ts3.turn_send(&msg).await;
                        }
                    }
                }
                msg_opt = stun_resp_rx.recv() => {
                    if let Some(data) = msg_opt {
                        if let Ok(parsed) = stun::parse_stun(&data) {
                            if let Some((code, _)) = stun::extract_error_code(&parsed) {
                                if code == 438 { // Stale Nonce
                                    if let (_, Some(new_nonce)) = stun::extract_realm_nonce(&parsed) {
                                        current_nonce = new_nonce.clone();
                                        log::info!("[СЕССИЯ] Nonce ротирован TURN сервером (Stale Nonce)");
                                        
                                        // Повторяем Permission Refresh сразу с новым Nonce!
                                        let (msg, _) = stun::build_create_permission(
                                            peer, &creds_ka.user, &creds_ka.pass, &realm_ka, &current_nonce,
                                        );
                                        let _ = ts3.turn_send(&msg).await;
                                    }
                                }
                            }
                        }
                    } else {
                        return; // channel closed
                    }
                }
            }
        }
    });

    // DTLS handshake
    let sni = if tp.sni.is_empty() {
        "example.com".to_string()
    } else {
        tp.sni.clone()
    };

    let dtls_conn = {
        // Оборачиваем dtls_local в Conn для webrtc-dtls
        let udp_conn = Arc::new(UdpConnWrapper(dtls_local.clone()));

        let config = DtlsConfig {
            insecure_skip_verify: true,
            extended_master_secret: ExtendedMasterSecretType::Require,
            cipher_suites: vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
            server_name: sni,
            ..Default::default()
        };

        let dtls_result = tokio::time::timeout(
            Duration::from_secs(30),
            DTLSConn::new(udp_conn, config, true, None),
        )
        .await;

        match dtls_result {
            Ok(Ok(conn)) => {
                log::info!("[СЕССИЯ #{}] DTLS ОК ✓", session_id);
                Arc::new(conn)
            }
            Ok(Err(e)) => {
                session_shutdown.store(true, Ordering::Relaxed);
                relay_reader.abort();
                relay_writer.abort();
                keepalive.abort();
                deallocate(&transport, creds, &realm, &nonce).await;
                return Err(format!("DTLS handshake: {}", e));
            }
            Err(_) => {
                session_shutdown.store(true, Ordering::Relaxed);
                relay_reader.abort();
                relay_writer.abort();
                keepalive.abort();
                deallocate(&transport, creds, &realm, &nonce).await;
                return Err("DTLS timeout".into());
            }
        }
    };

    stats.active_connections.fetch_add(1, Ordering::Relaxed);

    // Запрос конфига
    if get_config {
        if let Some(tx) = config_tx {
            match config_via_dtls(&dtls_conn, local_port, device_id, password).await {
                Ok(Some(conf)) => {
                    let _ = tx.try_send(conf);
                    log::info!("[СЕССИЯ #{}] Конфиг получен", session_id);
                }
                Ok(None) => {}
                Err(e) => {
                    if e.contains("FATAL_AUTH") {
                        stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                        session_shutdown.store(true, Ordering::Relaxed);
                        relay_reader.abort();
                        relay_writer.abort();
                        keepalive.abort();
                        deallocate(&transport, creds, &realm, &nonce).await;
                        return Err(e);
                    }
                    log::warn!("[СЕССИЯ #{}] Ошибка конфига: {}", session_id, e);
                }
            }
        }
    }

    // READY
    match ready_via_dtls(&dtls_conn).await {
        Ok(()) => {
            log::info!("[СЕССИЯ #{}] Активна ✓", session_id);
        }
        Err(e) => {
            stats.active_connections.fetch_sub(1, Ordering::Relaxed);
            session_shutdown.store(true, Ordering::Relaxed);
            relay_reader.abort();
            relay_writer.abort();
            keepalive.abort();
            deallocate(&transport, creds, &realm, &nonce).await;
            return Err(format!("READY: {}", e));
        }
    }

    // Регистрируем в диспетчере
    let (slot_tx, mut slot_rx) = mpsc::channel(WORKER_SEND_BUF);
    let slot = Arc::new(WorkerSlot {
        id: session_id,
        send_tx: slot_tx,
    });
    dispatcher.register(slot.clone()).await;

    // Writer: dispatcher -> DTLS
    let dtls_w = dtls_conn.clone();
    let ss_w = session_shutdown.clone();
    let writer = tokio::spawn(async move {
        let mut wakeup_interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                pkt = slot_rx.recv() => {
                    match pkt {
                        Some(data) => {
                            if dtls_w.send(&data).await.is_err() {
                                ss_w.store(true, Ordering::Relaxed);
                                return;
                            }
                        }
                        None => return,
                    }
                }
                _ = wakeup_interval.tick() => {
                    if ss_w.load(Ordering::Relaxed) {
                        return;
                    }
                    if dtls_w.send(b"WAKEUP").await.is_err() {
                        ss_w.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }
    });

    // Reader: DTLS -> dispatcher
    let dtls_r = dtls_conn.clone();
    let ss_r = session_shutdown.clone();
    let ret_tx = dispatcher.return_tx.clone();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; READ_BUF];
        loop {
            if ss_r.load(Ordering::Relaxed) {
                return;
            }
            let result = tokio::time::timeout(Duration::from_secs(35), dtls_r.recv(&mut buf)).await;
            match result {
                Ok(Ok(n)) => {
                    if n == 6 && &buf[..6] == b"WAKEUP" {
                        continue; // игнорируем эхо (если мы его сами добавим)
                    }
                    let pkt = buf[..n].to_vec();
                    let _ = ret_tx.try_send(pkt);
                }
                Ok(Err(_)) => {
                    ss_r.store(true, Ordering::Relaxed);
                    return;
                }
                Err(_) => {
                    // Просто ждем дальше: отсутствие трафика (idle) — это нормально в туннелях!
                }
            }
        }
    });

    // Ждём завершения reader или writer
    tokio::select! {
        _ = reader => {}
        _ = writer => {}
        _ = async {
            loop {
                if shutdown.load(Ordering::Relaxed) || session_shutdown.load(Ordering::Relaxed) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        } => {}
    }

    session_shutdown.store(true, Ordering::Relaxed);

    // Cleanup
    dispatcher.unregister(session_id).await;
    stats.active_connections.fetch_sub(1, Ordering::Relaxed);

    keepalive.abort();
    relay_reader.abort();
    relay_writer.abort();

    // Deallocate
    deallocate(&transport, creds, &realm, &nonce).await;

    let _ = dtls_conn.close().await;

    log::info!("[СЕССИЯ #{}] Завершена", session_id);
    Ok(())
}

// === Helpers ===

fn parse_host_port(addr: &str) -> Result<(String, String), String> {
    // Пробуем найти последний ':'
    if let Some(idx) = addr.rfind(':') {
        let host = &addr[..idx];
        let port = &addr[idx + 1..];
        if !port.is_empty() {
            return Ok((host.to_string(), port.to_string()));
        }
    }
    Err(format!("Invalid host:port: {}", addr))
}

async fn deallocate(
    transport: &Arc<Box<dyn TurnTransport>>,
    creds: &Credentials,
    realm: &str,
    nonce: &str,
) {
    let (msg, _) = stun::build_refresh(&creds.user, &creds.pass, realm, nonce, 0);
    let _ = transport.turn_send(&msg).await;
}

// === Абстракция транспорта (TCP/UDP) ===

#[async_trait::async_trait]
trait TurnTransport: Send + Sync + 'static {
    async fn turn_send(&self, data: &[u8]) -> Result<(), String>;
    async fn turn_recv(&self, buf: &mut [u8], timeout: Duration) -> Result<usize, String>;
}

// --- UDP транспорт ---
struct UdpTurnTransport(UdpSocket);

#[async_trait::async_trait]
impl TurnTransport for UdpTurnTransport {
    async fn turn_send(&self, data: &[u8]) -> Result<(), String> {
        self.0.send(data).await.map_err(|e| format!("UDP send: {}", e))?;
        Ok(())
    }

    async fn turn_recv(&self, buf: &mut [u8], timeout: Duration) -> Result<usize, String> {
        tokio::time::timeout(timeout, self.0.recv(buf))
            .await
            .map_err(|_| "recv timeout".to_string())?
            .map_err(|e| format!("UDP recv: {}", e))
    }
}

// --- TCP транспорт (RFC 5766: STUN messages are self-delimiting) ---
struct TcpTurnTransport {
    reader: tokio::sync::Mutex<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>,
}

impl TcpTurnTransport {
    fn new(stream: TcpStream) -> Self {
        let (rx, tx) = stream.into_split();
        Self {
            reader: tokio::sync::Mutex::new(rx),
            writer: tokio::sync::Mutex::new(tx),
        }
    }
}

#[async_trait::async_trait]
impl TurnTransport for TcpTurnTransport {
    async fn turn_send(&self, data: &[u8]) -> Result<(), String> {
        let mut stream = self.writer.lock().await;
        // STUN/ChannelData over TCP: просто пишем сырые данные (самоделимитируемые)
        stream.write_all(data).await.map_err(|e| format!("TCP write: {}", e))?;
        stream.flush().await.map_err(|e| format!("TCP flush: {}", e))?;
        Ok(())
    }

    async fn turn_recv(&self, buf: &mut [u8], timeout: Duration) -> Result<usize, String> {
        let mut stream = self.reader.lock().await;

        // Читаем первые 4 байта чтобы определить тип и длину
        let mut header = [0u8; 4];
        tokio::time::timeout(timeout, stream.read_exact(&mut header))
            .await
            .map_err(|_| "TCP recv timeout".to_string())?
            .map_err(|e| format!("TCP read header: {}", e))?;

        let first_byte = header[0];
        let mut pad_len = 0;
        let msg_len: usize;
        
        if first_byte >= 0x40 && first_byte <= 0x7F {
            // ChannelData: первые 2 байта = channel number, следующие 2 = data length
            let data_len = u16::from_be_bytes([header[2], header[3]]) as usize;
            msg_len = 4 + data_len;
            pad_len = (4 - (data_len % 4)) % 4;
        } else {
            // STUN message: bytes 2-3 = payload length (excluding 20-byte header)
            let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;
            msg_len = 20 + payload_len; // 20-byte STUN header + payload
        }

        if msg_len > buf.len() {
            return Err(format!("TCP message too large: {} > {}", msg_len, buf.len()));
        }

        // Копируем уже прочитанные 4 байта
        buf[..4].copy_from_slice(&header);

        // Дочитываем остаток
        if msg_len > 4 {
            tokio::time::timeout(timeout, stream.read_exact(&mut buf[4..msg_len]))
                .await
                .map_err(|_| "TCP recv data timeout".to_string())?
                .map_err(|e| format!("TCP read body: {}", e))?;
        }
        
        // Вычитываем и отбрасываем паддинг
        if pad_len > 0 {
            let mut throwaway = [0u8; 4];
            tokio::time::timeout(timeout, stream.read_exact(&mut throwaway[..pad_len]))
                .await
                .map_err(|_| "TCP padding timeout".to_string())?
                .map_err(|e| format!("TCP read padding: {}", e))?;
        }

        Ok(msg_len)
    }
}

async fn config_via_dtls(
    conn: &Arc<DTLSConn>,
    local_port: &str,
    device_id: &str,
    password: &str,
) -> Result<Option<String>, String> {
    let payload = format!("GETCONF:{}|{}|{}", local_port, device_id, password);
    conn.send(payload.as_bytes())
        .await
        .map_err(|e| format!("Send GETCONF: {}", e))?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(15), conn.recv(&mut buf))
        .await
        .map_err(|_| "GETCONF timeout".to_string())?
        .map_err(|e| format!("Read config: {}", e))?;

    let resp = String::from_utf8_lossy(&buf[..n]).to_string();

    if resp == "NOCONF" {
        return Ok(None);
    }

    if resp.starts_with("DENIED:") {
        let reason = resp.trim_start_matches("DENIED:");
        return match reason {
            "wrong_password" => Err("FATAL_AUTH: неверный пароль".into()),
            "expired" => Err("FATAL_AUTH: пароль истёк".into()),
            "device_mismatch" => Err("FATAL_AUTH: другое устройство".into()),
            _ => Err(format!("FATAL_AUTH: {}", reason)),
        };
    }

    Ok(Some(resp))
}

async fn ready_via_dtls(conn: &Arc<DTLSConn>) -> Result<(), String> {
    let mut buf = vec![0u8; 64];
    for attempt in 0..4 {
        conn.send(b"READY")
            .await
            .map_err(|e| format!("Send READY: {}", e))?;

        if let Ok(res) = tokio::time::timeout(Duration::from_secs(5), conn.recv(&mut buf)).await {
            let n = res.map_err(|e| format!("Read READY_OK: {}", e))?;
            let resp = String::from_utf8_lossy(&buf[..n]);
            if resp == "READY_OK" {
                return Ok(());
            }
        }
    }
    Err("READY_OK timeout after retries".to_string())
}

/// Обёртка над tokio UdpSocket для webrtc_util::conn::Conn trait.
struct UdpConnWrapper(Arc<UdpSocket>);

#[async_trait::async_trait]
impl Conn for UdpConnWrapper {
    async fn connect(&self, _addr: SocketAddr) -> webrtc_util::Result<()> {
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        self.0
            .recv(buf)
            .await
            .map_err(|e| webrtc_util::Error::Other(e.to_string()))
    }

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> webrtc_util::Result<(usize, SocketAddr)> {
        self.0
            .recv_from(buf)
            .await
            .map_err(|e| webrtc_util::Error::Other(e.to_string()))
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        self.0
            .send(buf)
            .await
            .map_err(|e| webrtc_util::Error::Other(e.to_string()))
    }

    async fn send_to(
        &self,
        buf: &[u8],
        target: SocketAddr,
    ) -> webrtc_util::Result<usize> {
        self.0
            .send_to(buf, target)
            .await
            .map_err(|e| webrtc_util::Error::Other(e.to_string()))
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        self.0
            .local_addr()
            .map_err(|e| webrtc_util::Error::Other(e.to_string()))
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync + 'static) {
        self
    }
}