use super::MieruStreamCipher;
use crate::protocol::mieru::crypto::{
    MieruUser, MieruUserIndex, METADATA_LENGTH, NONCE_SIZE, OVERHEAD,
};
use crate::protocol::mieru::pattern::{decode_low_entropy, TrafficPatternExecutor};
use crate::protocol::mieru::relay::handle_socks5_session;
use crate::protocol::mieru::session::{
    PROTOCOL_ACK_C2S, PROTOCOL_ACK_S2C, PROTOCOL_CLOSE_SESSION_REQ, PROTOCOL_CLOSE_SESSION_RESP,
    PROTOCOL_DATA_C2S, PROTOCOL_DATA_C2S_LOW_ENTROPY, PROTOCOL_DATA_S2C, PROTOCOL_OPEN_SESSION_REQ,
    PROTOCOL_OPEN_SESSION_RESP,
};
use crate::protocol::InboundContext;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use parking_lot::RwLock;
use rand::RngCore;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

const MIN_MTU: usize = NONCE_SIZE + METADATA_LENGTH + OVERHEAD * 2 + 1;
const DEFAULT_MTU: usize = 1400;
const RECEIVE_WINDOW: usize = 16;
const SESSION_QUEUE_CAPACITY: usize = 64;
const MAX_RETRANSMISSIONS: u8 = 20;
const INITIAL_RTO: Duration = Duration::from_millis(250);
const MAX_RTO: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

type SessionKey = (SocketAddr, u32);

struct ActiveUdpSession {
    user: MieruUser,
    session_id: u32,
    key: [u8; 32],
    packet_tx: mpsc::Sender<Vec<u8>>,
    last_activity: parking_lot::Mutex<Instant>,
}

struct PendingPacket {
    packet: Vec<u8>,
    sent_at: Instant,
    retries: u8,
}

pub async fn start_udp_server(
    ctx: InboundContext,
    user_index: Arc<RwLock<MieruUserIndex>>,
    pattern: Arc<TrafficPatternExecutor>,
    mtu: usize,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<()> {
    let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
    let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);
    let mtu = if mtu < MIN_MTU {
        DEFAULT_MTU
    } else {
        mtu.min(1500)
    };
    info!("Mieru UDP inbound listening on {} (MTU {})", bind_addr, mtu);

    let sessions = Arc::new(RwLock::new(
        HashMap::<SessionKey, Arc<ActiveUdpSession>>::new(),
    ));
    let mut tasks = tokio::task::JoinSet::new();
    let mut recv_buf = vec![0u8; u16::MAX as usize];
    let mut cleaner = tokio::time::interval(Duration::from_secs(10));
    cleaner.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ctx.mark_ready();

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Mieru UDP inbound on port {} stopping", ctx.port);
                break;
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result {
                    warn!(error = %error, "Mieru UDP session task failed");
                }
            }
            _ = cleaner.tick() => {
                let timeout = ctx.global_config.udp_timeout;
                sessions.write().retain(|_, session| {
                    !session.packet_tx.is_closed()
                        && (timeout == 0 || session.last_activity.lock().elapsed() < Duration::from_secs(timeout))
                });
            }
            recv = socket.recv_from(&mut recv_buf) => {
                let (n, remote_addr) = match recv {
                    Ok(result) => result,
                    Err(error) => {
                        warn!(error = %error, "Mieru UDP recv_from failed");
                        continue;
                    }
                };
                if n < NONCE_SIZE + METADATA_LENGTH + OVERHEAD {
                    continue;
                }
                if ctx.defense.is_banned(remote_addr.ip()) {
                    continue;
                }
                let packet = recv_buf[..n].to_vec();
                let packet = match dispatch_existing_packet(&sessions, remote_addr, packet) {
                    Ok(()) => continue,
                    Err(packet) => packet,
                };

                let nonce: [u8; NONCE_SIZE] = match packet[..NONCE_SIZE].try_into() {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let now_sec = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let authenticated = {
                    let users = user_index.read();
                    users.try_decrypt_metadata(&packet[NONCE_SIZE..NONCE_SIZE + METADATA_LENGTH + OVERHEAD], &nonce, now_sec)
                };
                let Some((user, key, metadata)) = authenticated else {
                    ctx.defense.record_failure(remote_addr.ip());
                    continue;
                };
                if metadata[0] != PROTOCOL_OPEN_SESSION_REQ || !valid_metadata(&metadata) {
                    continue;
                }
                let session_id = u32::from_be_bytes(metadata[6..10].try_into().unwrap());
                if session_id == 0 {
                    continue;
                }
                if !valid_open_packet(&packet, &metadata, &key) {
                    continue;
                }
                if !ctx.device_limiter.check_and_record_async(user.panel_user.id, remote_addr.ip()).await {
                    continue;
                }
                let conn_guard = match ctx.conn_limiter.try_acquire(user.panel_user.id) {
                    Some(guard) => guard,
                    None => continue,
                };

                let key_tuple = (remote_addr, session_id);
                if sessions.read().contains_key(&key_tuple) {
                    continue;
                }
                let (packet_tx, packet_rx) = mpsc::channel(SESSION_QUEUE_CAPACITY);
                let session = Arc::new(ActiveUdpSession {
                    user: user.clone(),
                    session_id,
                    key,
                    packet_tx,
                    last_activity: parking_lot::Mutex::new(Instant::now()),
                });
                sessions.write().insert(key_tuple, session.clone());
                ctx.defense.record_success(remote_addr.ip());
                let socket = socket.clone();
                let ctx = ctx.clone();
                let pattern = pattern.clone();
                let sessions = sessions.clone();
                let session_for_cleanup = session.clone();
                tasks.spawn(async move {
                    let result = run_udp_session(
                        socket,
                        remote_addr,
                        session,
                        packet,
                        metadata,
                        packet_rx,
                        ctx.clone(),
                        pattern,
                        mtu,
                        conn_guard,
                    ).await;
                    let mut sessions = sessions.write();
                    if sessions
                        .get(&key_tuple)
                        .is_some_and(|current| Arc::ptr_eq(current, &session_for_cleanup))
                    {
                        sessions.remove(&key_tuple);
                    }
                    drop(sessions);
                    if let Err(error) = result {
                        if !matches!(error.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe) {
                            debug!(node_id = ctx.node_id, error = %error, "Mieru UDP session closed");
                        }
                    }
                });
            }
        }
    }

    sessions.write().clear();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn run_udp_session(
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    session: Arc<ActiveUdpSession>,
    first_packet: Vec<u8>,
    open_metadata: [u8; METADATA_LENGTH],
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    ctx: InboundContext,
    pattern: Arc<TrafficPatternExecutor>,
    mtu: usize,
    conn_guard: crate::limiter::ConnGuard,
) -> io::Result<()> {
    let initial_payload = decode_open_payload(&first_packet, &open_metadata, &session.key)?;
    let open_response = encode_session_packet(
        &session.key,
        session.session_id,
        PROTOCOL_OPEN_SESSION_RESP,
        0,
        &[],
        &pattern,
        true,
    )?;
    socket.send_to(&open_response, remote_addr).await?;

    let (application_stream, relay_stream) = tokio::io::duplex(64 * 1024);
    let (mut application_read, mut application_write) = tokio::io::split(application_stream);
    let (relay_read, relay_write) = tokio::io::split(relay_stream);
    if !initial_payload.is_empty() {
        application_write.write_all(&initial_payload).await?;
    }
    let mut relay_task = tokio::spawn(handle_socks5_session(
        relay_read,
        relay_write,
        session.user.panel_user.clone(),
        remote_addr.ip(),
        ctx.clone(),
        conn_guard,
    ));
    let _relay_abort = TaskAbortOnDrop(relay_task.abort_handle());

    let mut next_send = 1u32;
    let mut next_recv =
        u32::from_be_bytes(open_metadata[10..14].try_into().unwrap()).wrapping_add(1);
    let mut remote_window = RECEIVE_WINDOW as u16;
    let mut pending = BTreeMap::<u32, PendingPacket>::new();
    let mut out_of_order = BTreeMap::<u32, Vec<u8>>::new();
    let mut stream_buf = vec![0u8; mtu.saturating_sub(MIN_MTU).max(1)];
    let mut last_activity = Instant::now();
    let mut last_tx = Instant::now();
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await;

    loop {
        let retry_at = pending
            .values()
            .map(|item| item.sent_at + retransmission_timeout(item.retries))
            .min()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(24 * 60 * 60));
        let idle_timeout = ctx.global_config.udp_timeout;
        let idle_at = if idle_timeout == 0 {
            tokio::time::Instant::now() + Duration::from_secs(24 * 60 * 60)
        } else {
            tokio::time::Instant::from_std(last_activity + Duration::from_secs(idle_timeout))
        };

        tokio::select! {
            packet = packet_rx.recv() => {
                let Some(packet) = packet else { break; };
                last_activity = Instant::now();
                let (metadata, payload) = match decode_data_packet(&packet, &session.key) {
                    Ok(Some(frame)) => frame,
                    Ok(None) | Err(_) => continue,
                };
                let protocol = metadata[0];
                let seq = u32::from_be_bytes(metadata[10..14].try_into().unwrap());
                if matches!(
                    protocol,
                    PROTOCOL_DATA_C2S | PROTOCOL_DATA_C2S_LOW_ENTROPY | PROTOCOL_ACK_C2S
                ) {
                    let ack_next = u32::from_be_bytes(metadata[14..18].try_into().unwrap());
                    remote_window =
                        u16::from_be_bytes(metadata[18..20].try_into().unwrap()).min(256);
                    acknowledge_pending(&mut pending, ack_next);
                }

                match protocol {
                    PROTOCOL_OPEN_SESSION_REQ => {
                        // OPEN may be retransmitted if its response was lost.
                        socket.send_to(&open_response, remote_addr).await?;
                        last_tx = Instant::now();
                    }
                    PROTOCOL_DATA_C2S | PROTOCOL_DATA_C2S_LOW_ENTROPY => {
                        if seq == next_recv {
                            if !payload.is_empty() {
                                application_write.write_all(&payload).await?;
                            }
                            next_recv = next_recv.wrapping_add(1);
                            while let Some(buffered) = out_of_order.remove(&next_recv) {
                                if !buffered.is_empty() {
                                    application_write.write_all(&buffered).await?;
                                }
                                next_recv = next_recv.wrapping_add(1);
                            }
                        } else if seq_is_after(seq, next_recv) && out_of_order.len() < RECEIVE_WINDOW {
                            out_of_order.entry(seq).or_insert(payload);
                        }
                        let ack = encode_data_packet(
                            &session.key,
                            session.session_id,
                            PROTOCOL_ACK_S2C,
                            next_send.wrapping_sub(1),
                            next_recv,
                            RECEIVE_WINDOW as u16,
                            &[],
                            &pattern,
                        )?;
                        socket.send_to(&ack, remote_addr).await?;
                        last_tx = Instant::now();
                    }
                    PROTOCOL_ACK_C2S => {
                        // Cumulative ACK and advertised receive window were applied above.
                    }
                    PROTOCOL_CLOSE_SESSION_REQ => {
                        let close = encode_session_packet(
                            &session.key,
                            session.session_id,
                            PROTOCOL_CLOSE_SESSION_RESP,
                            next_send,
                            &[],
                            &pattern,
                            false,
                        )?;
                        socket.send_to(&close, remote_addr).await?;
                        break;
                    }
                    PROTOCOL_CLOSE_SESSION_RESP => break,
                    _ => {}
                }
            }
            result = application_read.read(&mut stream_buf), if remote_window > 0 && pending.len() < usize::from(remote_window).min(RECEIVE_WINDOW) => {
                let n = result?;
                if n == 0 { break; }
                let seq = next_send;
                next_send = next_send.wrapping_add(1);
                let packet = encode_data_packet(
                    &session.key,
                    session.session_id,
                    PROTOCOL_DATA_S2C,
                    seq,
                    next_recv,
                    RECEIVE_WINDOW as u16,
                    &stream_buf[..n],
                    &pattern,
                )?;
                socket.send_to(&packet, remote_addr).await?;
                last_tx = Instant::now();
                pending.insert(seq, PendingPacket { packet, sent_at: Instant::now(), retries: 0 });
            }
            _ = tokio::time::sleep_until(retry_at.into()), if !pending.is_empty() => {
                let now = Instant::now();
                let mut dead = false;
                for packet in pending.values_mut() {
                    if now.duration_since(packet.sent_at) >= retransmission_timeout(packet.retries) {
                        if packet.retries >= MAX_RETRANSMISSIONS {
                            dead = true;
                            break;
                        }
                        socket.send_to(&packet.packet, remote_addr).await?;
                        last_tx = now;
                        packet.retries = packet.retries.saturating_add(1);
                        packet.sent_at = now;
                    }
                }
                if dead {
                    return Err(Error::new(ErrorKind::TimedOut, "Mieru UDP retransmission limit reached"));
                }
            }
            _ = tokio::time::sleep_until(idle_at) => {
                return Err(Error::new(ErrorKind::TimedOut, "Mieru UDP session idle timeout"));
            }
            _ = heartbeat.tick() => {
                if last_tx.elapsed() >= HEARTBEAT_INTERVAL {
                    let ack = encode_data_packet(
                        &session.key,
                        session.session_id,
                        PROTOCOL_ACK_S2C,
                        next_send.wrapping_sub(1),
                        next_recv,
                        RECEIVE_WINDOW as u16,
                        &[],
                        &pattern,
                    )?;
                    socket.send_to(&ack, remote_addr).await?;
                    last_tx = Instant::now();
                }
            }
            result = &mut relay_task => {
                match result {
                    Ok(Ok(())) => break,
                    Ok(Err(error)) => return Err(error),
                    Err(error) => return Err(Error::other(error)),
                }
            }
        }
    }

    relay_task.abort();
    let _ = relay_task.await;
    Ok(())
}

fn dispatch_existing_packet(
    sessions: &parking_lot::RwLock<HashMap<SessionKey, Arc<ActiveUdpSession>>>,
    remote_addr: SocketAddr,
    packet: Vec<u8>,
) -> Result<(), Vec<u8>> {
    let Ok(nonce) = <[u8; NONCE_SIZE]>::try_from(&packet[..NONCE_SIZE]) else {
        return Err(packet);
    };
    let sessions = sessions.read();
    for (_, session) in sessions
        .iter()
        .filter(|((addr, _), _)| *addr == remote_addr)
    {
        let Ok(metadata) = decrypt_metadata(
            &session.key,
            &nonce,
            &packet[NONCE_SIZE..NONCE_SIZE + METADATA_LENGTH + OVERHEAD],
        ) else {
            continue;
        };
        if !valid_metadata(&metadata) {
            continue;
        }
        if u32::from_be_bytes(metadata[6..10].try_into().unwrap()) != session.session_id {
            continue;
        }
        *session.last_activity.lock() = Instant::now();
        // A full queue drops this datagram; the protocol peer retransmits unacknowledged data.
        let _ = session.packet_tx.try_send(packet);
        return Ok(());
    }
    Err(packet)
}

fn valid_open_packet(packet: &[u8], metadata: &[u8; METADATA_LENGTH], key: &[u8; 32]) -> bool {
    valid_metadata(metadata) && decode_open_payload(packet, metadata, key).is_ok()
}

fn valid_metadata(metadata: &[u8; METADATA_LENGTH]) -> bool {
    let now_minute = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 60;
    let timestamp = u32::from_be_bytes(metadata[2..6].try_into().unwrap()) as u64;
    now_minute.abs_diff(timestamp) <= 1
        && u32::from_be_bytes(metadata[6..10].try_into().unwrap()) != 0
}

fn decode_open_payload(
    packet: &[u8],
    metadata: &[u8; METADATA_LENGTH],
    key: &[u8; 32],
) -> io::Result<Vec<u8>> {
    let length = u16::from_be_bytes(metadata[15..17].try_into().unwrap()) as usize;
    let suffix = metadata[17] as usize;
    let end = NONCE_SIZE + METADATA_LENGTH + OVERHEAD;
    if packet.len() != end + length + OVERHEAD + suffix || length > 1024 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Invalid Mieru OPEN packet length",
        ));
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    let nonce: [u8; NONCE_SIZE] = packet[..NONCE_SIZE].try_into().unwrap();
    let mut cipher = stream_cipher(key, nonce)?;
    cipher.decrypt_payload(&packet[end..end + length + OVERHEAD], length)
}

fn decode_data_packet(
    packet: &[u8],
    key: &[u8; 32],
) -> io::Result<Option<([u8; METADATA_LENGTH], Vec<u8>)>> {
    if packet.len() < NONCE_SIZE + METADATA_LENGTH + OVERHEAD {
        return Ok(None);
    }
    let nonce: [u8; NONCE_SIZE] = packet[..NONCE_SIZE].try_into().unwrap();
    let metadata = decrypt_metadata(
        key,
        &nonce,
        &packet[NONCE_SIZE..NONCE_SIZE + METADATA_LENGTH + OVERHEAD],
    )?;
    if !valid_metadata(&metadata) {
        return Ok(None);
    }
    let protocol = metadata[0];
    if !matches!(
        protocol,
        PROTOCOL_OPEN_SESSION_REQ
            | PROTOCOL_CLOSE_SESSION_REQ
            | PROTOCOL_CLOSE_SESSION_RESP
            | PROTOCOL_DATA_C2S
            | PROTOCOL_DATA_C2S_LOW_ENTROPY
            | PROTOCOL_ACK_C2S
    ) {
        return Ok(None);
    }
    if protocol == PROTOCOL_ACK_C2S {
        let prefix = metadata[21] as usize;
        let suffix = metadata[24] as usize;
        if u16::from_be_bytes(metadata[22..24].try_into().unwrap()) != 0
            || packet.len() != NONCE_SIZE + METADATA_LENGTH + OVERHEAD + prefix + suffix
        {
            return Ok(None);
        }
        return Ok(Some((metadata, Vec::new())));
    }
    if matches!(
        protocol,
        PROTOCOL_OPEN_SESSION_REQ | PROTOCOL_CLOSE_SESSION_REQ | PROTOCOL_CLOSE_SESSION_RESP
    ) {
        return Ok(Some((metadata, Vec::new())));
    }

    let prefix = metadata[21] as usize;
    let payload_len = u16::from_be_bytes(metadata[22..24].try_into().unwrap()) as usize;
    let suffix = metadata[24] as usize;
    let body_start = NONCE_SIZE + METADATA_LENGTH + OVERHEAD + prefix;
    let body_end = body_start
        .checked_add(payload_len)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Mieru payload length overflow"))?;
    if packet.len() != body_end + OVERHEAD + suffix {
        return Ok(None);
    }
    if payload_len == 0 {
        return Ok(Some((metadata, Vec::new())));
    }

    let mut wire_body = packet[body_start..body_end].to_vec();
    let mut tag = packet[body_end..body_end + OVERHEAD].to_vec();
    let (decoded_body, plain_len) = if protocol == PROTOCOL_DATA_C2S_LOW_ENTROPY {
        let extracted = u16::from_be_bytes(metadata[29..31].try_into().unwrap()) as usize;
        let decoded = decode_low_entropy(
            &wire_body,
            extracted,
            metadata[1] as i32,
            u32::from_be_bytes(metadata[25..29].try_into().unwrap()),
            metadata[31] as i32,
        )?;
        (decoded, extracted)
    } else {
        (std::mem::take(&mut wire_body), payload_len)
    };
    let mut wire = decoded_body;
    wire.append(&mut tag);
    let mut cipher = stream_cipher(key, nonce)?;
    let payload = cipher.decrypt_payload(&wire, plain_len)?;
    Ok(Some((metadata, payload)))
}

fn decrypt_metadata(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    encrypted: &[u8],
) -> io::Result<[u8; METADATA_LENGTH]> {
    if encrypted.len() != METADATA_LENGTH + OVERHEAD {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Invalid Mieru metadata length",
        ));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid Mieru cipher key"))?;
    let mut bytes = encrypted[..METADATA_LENGTH].to_vec();
    let tag = chacha20poly1305::Tag::from_slice(&encrypted[METADATA_LENGTH..]);
    cipher
        .decrypt_in_place_detached(XNonce::from_slice(nonce), b"", &mut bytes, tag)
        .map_err(|_| {
            Error::new(
                ErrorKind::InvalidData,
                "Mieru metadata authentication failed",
            )
        })?;
    let metadata: [u8; METADATA_LENGTH] = bytes
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid Mieru metadata"))?;
    Ok(metadata)
}

fn stream_cipher(key: &[u8; 32], nonce: [u8; NONCE_SIZE]) -> io::Result<MieruStreamCipher> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid Mieru cipher key"))?;
    Ok(MieruStreamCipher::new(cipher, nonce))
}

fn encode_session_packet(
    key: &[u8; 32],
    session_id: u32,
    protocol: u8,
    seq: u32,
    payload: &[u8],
    pattern: &TrafficPatternExecutor,
    first: bool,
) -> io::Result<Vec<u8>> {
    let mut metadata = [0u8; METADATA_LENGTH];
    metadata[0] = protocol;
    metadata[6..10].copy_from_slice(&session_id.to_be_bytes());
    metadata[10..14].copy_from_slice(&seq.to_be_bytes());
    metadata[15..17].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    metadata[17] = 0;
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    pattern.apply_nonce_pattern(&mut nonce, true, first);
    encrypt_packet(key, nonce, metadata, payload)
}

fn encode_data_packet(
    key: &[u8; 32],
    session_id: u32,
    protocol: u8,
    seq: u32,
    unack_seq: u32,
    window_size: u16,
    payload: &[u8],
    pattern: &TrafficPatternExecutor,
) -> io::Result<Vec<u8>> {
    let mut metadata = [0u8; METADATA_LENGTH];
    metadata[0] = protocol;
    metadata[6..10].copy_from_slice(&session_id.to_be_bytes());
    metadata[10..14].copy_from_slice(&seq.to_be_bytes());
    metadata[14..18].copy_from_slice(&unack_seq.to_be_bytes());
    metadata[18..20].copy_from_slice(&window_size.to_be_bytes());
    metadata[22..24].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    pattern.apply_nonce_pattern(&mut nonce, true, false);
    encrypt_packet(key, nonce, metadata, payload)
}

fn encrypt_packet(
    key: &[u8; 32],
    nonce: [u8; NONCE_SIZE],
    metadata: [u8; METADATA_LENGTH],
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid Mieru cipher key"))?;
    let mut metadata = metadata;
    let now_minute = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 60) as u32;
    metadata[2..6].copy_from_slice(&now_minute.to_be_bytes());
    let mut encrypted_metadata = metadata.to_vec();
    let metadata_tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), b"", &mut encrypted_metadata)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Mieru metadata encryption failed"))?;
    let mut packet =
        Vec::with_capacity(NONCE_SIZE + METADATA_LENGTH + OVERHEAD * 2 + payload.len());
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&encrypted_metadata);
    packet.extend_from_slice(metadata_tag.as_slice());
    if !payload.is_empty() {
        let mut encrypted_payload = payload.to_vec();
        let payload_tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), b"", &mut encrypted_payload)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Mieru payload encryption failed"))?;
        packet.extend_from_slice(&encrypted_payload);
        packet.extend_from_slice(payload_tag.as_slice());
    }
    Ok(packet)
}

fn acknowledge_pending(pending: &mut BTreeMap<u32, PendingPacket>, ack_next: u32) {
    pending.retain(|seq, _| seq_is_after_or_equal(*seq, ack_next));
}

fn seq_is_after(seq: u32, reference: u32) -> bool {
    seq.wrapping_sub(reference) as i32 > 0
}

fn seq_is_after_or_equal(seq: u32, reference: u32) -> bool {
    seq == reference || seq_is_after(seq, reference)
}

fn retransmission_timeout(retries: u8) -> Duration {
    INITIAL_RTO
        .saturating_mul(1u32 << retries.min(5))
        .min(MAX_RTO)
}

struct TaskAbortOnDrop(tokio::task::AbortHandle);

impl Drop for TaskAbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::mieru::crypto::{pbkdf2_sha256_32, salts_from_time};
    use crate::protocol::mieru::MieruUser;
    use crate::protocol::InboundContext;
    use crate::proxy::router::{OutboundDialer, Router};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    fn context(port: u16) -> InboundContext {
        let geo = Arc::new(crate::geo::GeoEngine::default());
        let dialer = Arc::new(OutboundDialer::new(
            Arc::new(crate::dns::DNSResolver::default()),
            None,
            None,
            false,
        ));
        InboundContext {
            ready: None,
            node_id: 1,
            listen_addr: "127.0.0.1".into(),
            port,
            router: Arc::new(Router::new(Default::default(), dialer, geo.clone())),
            rate_limiter: Arc::new(crate::limiter::RateLimiter::new()),
            conn_limiter: Arc::new(crate::limiter::ConnectionLimiter::new()),
            device_limiter: Arc::new(crate::limiter::DeviceLimiter::new(60, 32, 128, None)),
            audit: Arc::new(crate::security::AuditController::new_with_options(
                "",
                "",
                geo,
                Vec::new(),
                false,
                false,
            )),
            defense: Arc::new(crate::security::AttackDefenseManager::default()),
            tls_manager: Arc::new(crate::security::TLSManager::new(false, "localhost".into())),
            audit_logger: Arc::new(crate::observability::AuditLogger::new(None::<&str>)),
            clickhouse_logger: Arc::new(crate::observability::ClickHouseLogger::new(
                false,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                None,
            )),
            on_traffic: Arc::new(|_, _, _| ()),
            global_config: Arc::new(crate::config::GlobalConfig::default()),
            ip_user_cache: Arc::new(crate::limiter::IpUserCache::new(24, false, "")),
        }
    }

    fn test_user_and_key() -> (MieruUser, [u8; 32]) {
        let user = MieruUser::from_panel_user(crate::panel::types::User {
            id: 7,
            uuid: "udp-test-password".into(),
            username: Some("udp-test-user".into()),
            password: Some("udp-test-password".into()),
            ..Default::default()
        });
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let salt = salts_from_time(now)[1];
        let key = pbkdf2_sha256_32(&user.hashed_password, &salt, 64);
        (user, key)
    }

    fn client_open_packet(
        key: &[u8; 32],
        username: &str,
        session_id: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce[..16]);
        let prefix: [u8; 16] = nonce[..16].try_into().unwrap();
        nonce[20..24].copy_from_slice(&crate::protocol::mieru::crypto::compute_user_hint(
            username, &prefix,
        ));
        let mut metadata = [0u8; METADATA_LENGTH];
        metadata[0] = PROTOCOL_OPEN_SESSION_REQ;
        metadata[6..10].copy_from_slice(&session_id.to_be_bytes());
        metadata[15..17].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        encrypt_packet(key, nonce, metadata, payload).unwrap()
    }

    fn decode_server_data(packet: &[u8], key: &[u8; 32]) -> io::Result<([u8; 32], Vec<u8>)> {
        let nonce: [u8; NONCE_SIZE] = packet[..NONCE_SIZE].try_into().unwrap();
        let metadata = decrypt_metadata(
            key,
            &nonce,
            &packet[NONCE_SIZE..NONCE_SIZE + METADATA_LENGTH + OVERHEAD],
        )?;
        let payload_len = u16::from_be_bytes(metadata[22..24].try_into().unwrap()) as usize;
        let offset = NONCE_SIZE + METADATA_LENGTH + OVERHEAD + metadata[21] as usize;
        let mut cipher = stream_cipher(key, nonce)?;
        let payload = cipher.decrypt_payload(
            &packet[offset..offset + payload_len + OVERHEAD],
            payload_len,
        )?;
        Ok((metadata, payload))
    }

    #[tokio::test]
    async fn native_udp_transport_runs_socks_connect_and_returns_tcp_payload() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            loop {
                let n = match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if stream.write_all(&buffer[..n]).await.is_err() {
                    break;
                }
            }
        });

        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (user, key) = test_user_and_key();
        let username = user.username.clone();
        let user_index = Arc::new(RwLock::new(MieruUserIndex::new(vec![user
            .panel_user
            .clone()])));
        let server = tokio::spawn(start_udp_server(
            context(port),
            user_index,
            Arc::new(TrafficPatternExecutor::default()),
            DEFAULT_MTU,
            shutdown_rx,
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = echo_addr.port().to_be_bytes();
        let mut socks_stream = vec![
            5,
            1,
            0,
            1,
            127,
            0,
            0,
            1,
            target_port[0],
            target_port[1], // SOCKS5 CONNECT request
        ];
        socks_stream.extend_from_slice(b"udp-roundtrip");
        let session_id = 0x1020_3040;
        let open = client_open_packet(&key, &username, session_id, &socks_stream);
        client.send_to(&open, ("127.0.0.1", port)).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(8), async {
            let mut received = Vec::new();
            let mut packet_buf = vec![0u8; 2048];
            let mut opened = false;
            let mut open_responses = 0;
            let mut next_data_seq = 1u32;
            let mut received_out_of_order = BTreeMap::<u32, Vec<u8>>::new();
            let mut intentionally_dropped_seq = None;
            let mut retransmit = tokio::time::interval(Duration::from_millis(200));
            while !received
                .windows(b"udp-roundtrip".len())
                .any(|w| w == b"udp-roundtrip")
            {
                let n = tokio::select! {
                    _ = retransmit.tick() => {
                        if !opened {
                            client.send_to(&open, ("127.0.0.1", port)).await.unwrap();
                        }
                        continue;
                    }
                    result = client.recv_from(&mut packet_buf) => result.unwrap().0,
                };
                let packet = &packet_buf[..n];
                let nonce: [u8; NONCE_SIZE] = packet[..NONCE_SIZE].try_into().unwrap();
                let metadata = decrypt_metadata(
                    &key,
                    &nonce,
                    &packet[NONCE_SIZE..NONCE_SIZE + METADATA_LENGTH + OVERHEAD],
                )
                .unwrap();
                assert_eq!(
                    u32::from_be_bytes(metadata[6..10].try_into().unwrap()),
                    session_id
                );
                match metadata[0] {
                    PROTOCOL_OPEN_SESSION_RESP => {
                        open_responses += 1;
                        opened = true;
                        if open_responses == 1 {
                            // A repeated OPEN must recover a lost response without resetting
                            // the established packet window.
                            client.send_to(&open, ("127.0.0.1", port)).await.unwrap();
                        }
                    }
                    PROTOCOL_DATA_S2C => {
                        if !opened {
                            continue;
                        }
                        let (metadata, payload) = decode_server_data(packet, &key).unwrap();
                        let seq = u32::from_be_bytes(metadata[10..14].try_into().unwrap());
                        if intentionally_dropped_seq.is_none() {
                            // Simulate one lost server packet; the same sequence must be
                            // retransmitted and delivered before later sequence numbers.
                            intentionally_dropped_seq = Some(seq);
                            continue;
                        }
                        received_out_of_order.entry(seq).or_insert(payload);
                        while let Some(payload) = received_out_of_order.remove(&next_data_seq) {
                            received.extend_from_slice(&payload);
                            next_data_seq = next_data_seq.wrapping_add(1);
                        }
                        let ack = encode_data_packet(
                            &key,
                            session_id,
                            PROTOCOL_ACK_C2S,
                            0,
                            next_data_seq,
                            RECEIVE_WINDOW as u16,
                            &[],
                            &TrafficPatternExecutor::default(),
                        )
                        .unwrap();
                        client.send_to(&ack, ("127.0.0.1", port)).await.unwrap();
                    }
                    _ => {}
                }
            }
            (received, open_responses)
        })
        .await
        .expect("Mieru UDP stream did not return the echoed bytes");

        assert!(result
            .0
            .windows(b"udp-roundtrip".len())
            .any(|w| w == b"udp-roundtrip"));
        assert!(result.1 >= 2, "duplicate OPEN was not answered");
        let _ = shutdown_tx.send(());
        server.await.unwrap().unwrap();
        echo_task.abort();
    }

    #[tokio::test]
    async fn native_udp_transport_runs_socks_udp_associate() {
        let echo_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_socket.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, peer) = echo_socket.recv_from(&mut buf).await.unwrap();
                if echo_socket.send_to(&buf[..n], peer).await.is_err() {
                    break;
                }
            }
        });

        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (user, key) = test_user_and_key();
        let username = user.username.clone();
        let user_index = Arc::new(RwLock::new(MieruUserIndex::new(vec![user.panel_user])));
        let server = tokio::spawn(start_udp_server(
            context(port),
            user_index,
            Arc::new(TrafficPatternExecutor::default()),
            DEFAULT_MTU,
            shutdown_rx,
        ));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let session_id = 0x5060_7080;
        let socks_udp_associate = [5, 3, 0, 1, 0, 0, 0, 0, 0, 0];
        let open = client_open_packet(&key, &username, session_id, &socks_udp_associate);
        client.send_to(&open, ("127.0.0.1", port)).await.unwrap();

        tokio::time::timeout(Duration::from_secs(8), async {
            let mut packet_buf = vec![0u8; 4096];
            let mut open_response = false;
            let mut next_server_seq = 1u32;
            let mut pending = BTreeMap::<u32, Vec<u8>>::new();
            let mut stream_bytes = Vec::new();
            let mut retransmit = tokio::time::interval(Duration::from_millis(200));
            loop {
                let n = tokio::select! {
                    _ = retransmit.tick() => {
                        if !open_response {
                            client.send_to(&open, ("127.0.0.1", port)).await.unwrap();
                        }
                        continue;
                    }
                    result = client.recv_from(&mut packet_buf) => result.unwrap().0,
                };
                let packet = &packet_buf[..n];
                let nonce: [u8; NONCE_SIZE] = packet[..NONCE_SIZE].try_into().unwrap();
                let metadata = decrypt_metadata(
                    &key,
                    &nonce,
                    &packet[NONCE_SIZE..NONCE_SIZE + METADATA_LENGTH + OVERHEAD],
                )
                .unwrap();
                match metadata[0] {
                    PROTOCOL_OPEN_SESSION_RESP => open_response = true,
                    PROTOCOL_DATA_S2C if open_response => {
                        let (metadata, payload) = decode_server_data(packet, &key).unwrap();
                        let seq = u32::from_be_bytes(metadata[10..14].try_into().unwrap());
                        pending.entry(seq).or_insert(payload);
                        while let Some(payload) = pending.remove(&next_server_seq) {
                            stream_bytes.extend_from_slice(&payload);
                            next_server_seq = next_server_seq.wrapping_add(1);
                        }
                        let ack = encode_data_packet(
                            &key,
                            session_id,
                            PROTOCOL_ACK_C2S,
                            0,
                            next_server_seq,
                            RECEIVE_WINDOW as u16,
                            &[],
                            &TrafficPatternExecutor::default(),
                        )
                        .unwrap();
                        client.send_to(&ack, ("127.0.0.1", port)).await.unwrap();

                        // SOCKS5 UDP Associate first returns its standard ten-byte bind reply.
                        if stream_bytes.len() >= 10 {
                            assert_eq!(&stream_bytes[..2], &[5, 0]);
                            break;
                        }
                    }
                    _ => {}
                }
            }

            let mut socks_udp_packet = vec![0, 0, 0, 1];
            socks_udp_packet.extend_from_slice(&[127, 0, 0, 1]);
            socks_udp_packet.extend_from_slice(&echo_addr.port().to_be_bytes());
            socks_udp_packet.extend_from_slice(b"mieru-udp-associate");
            let mut framed = vec![0];
            framed.extend_from_slice(&(socks_udp_packet.len() as u16).to_be_bytes());
            framed.extend_from_slice(&socks_udp_packet);
            framed.push(0xff);
            let data = encode_data_packet(
                &key,
                session_id,
                PROTOCOL_DATA_C2S,
                1,
                next_server_seq,
                RECEIVE_WINDOW as u16,
                &framed,
                &TrafficPatternExecutor::default(),
            )
            .unwrap();
            client.send_to(&data, ("127.0.0.1", port)).await.unwrap();

            loop {
                let n = client.recv_from(&mut packet_buf).await.unwrap().0;
                let packet = &packet_buf[..n];
                let nonce: [u8; NONCE_SIZE] = packet[..NONCE_SIZE].try_into().unwrap();
                let metadata = decrypt_metadata(
                    &key,
                    &nonce,
                    &packet[NONCE_SIZE..NONCE_SIZE + METADATA_LENGTH + OVERHEAD],
                )
                .unwrap();
                if metadata[0] != PROTOCOL_DATA_S2C {
                    continue;
                }
                let (metadata, payload) = decode_server_data(packet, &key).unwrap();
                let seq = u32::from_be_bytes(metadata[10..14].try_into().unwrap());
                pending.entry(seq).or_insert(payload);
                while let Some(payload) = pending.remove(&next_server_seq) {
                    stream_bytes.extend_from_slice(&payload);
                    next_server_seq = next_server_seq.wrapping_add(1);
                }
                let ack = encode_data_packet(
                    &key,
                    session_id,
                    PROTOCOL_ACK_C2S,
                    0,
                    next_server_seq,
                    RECEIVE_WINDOW as u16,
                    &[],
                    &TrafficPatternExecutor::default(),
                )
                .unwrap();
                client.send_to(&ack, ("127.0.0.1", port)).await.unwrap();

                let marker = b"mieru-udp-associate";
                if stream_bytes.windows(marker.len()).any(|w| w == marker) {
                    // SOCKS5 bind reply is ten bytes. The following frame is
                    // 00 | u16 length | SOCKS5 UDP packet | FF.
                    let frame = &stream_bytes[10..];
                    assert_eq!(frame[0], 0);
                    let frame_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
                    assert!(frame.len() > 3 + frame_len);
                    assert_eq!(frame[3 + frame_len], 0xff);
                    assert!(frame[3..3 + frame_len]
                        .windows(marker.len())
                        .any(|w| w == marker));
                    break;
                }
            }
        })
        .await
        .expect("Mieru UDP Associate did not return the echoed UDP datagram");

        let _ = shutdown_tx.send(());
        server.await.unwrap().unwrap();
        echo_task.abort();
    }

    #[test]
    fn udp_data_packet_round_trips_with_one_datagram_nonce() {
        let key = [3u8; 32];
        let payload = b"mieru udp segment";
        let packet = encode_data_packet(
            &key,
            77,
            PROTOCOL_DATA_S2C,
            9,
            4,
            16,
            payload,
            &TrafficPatternExecutor::default(),
        )
        .unwrap();
        let (metadata, decoded) = decode_server_data(&packet, &key).unwrap();
        assert_eq!(metadata[0], PROTOCOL_DATA_S2C);
        assert_eq!(u32::from_be_bytes(metadata[10..14].try_into().unwrap()), 9);
        assert_eq!(decoded, payload);
    }
}
