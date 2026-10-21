use super::padding::{write_padded_frame, CompiledPaddingScheme, FRAME_OVERHEAD, MAX_FRAME_SIZE};
use super::stream::{parse_socks5_addr, run_anytls_stream_worker};
use super::uot::{run_anytls_uot_worker, UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS};
use crate::conn::BoxedStream;
use crate::panel::types::User;
use crate::protocol::InboundContext;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

pub const CMD_WASTE: u8 = 0;
pub const CMD_SYN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_FIN: u8 = 3;
pub const CMD_SETTINGS: u8 = 4;
pub const CMD_ALERT: u8 = 5;
pub const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;
pub const CMD_SERVER_SETTINGS: u8 = 10;

pub const MAX_CONCURRENT_STREAMS: usize = 1024;
pub const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(15);
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const WAITING_DEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Base timeout ± ~20% jitter so idle/close timing is less uniform across sessions.
fn jittered_timeout(base: Duration) -> Duration {
    let base_ms = base.as_millis() as u64;
    if base_ms == 0 {
        return base;
    }
    let span = (base_ms / 5).max(1);
    let offset = rand::random::<u64>() % (span * 2 + 1);
    Duration::from_millis(base_ms.saturating_sub(span).saturating_add(offset).max(1))
}

pub fn make_frame(command: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_OVERHEAD + payload.len());
    frame.push(command);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub enum StreamState {
    WaitingForDestination { since: Instant },
    Active(mpsc::Sender<Vec<u8>>),
}

impl Clone for StreamState {
    fn clone(&self) -> Self {
        match self {
            StreamState::WaitingForDestination { since } => {
                StreamState::WaitingForDestination { since: *since }
            }
            StreamState::Active(ref tx) => StreamState::Active(tx.clone()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_anytls_session(
    stream: BoxedStream,
    user: Arc<User>,
    ctx: InboundContext,
    client_ip: IpAddr,
    local_ip: Option<IpAddr>,
    _conn_guard: crate::limiter::ConnGuard,
    padding_scheme_ref: Arc<RwLock<Arc<CompiledPaddingScheme>>>,
    session_cancel: CancellationToken,
) -> std::io::Result<()> {
    let (mut client_read, mut client_write) = tokio::io::split(stream);

    let (session_tx, mut session_rx) = mpsc::channel::<Vec<u8>>(128);

    let padding_scheme_snapshot = padding_scheme_ref.read().clone();
    let writer_cancel = session_cancel.clone();

    let writer_task = tokio::spawn(async move {
        let mut packet_count = 0u32;
        let mut send_padding = true;
        let scheme = padding_scheme_snapshot;

        loop {
            tokio::select! {
                _ = writer_cancel.cancelled() => break,
                frame_opt = session_rx.recv() => {
                    match frame_opt {
                        Some(frame) => {
                            if send_padding {
                                if write_padded_frame(&mut client_write, &frame, &mut packet_count, &mut send_padding, &scheme).await.is_err() {
                                    break;
                                }
                            } else if client_write.write_all(&frame).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        let _ = client_write.shutdown().await;
    });

    let streams: Arc<RwLock<HashMap<u32, StreamState>>> = Arc::new(RwLock::new(HashMap::new()));
    let session_start = Instant::now();
    let last_activity = Arc::new(AtomicU64::new(0));
    let session_idle_timeout = jittered_timeout(SESSION_IDLE_TIMEOUT);
    let waiting_dest_timeout = jittered_timeout(WAITING_DEST_TIMEOUT);
    crate::stats::memory::ANYTLS_SESSIONS.fetch_add(1, Ordering::Relaxed);

    let mut stream_tasks = JoinSet::new();

    let mut settings_received = false;
    let mut client_version = 1u32;
    let mut last_stream_id = 0u32;
    let mut header = [0u8; FRAME_OVERHEAD];

    let session_res: std::io::Result<()> = async {
        loop {
            while stream_tasks.try_join_next().is_some() {}

            let tick = tokio::time::sleep(Duration::from_secs(5));
            tokio::pin!(tick);

            let read_hdr = tokio::select! {
                _ = session_cancel.cancelled() => {
                    return Ok(());
                }
                _ = &mut tick => {
                    let expired: Vec<u32> = {
                        let mut streams_guard = streams.write();
                        let mut expired = Vec::new();
                        streams_guard.retain(|&id, state| match state {
                            StreamState::WaitingForDestination { since }
                                if since.elapsed() > waiting_dest_timeout =>
                            {
                                expired.push(id);
                                false
                            }
                            _ => true,
                        });
                        expired
                    };
                    for id in expired {
                        debug!("AnyTLS WaitingForDestination timeout for stream {}", id);
                        let _ = session_tx.send(make_frame(CMD_FIN, id, &[])).await;
                    }

                    let has_streams = !streams.read().is_empty();
                    let elapsed_ms = session_start.elapsed().as_millis() as u64
                        - last_activity.load(Ordering::Relaxed);
                    if !has_streams && elapsed_ms > session_idle_timeout.as_millis() as u64 {
                        debug!("AnyTLS session idle timeout reached with 0 active streams; closing session");
                        return Ok(());
                    }
                    continue;
                }
                res = client_read.read_exact(&mut header) => res,
            };

            match read_hdr {
                Ok(_) => {
                    last_activity.store(
                        session_start.elapsed().as_millis() as u64,
                        Ordering::Relaxed,
                    );
                }
                Err(e) => {
                    debug!("AnyTLS client disconnected: {:?}", e);
                    return Ok(());
                }
            }

            let command = header[0];
            let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
            let length = u16::from_be_bytes([header[5], header[6]]) as usize;

            let mut payload = vec![0u8; length];
            if length > 0 {
                let read_payload_res = tokio::time::timeout(
                    FRAME_READ_TIMEOUT,
                    client_read.read_exact(&mut payload),
                )
                .await;

                match read_payload_res {
                    Ok(Ok(_)) => {
                        last_activity.store(
                            session_start.elapsed().as_millis() as u64,
                            Ordering::Relaxed,
                        );
                    }
                    _ => {
                        warn!("AnyTLS frame payload read timeout or error for stream {}", stream_id);
                        return Ok(());
                    }
                }
            }

            match command {
                CMD_SETTINGS => {

                    settings_received = true;
                    let mut peer_version = 1u32;
                    let mut peer_padding_md5 = String::new();

                    if let Ok(settings_str) = std::str::from_utf8(&payload) {
                        for line in settings_str.lines() {
                            if let Some((k, v)) = line.split_once('=') {
                                match k.trim() {
                                    "v" => {
                                        if let Ok(v_num) = v.trim().parse::<u32>() {
                                            peer_version = v_num;
                                        }
                                    }
                                    "padding-md5" => {
                                        peer_padding_md5 = v.trim().to_string();
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    client_version = peer_version;

                    let current_scheme = padding_scheme_ref.read().clone();
                    if peer_padding_md5 != current_scheme.md5_hex && current_scheme.raw.len() <= MAX_FRAME_SIZE {
                        let _ = session_tx
                            .send(make_frame(
                                CMD_UPDATE_PADDING_SCHEME,
                                0,
                                current_scheme.raw.as_bytes(),
                            ))
                            .await;
                    }

                    if client_version >= 2 {
                        let _ = session_tx
                            .send(make_frame(CMD_SERVER_SETTINGS, 0, b"v=2\n"))
                            .await;
                    }
                }
                CMD_SYN => {

                    if !settings_received {
                        let _ = session_tx
                            .send(make_frame(CMD_ALERT, 0, b"settings required before syn"))
                            .await;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "client sent SYN before settings",
                        ));
                    }

                    if stream_id <= last_stream_id {
                        let _ = session_tx
                            .send(make_frame(CMD_ALERT, 0, b"invalid stream id"))
                            .await;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("non-monotonic stream id: got {stream_id} <= {last_stream_id}"),
                        ));
                    }
                    last_stream_id = stream_id;

                    let should_reject = {
                        let mut streams_guard = streams.write();
                        if streams_guard.len() < MAX_CONCURRENT_STREAMS {
                            streams_guard.insert(
                                stream_id,
                                StreamState::WaitingForDestination {
                                    since: Instant::now(),
                                },
                            );
                            false
                        } else {
                            true
                        }
                    };
                    if should_reject {
                        warn!("AnyTLS stream limit reached, rejecting stream {}", stream_id);
                        let _ = session_tx.send(make_frame(CMD_FIN, stream_id, &[])).await;
                    }
                }
                CMD_PSH => {
                    let state_opt = streams.read().get(&stream_id).cloned();
                    match state_opt {
                        Some(StreamState::WaitingForDestination { .. }) => {
                            if let Some((target_host, target_ip, target_port, leftover)) =
                                parse_socks5_addr(&payload)
                            {
                                let (stream_tx, stream_rx) = mpsc::channel::<Vec<u8>>(64);
                                streams
                                    .write()
                                    .insert(stream_id, StreamState::Active(stream_tx));

                                let initial_payload = leftover.to_vec();
                                let ctx_clone = ctx.clone();
                                let user_clone = user.clone();
                                let session_tx_clone = session_tx.clone();
                                let streams_clone = streams.clone();
                                let worker_cancel = session_cancel.child_token();

                                if target_host == UOT_V2_MAGIC_ADDRESS || target_host == UOT_V1_MAGIC_ADDRESS {
                                    stream_tasks.spawn(async move {
                                        let _ = run_anytls_uot_worker(
                                            stream_id,
                                            client_version,
                                            initial_payload,
                                            stream_rx,
                                            session_tx_clone,
                                            user_clone,
                                            ctx_clone,
                                            client_ip,
                                            local_ip,
                                            worker_cancel,
                                        )
                                        .await;
                                        streams_clone.write().remove(&stream_id);
                                    });
                                } else {

                                    stream_tasks.spawn(async move {
                                        let _ = run_anytls_stream_worker(
                                            stream_id,
                                            client_version,
                                            target_host,
                                            target_ip,
                                            target_port,
                                            initial_payload,
                                            stream_rx,
                                            session_tx_clone,
                                            user_clone,
                                            ctx_clone,
                                            client_ip,
                                            local_ip,
                                            worker_cancel,
                                        )
                                        .await;
                                        streams_clone.write().remove(&stream_id);
                                    });
                                }
                            } else {
                                if client_version >= 2 {
                                    let _ = session_tx
                                        .send(make_frame(CMD_SYNACK, stream_id, b"invalid target address"))
                                        .await;
                                }
                                let _ = session_tx.send(make_frame(CMD_FIN, stream_id, &[])).await;
                                streams.write().remove(&stream_id);
                            }
                        }
                        Some(StreamState::Active(ref tx)) => {
                            let _ = tx.send(payload).await;
                        }
                        None => {

                        }
                    }
                }
                CMD_FIN => {

                    streams.write().remove(&stream_id);
                }
                CMD_HEART_REQUEST => {
                    let _ = session_tx
                        .send(make_frame(CMD_HEART_RESPONSE, stream_id, &[]))
                        .await;
                }
                _ => {

                }
            }
        }
    }
    .await;

    session_cancel.cancel();
    stream_tasks.abort_all();
    drop(session_tx);
    let _ = writer_task.await;
    crate::stats::memory::saturating_dec(&crate::stats::memory::ANYTLS_SESSIONS);

    session_res
}
