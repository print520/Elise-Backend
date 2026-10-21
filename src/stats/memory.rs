use std::sync::atomic::{AtomicU64, Ordering};

pub static ANYTLS_SESSIONS: AtomicU64 = AtomicU64::new(0);
pub static VLESS_MUX_SESSIONS: AtomicU64 = AtomicU64::new(0);
pub static MIERU_TCP_SESSIONS: AtomicU64 = AtomicU64::new(0);
pub static AUDIT_QUEUE_LEN: AtomicU64 = AtomicU64::new(0);
pub static AUDIT_QUEUE_DROPPED: AtomicU64 = AtomicU64::new(0);
pub static CLICKHOUSE_QUEUE_LEN: AtomicU64 = AtomicU64::new(0);
pub static CLICKHOUSE_QUEUE_DROPPED: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn saturating_dec(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(1))
    });
}

pub fn process_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    let kb: u64 = rest
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())?;
                    return Some(kb.saturating_mul(1024));
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        use sysinfo::{get_current_pid, System};
        let mut sys = System::new();
        let Ok(pid) = get_current_pid() else {
            return None;
        };
        sys.refresh_process(pid);
        if let Some(proc_) = sys.process(pid) {
            return Some(proc_.memory());
        }
    }

    None
}

pub fn snapshot_json(active_connections: u32, uptime_secs: u64) -> String {
    let process_rss = process_rss_bytes().unwrap_or(0);
    format!(
        r#"{{"service":"elise","version":"{}","os":"{}","arch":"{}","pid":{},"uptime_seconds":{},"process_rss_bytes":{},"active_connections":{},"anytls_sessions":{},"vless_mux_sessions":{},"mieru_tcp_sessions":{},"audit_queue_len":{},"audit_queue_dropped":{},"clickhouse_queue_len":{},"clickhouse_queue_dropped":{}}}"#,
        crate::VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::process::id(),
        uptime_secs,
        process_rss,
        active_connections,
        ANYTLS_SESSIONS.load(Ordering::Relaxed),
        VLESS_MUX_SESSIONS.load(Ordering::Relaxed),
        MIERU_TCP_SESSIONS.load(Ordering::Relaxed),
        AUDIT_QUEUE_LEN.load(Ordering::Relaxed),
        AUDIT_QUEUE_DROPPED.load(Ordering::Relaxed),
        CLICKHOUSE_QUEUE_LEN.load(Ordering::Relaxed),
        CLICKHOUSE_QUEUE_DROPPED.load(Ordering::Relaxed),
    )
}
