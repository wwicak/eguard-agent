use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tracing::warn;

pub(super) fn compute_poll_timeout(pending: usize, recent_ebpf_drops: u64) -> std::time::Duration {
    if recent_ebpf_drops > 0 {
        std::time::Duration::from_millis(1)
    } else if pending > 4096 {
        std::time::Duration::from_millis(5)
    } else if pending > 1024 {
        std::time::Duration::from_millis(20)
    } else {
        std::time::Duration::from_millis(100)
    }
}

pub(super) fn compute_sampling_stride(pending: usize, recent_ebpf_drops: u64) -> usize {
    if recent_ebpf_drops == 0 {
        return 1;
    }
    if pending > 8_192 {
        8
    } else if pending > 4_096 {
        4
    } else if pending > 1_024 {
        2
    } else {
        1
    }
}

pub(super) fn resolve_detection_shard_count() -> usize {
    const MAX_DETECTION_SHARDS: usize = 16;
    if let Ok(raw) = std::env::var("EGUARD_DETECTION_SHARDS") {
        match raw.trim().parse::<usize>() {
            Ok(value) if value > 0 => return value.min(MAX_DETECTION_SHARDS),
            _ => warn!(
                value = %raw,
                "invalid EGUARD_DETECTION_SHARDS value; falling back to CPU-based default"
            ),
        }
    }

    std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, MAX_DETECTION_SHARDS))
        .unwrap_or(1)
}

pub(super) fn interval_due(last_run_unix: Option<i64>, now_unix: i64, interval_secs: i64) -> bool {
    match last_run_unix {
        None => true,
        Some(last) => {
            if now_unix < last {
                return false;
            }
            now_unix.saturating_sub(last) >= interval_secs
        }
    }
}

pub(super) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(super) fn elapsed_micros(started: Instant) -> u64 {
    let micros = started.elapsed().as_micros();
    let bounded = micros.min(u64::MAX as u128) as u64;
    bounded.max(1)
}
