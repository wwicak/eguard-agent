use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tracing::warn;

pub(super) fn compute_poll_timeout(
    _pending: usize,
    _recent_ebpf_drops: u64,
) -> std::time::Duration {
    // The outer runtime already ticks every 100ms. Blocking inside the eBPF
    // poll path can therefore only hurt us: if the kernel-side poll ignores or
    // stretches the requested timeout, heartbeats/control-plane work starve even
    // though no telemetry is available. Use a non-blocking poll and let the main
    // tick cadence provide the pacing.
    std::time::Duration::from_millis(0)
}

pub(super) fn compute_sampling_stride(pending: usize, recent_ebpf_drops: u64) -> usize {
    let backlog_stride = if pending > 2_048 {
        8
    } else if pending > 1_024 {
        4
    } else if pending > 256 {
        2
    } else {
        1
    };

    if recent_ebpf_drops == 0 {
        return backlog_stride;
    }

    let drop_stride = if pending > 2_048 {
        8
    } else if pending > 1_024 {
        4
    } else {
        2
    };

    backlog_stride.max(drop_stride)
}

pub(super) fn resolve_detection_shard_count() -> usize {
    const MAX_DETECTION_SHARDS: usize = 16;
    const DEFAULT_DETECTION_SHARDS: usize = 2;
    if let Ok(raw) = std::env::var("EGUARD_DETECTION_SHARDS") {
        match raw.trim().parse::<usize>() {
            Ok(value) if value > 0 => return value.min(MAX_DETECTION_SHARDS),
            _ => warn!(
                value = %raw,
                "invalid EGUARD_DETECTION_SHARDS value; falling back to default"
            ),
        }
    }

    std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, DEFAULT_DETECTION_SHARDS))
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
