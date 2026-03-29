use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tracing::warn;

const LOW_MEMORY_HOST_THRESHOLD_BYTES: u64 = 3 * 1024 * 1024 * 1024;

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

pub(super) fn host_is_low_memory(mem_total_bytes: Option<u64>) -> bool {
    mem_total_bytes
        .map(|value| value > 0 && value <= LOW_MEMORY_HOST_THRESHOLD_BYTES)
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
pub(super) fn linux_host_mem_total_bytes() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    meminfo.lines().find_map(parse_memtotal_line_bytes)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn linux_host_mem_total_bytes() -> Option<u64> {
    None
}

fn parse_memtotal_line_bytes(line: &str) -> Option<u64> {
    let trimmed = line.trim();
    let value = trimmed.strip_prefix("MemTotal:")?;
    let kib = value
        .split_whitespace()
        .next()
        .and_then(|raw| raw.parse::<u64>().ok())?;
    Some(kib.saturating_mul(1024))
}

fn recommended_detection_shard_count(
    available_parallelism: usize,
    mem_total_bytes: Option<u64>,
    override_raw: Option<&str>,
) -> usize {
    const MAX_DETECTION_SHARDS: usize = 16;
    const DEFAULT_DETECTION_SHARDS: usize = 2;

    if let Some(raw) = override_raw {
        if let Ok(value) = raw.trim().parse::<usize>() {
            if value > 0 {
                return value.min(MAX_DETECTION_SHARDS);
            }
        }
        warn!(
            value = %raw,
            "invalid EGUARD_DETECTION_SHARDS value; falling back to default"
        );
    }

    if host_is_low_memory(mem_total_bytes) {
        return 1;
    }

    available_parallelism.clamp(1, DEFAULT_DETECTION_SHARDS)
}

pub(super) fn resolve_detection_shard_count() -> usize {
    recommended_detection_shard_count(
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        linux_host_mem_total_bytes(),
        std::env::var("EGUARD_DETECTION_SHARDS").ok().as_deref(),
    )
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

#[cfg(test)]
mod tests {
    use super::{host_is_low_memory, parse_memtotal_line_bytes, recommended_detection_shard_count};

    #[test]
    fn parse_memtotal_line_bytes_accepts_meminfo_line() {
        assert_eq!(
            parse_memtotal_line_bytes("MemTotal:        2097152 kB"),
            Some(2_147_483_648)
        );
    }

    #[test]
    fn low_memory_hosts_default_to_single_detection_shard() {
        assert_eq!(
            recommended_detection_shard_count(8, Some(2 * 1024 * 1024 * 1024), None),
            1
        );
        assert!(host_is_low_memory(Some(3 * 1024 * 1024 * 1024)));
        assert!(!host_is_low_memory(Some(4 * 1024 * 1024 * 1024)));
    }

    #[test]
    fn detection_shard_override_wins_when_valid() {
        assert_eq!(
            recommended_detection_shard_count(8, Some(2 * 1024 * 1024 * 1024), Some("3")),
            3
        );
    }
}
