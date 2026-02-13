#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/ebpf-resource-budget"
OUT_JSON="${OUT_DIR}/metrics.json"
BIN_PATH="${ROOT_DIR}/target/release/agent-core"

IDLE_CPU_PCT_LIMIT="0.05"
ACTIVE_CPU_PCT_LIMIT="0.5"
PEAK_CPU_PCT_LIMIT="3"
MEMORY_RSS_MB_LIMIT="25"
DISK_IO_KBPS_LIMIT="100"
BINARY_SIZE_MB_LIMIT="10"
STARTUP_SECONDS_LIMIT="2"
DETECTION_LATENCY_NS_LIMIT="500"
LSM_BLOCK_LATENCY_MS_LIMIT="1"

IDLE_CPU_CMD="pidstat -p \$(pidof agent-core) 60"
ACTIVE_CPU_CMD="pidstat -p \$(pidof agent-core) 10 6"
RSS_CMD="ps -o rss= -p \$(pidof agent-core)"
DISK_IO_CMD="pidstat -d -p \$(pidof agent-core) 10 6"
DETECTION_LATENCY_CMD="cargo test -p detection tests::detection_latency_p99_stays_within_budget_for_reference_workload -- --exact"
LSM_LATENCY_CMD="cargo test -p platform-linux ebpf::tests::parses_structured_lsm_block_payload -- --exact"

mkdir -p "${OUT_DIR}"

START_NS="$(date +%s%N)"
cargo build --release -p agent-core
END_NS="$(date +%s%N)"
BUILD_WALL_MS="$(( (END_NS - START_NS) / 1000000 ))"

BINARY_SIZE_BYTES=0
if [[ -f "${BIN_PATH}" ]]; then
  BINARY_SIZE_BYTES="$(wc -c < "${BIN_PATH}")"
fi

NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat > "${OUT_JSON}" <<EOF
{
  "suite": "ebpf_resource_budget",
  "recorded_at_utc": "${NOW_UTC}",
  "limits": {
    "idle_cpu_pct": ${IDLE_CPU_PCT_LIMIT},
    "active_cpu_pct": ${ACTIVE_CPU_PCT_LIMIT},
    "peak_cpu_pct": ${PEAK_CPU_PCT_LIMIT},
    "memory_rss_mb": ${MEMORY_RSS_MB_LIMIT},
    "disk_io_kbps": ${DISK_IO_KBPS_LIMIT},
    "binary_size_mb": ${BINARY_SIZE_MB_LIMIT},
    "startup_seconds": ${STARTUP_SECONDS_LIMIT},
    "detection_latency_ns": ${DETECTION_LATENCY_NS_LIMIT},
    "lsm_block_latency_ms": ${LSM_BLOCK_LATENCY_MS_LIMIT}
  },
  "measurement_commands": {
    "idle_cpu": "${IDLE_CPU_CMD}",
    "active_cpu": "${ACTIVE_CPU_CMD}",
    "memory_rss": "${RSS_CMD}",
    "disk_io": "${DISK_IO_CMD}",
    "detection_latency": "${DETECTION_LATENCY_CMD}",
    "lsm_block_latency": "${LSM_LATENCY_CMD}"
  },
  "measured": {
    "release_build_wall_ms": ${BUILD_WALL_MS},
    "binary_size_bytes": ${BINARY_SIZE_BYTES}
  }
}
EOF

echo "wrote eBPF resource budget metrics to ${OUT_JSON}"
