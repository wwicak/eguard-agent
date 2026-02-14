#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/ebpf-resource-budget"
OUT_JSON="${OUT_DIR}/metrics.json"
BIN_PATH="${ROOT_DIR}/target/release/agent-core"
STARTUP_PROBE_CMD="${EGUARD_STARTUP_PROBE_CMD:-}"

IDLE_CPU_PCT_LIMIT="${EGUARD_IDLE_CPU_PCT_LIMIT:-0.05}"
ACTIVE_CPU_PCT_LIMIT="${EGUARD_ACTIVE_CPU_PCT_LIMIT:-0.5}"
PEAK_CPU_PCT_LIMIT="${EGUARD_PEAK_CPU_PCT_LIMIT:-3}"
MEMORY_RSS_MB_LIMIT="${EGUARD_MEMORY_RSS_MB_LIMIT:-25}"
DISK_IO_KBPS_LIMIT="${EGUARD_DISK_IO_KBPS_LIMIT:-100}"
BINARY_SIZE_MB_LIMIT="${EGUARD_BINARY_SIZE_MB_LIMIT:-}"
STARTUP_SECONDS_LIMIT="${EGUARD_STARTUP_SECONDS_LIMIT:-2}"
DETECTION_LATENCY_NS_LIMIT="${EGUARD_DETECTION_LATENCY_NS_LIMIT:-500}"
LSM_BLOCK_LATENCY_MS_LIMIT="${EGUARD_LSM_BLOCK_LATENCY_MS_LIMIT:-1}"

BINARY_SIZE_LIMIT_JSON="null"
BINARY_SIZE_ENFORCED_JSON="false"
if [[ -n "${BINARY_SIZE_MB_LIMIT}" ]]; then
  BINARY_SIZE_LIMIT_JSON="${BINARY_SIZE_MB_LIMIT}"
  BINARY_SIZE_ENFORCED_JSON="true"
fi

IDLE_CPU_CMD="pidstat -p \$(pidof agent-core) 60"
ACTIVE_CPU_CMD="pidstat -p \$(pidof agent-core) 10 6"
RSS_CMD="ps -o rss= -p \$(pidof agent-core)"
DISK_IO_CMD="pidstat -d -p \$(pidof agent-core) 10 6"
DETECTION_LATENCY_CMD="cargo test -p detection tests::detection_latency_p99_stays_within_budget_for_reference_workload -- --exact"
LSM_LATENCY_CMD="cargo test -p platform-linux ebpf::tests::parses_structured_lsm_block_payload -- --exact"

mkdir -p "${OUT_DIR}"

run_timed_command() {
  local command="$1"
  local start_ns
  local end_ns
  local status

  start_ns="$(date +%s%N)"
  set +e
  bash -c "${command}" >&2
  status="$?"
  set -e
  end_ns="$(date +%s%N)"

  printf '%s %s\n' "$(( (end_ns - start_ns) / 1000000 ))" "${status}"
}

START_NS="$(date +%s%N)"
cargo build --release -p agent-core
END_NS="$(date +%s%N)"
BUILD_WALL_MS="$(( (END_NS - START_NS) / 1000000 ))"

BINARY_SIZE_BYTES=0
if [[ -f "${BIN_PATH}" ]]; then
  BINARY_SIZE_BYTES="$(wc -c < "${BIN_PATH}")"
fi

BINARY_SIZE_MB="$((BINARY_SIZE_BYTES))"
BINARY_SIZE_MB="$(awk "BEGIN { printf \"%.6f\", ${BINARY_SIZE_MB} / (1024.0 * 1024.0) }")"

read -r DETECTION_PROBE_WALL_MS DETECTION_PROBE_STATUS <<< "$(run_timed_command "${DETECTION_LATENCY_CMD}")"
read -r LSM_PROBE_WALL_MS LSM_PROBE_STATUS <<< "$(run_timed_command "${LSM_LATENCY_CMD}")"

STARTUP_PROBE_WALL_MS="-1"
STARTUP_PROBE_STATUS="0"
if [[ -n "${STARTUP_PROBE_CMD}" ]]; then
  read -r STARTUP_PROBE_WALL_MS STARTUP_PROBE_STATUS <<< "$(run_timed_command "${STARTUP_PROBE_CMD}")"
fi

if [[ "${BINARY_SIZE_ENFORCED_JSON}" == "true" ]]; then
  if ! awk "BEGIN { if (${BINARY_SIZE_MB} > ${BINARY_SIZE_MB_LIMIT}) exit 1 }"; then
    echo "binary size budget exceeded: ${BINARY_SIZE_MB} MB > ${BINARY_SIZE_MB_LIMIT} MB"
    exit 1
  fi
fi
if [[ "${DETECTION_PROBE_STATUS}" != "0" ]]; then
  echo "detection latency probe command failed"
  exit 1
fi
if [[ "${LSM_PROBE_STATUS}" != "0" ]]; then
  echo "lsm block probe command failed"
  exit 1
fi
if [[ "${STARTUP_PROBE_WALL_MS}" != "-1" ]]; then
  awk "BEGIN { if ((${STARTUP_PROBE_WALL_MS} / 1000.0) > ${STARTUP_SECONDS_LIMIT}) exit 1 }"
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
    "binary_size_mb": ${BINARY_SIZE_LIMIT_JSON},
    "binary_size_enforced": ${BINARY_SIZE_ENFORCED_JSON},
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
    "binary_size_bytes": ${BINARY_SIZE_BYTES},
    "binary_size_mb": ${BINARY_SIZE_MB},
    "detection_latency_probe_wall_ms": ${DETECTION_PROBE_WALL_MS},
    "lsm_block_probe_wall_ms": ${LSM_PROBE_WALL_MS},
    "startup_probe_wall_ms": ${STARTUP_PROBE_WALL_MS}
  },
  "probe_status": {
    "detection_latency": ${DETECTION_PROBE_STATUS},
    "lsm_block_latency": ${LSM_PROBE_STATUS},
    "startup": ${STARTUP_PROBE_STATUS}
  }
}
EOF

echo "wrote eBPF resource budget metrics to ${OUT_JSON}"
