#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/ebpf-drop-rate-pressure"
OUT_JSON="${OUT_DIR}/metrics.json"

mkdir -p "${OUT_DIR}"

TEST_CMD="cargo test -p platform-linux ebpf::tests::drop_rate_stays_below_slo_for_reference_10k_event_batch -- --exact"
START_NS="$(date +%s%N)"
bash -c "${TEST_CMD}"
END_NS="$(date +%s%N)"

ELAPSED_MS="$(( (END_NS - START_NS) / 1000000 ))"
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat > "${OUT_JSON}" <<EOF
{
  "suite": "ebpf_drop_rate_pressure",
  "recorded_at_utc": "${NOW_UTC}",
  "command": "${TEST_CMD}",
  "wall_clock_ms": ${ELAPSED_MS},
  "drop_rate_slo": "< 1e-5"
}
EOF

echo "wrote eBPF drop-rate pressure metrics to ${OUT_JSON}"
