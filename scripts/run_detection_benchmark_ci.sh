#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/detection-benchmark"
OUT_JSON="${OUT_DIR}/metrics.json"

mkdir -p "${OUT_DIR}"

START_NS="$(date +%s%N)"
cargo test -p detection tests::detection_latency_p99_stays_within_budget_for_reference_workload -- --exact
END_NS="$(date +%s%N)"

ELAPSED_MS="$(( (END_NS - START_NS) / 1000000 ))"
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat > "${OUT_JSON}" <<EOF
{
  "suite": "detection_latency",
  "recorded_at_utc": "${NOW_UTC}",
  "command": "cargo test -p detection tests::detection_latency_p99_stays_within_budget_for_reference_workload -- --exact",
  "wall_clock_ms": ${ELAPSED_MS}
}
EOF

echo "wrote benchmark metrics to ${OUT_JSON}"
