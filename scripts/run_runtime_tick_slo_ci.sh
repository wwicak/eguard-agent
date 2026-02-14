#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/runtime-tick-slo"
OUT_JSON="${OUT_DIR}/metrics.json"

mkdir -p "${OUT_DIR}"

TEST_CMD="cargo test -p agent-core lifecycle::tests_observability::runtime_tick_p99_and_degraded_churn_stay_within_guardrails -- --exact"

START_NS="$(date +%s%N)"
bash -c "${TEST_CMD}"
END_NS="$(date +%s%N)"

ELAPSED_MS="$(( (END_NS - START_NS) / 1000000 ))"
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat > "${OUT_JSON}" <<EOF
{
  "suite": "runtime_tick_slo",
  "recorded_at_utc": "${NOW_UTC}",
  "command": "${TEST_CMD}",
  "wall_clock_ms": ${ELAPSED_MS}
}
EOF

echo "wrote runtime tick SLO metrics to ${OUT_JSON}"
