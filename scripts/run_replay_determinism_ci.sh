#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/replay-determinism"
OUT_JSON="${OUT_DIR}/metrics.json"

mkdir -p "${OUT_DIR}"

CMD="cargo test -p detection tests::replay_harness_is_deterministic -- --exact"
START_NS="$(date +%s%N)"
bash -c "${CMD}"
END_NS="$(date +%s%N)"

ELAPSED_MS="$(( (END_NS - START_NS) / 1000000 ))"
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat > "${OUT_JSON}" <<EOF
{
  "suite": "replay_determinism",
  "recorded_at_utc": "${NOW_UTC}",
  "command": "${CMD}",
  "wall_clock_ms": ${ELAPSED_MS}
}
EOF

echo "wrote replay determinism metrics to ${OUT_JSON}"
