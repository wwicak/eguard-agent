#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/perf-profile-gate"
OUT_JSON="${OUT_DIR}/metrics.json"
REQUIRE_TOOLS="${EGUARD_REQUIRE_PERF_TOOLS:-0}"
CMD="cargo test -p detection tests::detection_latency_p99_stays_within_budget_for_reference_workload -- --exact"

mkdir -p "${OUT_DIR}"
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

if ! command -v perf >/dev/null 2>&1; then
  if [[ "${REQUIRE_TOOLS}" == "1" ]]; then
    echo "perf is required but missing"
    exit 1
  fi

  cat > "${OUT_JSON}" <<EOF
{
  "suite": "perf_profile_gate",
  "recorded_at_utc": "${NOW_UTC}",
  "status": "skipped",
  "reason": "perf_not_available",
  "require_tools": ${REQUIRE_TOOLS}
}
EOF
  echo "perf unavailable; wrote skipped profile gate metrics to ${OUT_JSON}"
  exit 0
fi

PERF_OUT="${OUT_DIR}/perf-stat.txt"
set +e
perf stat -x, -e cycles,instructions,branches,branch-misses -- bash -c "${CMD}" 2>"${PERF_OUT}"
STATUS="$?"
set -e

if [[ "${STATUS}" != "0" ]]; then
  if [[ "${REQUIRE_TOOLS}" == "1" ]]; then
    echo "perf profile gate command failed"
    cat > "${OUT_JSON}" <<EOF
{
  "suite": "perf_profile_gate",
  "recorded_at_utc": "${NOW_UTC}",
  "status": "failed",
  "command": "${CMD}",
  "exit_code": ${STATUS}
}
EOF
    exit "${STATUS}"
  fi

  cat > "${OUT_JSON}" <<EOF
{
  "suite": "perf_profile_gate",
  "recorded_at_utc": "${NOW_UTC}",
  "status": "skipped",
  "reason": "perf_unavailable_or_permission_denied",
  "command": "${CMD}",
  "exit_code": ${STATUS},
  "require_tools": ${REQUIRE_TOOLS}
}
EOF
  echo "perf unavailable or not permitted; wrote skipped profile gate metrics to ${OUT_JSON}"
  exit 0
fi

extract_metric() {
  local key="$1"
  awk -F',' -v key="${key}" '$3==key { print $1; exit }' "${PERF_OUT}" | tr -d ' '
}

CYCLES="$(extract_metric cycles)"
INSTRUCTIONS="$(extract_metric instructions)"
BRANCHES="$(extract_metric branches)"
BRANCH_MISSES="$(extract_metric branch-misses)"

if cargo flamegraph --version >/dev/null 2>&1; then
  FLAMEGRAPH_AVAILABLE=true
else
  FLAMEGRAPH_AVAILABLE=false
fi

cat > "${OUT_JSON}" <<EOF
{
  "suite": "perf_profile_gate",
  "recorded_at_utc": "${NOW_UTC}",
  "status": "ok",
  "command": "${CMD}",
  "perf_stat_file": "${PERF_OUT}",
  "flamegraph_available": ${FLAMEGRAPH_AVAILABLE},
  "metrics": {
    "cycles": "${CYCLES}",
    "instructions": "${INSTRUCTIONS}",
    "branches": "${BRANCHES}",
    "branch_misses": "${BRANCH_MISSES}"
  }
}
EOF

echo "wrote perf profile metrics to ${OUT_JSON}"
