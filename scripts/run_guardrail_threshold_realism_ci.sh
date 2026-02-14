#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/guardrail-threshold-realism"

mkdir -p "${OUT_DIR}"

METRIC_FILES=(
  "artifacts/detection-benchmark/metrics.json"
  "artifacts/runtime-tick-slo/metrics.json"
  "artifacts/replay-determinism/metrics.json"
  "artifacts/detection-quality-gate/metrics.json"
  "artifacts/detection-quality-gate/per-confidence-trend.ndjson"
  "artifacts/detection-quality-gate/trend-drift-report.json"
  "artifacts/ebpf-drop-rate-pressure/metrics.json"
  "artifacts/rule-push-slo/metrics.json"
  "artifacts/ebpf-resource-budget/metrics.json"
  "artifacts/perf-profile-gate/metrics.json"
  "artifacts/release-profile-opt/metrics.json"
  "artifacts/optimization-guardrail-summary/metrics.json"
)

run_guardrails() {
  local label="$1"
  local cold_clean="$2"

  echo "running guardrail threshold realism pass: ${label}"

  if [[ "${cold_clean}" == "1" ]]; then
    echo "performing cargo clean for cold pass"
    cargo clean
  fi

  bash "${ROOT_DIR}/scripts/run_detection_benchmark_ci.sh"
  bash "${ROOT_DIR}/scripts/run_runtime_tick_slo_ci.sh"
  bash "${ROOT_DIR}/scripts/run_replay_determinism_ci.sh"
  bash "${ROOT_DIR}/scripts/run_detection_quality_gate_ci.sh"
  bash "${ROOT_DIR}/scripts/run_ebpf_drop_rate_pressure_ci.sh"
  bash "${ROOT_DIR}/scripts/run_rule_push_slo_ci.sh"
  bash "${ROOT_DIR}/scripts/run_ebpf_resource_budget_ci.sh"
  bash "${ROOT_DIR}/scripts/run_perf_profile_gate_ci.sh"
  bash "${ROOT_DIR}/scripts/run_release_profile_opt_ci.sh"

  python3 "${ROOT_DIR}/scripts/check_optimization_guardrail_thresholds.py" \
    --root "${ROOT_DIR}" \
    --output "${ROOT_DIR}/artifacts/optimization-guardrail-summary/metrics.json"

  local pass_dir="${OUT_DIR}/${label}"
  mkdir -p "${pass_dir}"

  for relative in "${METRIC_FILES[@]}"; do
    local src="${ROOT_DIR}/${relative}"
    if [[ ! -f "${src}" ]]; then
      echo "missing expected metric artifact during ${label}: ${relative}" >&2
      return 1
    fi
    local dst="${pass_dir}/${relative}"
    mkdir -p "$(dirname "${dst}")"
    cp -f "${src}" "${dst}"
  done
}

COLD_CLEAN="${EGUARD_GUARDRAIL_REALISM_COLD_CLEAN:-1}"
run_guardrails cold "${COLD_CLEAN}"
run_guardrails warm 0

python3 - <<'PY' "${OUT_DIR}"
import json
import pathlib
import sys

out_dir = pathlib.Path(sys.argv[1])

cold_summary_path = out_dir / "cold" / "artifacts/optimization-guardrail-summary/metrics.json"
warm_summary_path = out_dir / "warm" / "artifacts/optimization-guardrail-summary/metrics.json"

cold = json.loads(cold_summary_path.read_text())
warm = json.loads(warm_summary_path.read_text())

status = "ok"
failures = []
if cold.get("status") != "ok":
    status = "failed"
    failures.append("cold run guardrail thresholds failed")
if warm.get("status") != "ok":
    status = "failed"
    failures.append("warm run guardrail thresholds failed")

summary = {
    "suite": "guardrail_threshold_realism",
    "status": status,
    "cold": {
        "status": cold.get("status"),
        "failures": cold.get("failures", []),
    },
    "warm": {
        "status": warm.get("status"),
        "failures": warm.get("failures", []),
    },
    "failures": failures,
}

summary_path = out_dir / "summary.json"
summary_path.write_text(json.dumps(summary, indent=2) + "\n")
print(f"wrote guardrail threshold realism summary to {summary_path}")

if status != "ok":
    for failure in failures:
        print(f"- {failure}")
    raise SystemExit(1)
PY
