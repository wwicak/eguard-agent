#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE_METRICS_DEFAULT="${ROOT_DIR}/artifacts/benign-edr-benchmark-suite/metrics.json"
TARGET_PROFILE_DEFAULT="${ROOT_DIR}/benchmarks/competitive_profiles/crowdstrike-parity.example.json"
OUT_DIR_DEFAULT="${ROOT_DIR}/artifacts/competitive-benchmark-eval"

SUITE_METRICS="${SUITE_METRICS_DEFAULT}"
TARGET_PROFILE="${TARGET_PROFILE_DEFAULT}"
OUT_DIR="${OUT_DIR_DEFAULT}"
GATES_ENABLED=true

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --suite-metrics <path>      Suite artifact JSON (default: ${SUITE_METRICS_DEFAULT})
  --target-profile <path>     Competitor target profile JSON (default: ${TARGET_PROFILE_DEFAULT})
  --out-dir <path>            Output directory (default: ${OUT_DIR_DEFAULT})
  --no-gates                  Do not fail process on competitive miss (artifact only)
  -h, --help                  Show help

Target profile schema:
{
  "profile_name": "crowdstrike-parity-v1",
  "thresholds": {
    "minimum_runs": 10,
    "latency_e2e_ms_p95_max": 35000,
    "ingest_delay_s_p95_max": 20,
    "idle_cpu_mean_pct_max": 1.0,
    "load_cpu_mean_pct_max": 55.0,
    "false_positive_all_max": 0,
    "require_cleanup_clean": true
  }
}
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite-metrics)
      SUITE_METRICS="$2"; shift 2 ;;
    --target-profile)
      TARGET_PROFILE="$2"; shift 2 ;;
    --out-dir)
      OUT_DIR="$2"; shift 2 ;;
    --no-gates)
      GATES_ENABLED=false; shift ;;
    -h|--help)
      usage
      exit 0 ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 1 ;;
  esac
done

for bin in python3; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing required tool: $bin" >&2
    exit 1
  fi
done

if [[ ! -f "${SUITE_METRICS}" ]]; then
  echo "suite metrics file not found: ${SUITE_METRICS}" >&2
  exit 1
fi
if [[ ! -f "${TARGET_PROFILE}" ]]; then
  echo "target profile file not found: ${TARGET_PROFILE}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
RUN_ID="$(date -u +"%Y%m%dT%H%M%SZ")"
OUT_JSON="${OUT_DIR}/metrics-${RUN_ID}.json"
OUT_LATEST_JSON="${OUT_DIR}/metrics.json"

PY_OUTPUT="$(python3 - <<PY
import json
import datetime as dt
from pathlib import Path

suite_path = Path(${SUITE_METRICS@Q})
profile_path = Path(${TARGET_PROFILE@Q})
out_path = Path(${OUT_JSON@Q})
out_latest = Path(${OUT_LATEST_JSON@Q})

def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

suite = read_json(suite_path)
profile = read_json(profile_path)
thresholds = profile.get("thresholds", {})

summary = suite.get("summary", {})
lat = summary.get("latency", {})
res = summary.get("resource", {})
fp = summary.get("false_positive", {})
cleanup = summary.get("cleanup", {})

measured = {
    "runs_completed": int(summary.get("runs_completed", 0)),
    "latency_e2e_ms_p95": int(lat.get("e2e_ms_p95", 0)),
    "ingest_delay_s_p95": int(lat.get("ingest_s_p95", 0)),
    "idle_cpu_mean_pct": float(res.get("idle_cpu_mean_percent", 0.0)),
    "load_cpu_mean_pct": float(res.get("load_cpu_mean_percent", 0.0)),
    "false_positive_all_max": int(fp.get("all_max", 0)),
    "cleanup_all_runs_clean": bool(cleanup.get("all_runs_clean", False)),
}

minimum_runs = int(thresholds.get("minimum_runs", 1))
latency_max = int(thresholds.get("latency_e2e_ms_p95_max", 999999999))
ingest_max = int(thresholds.get("ingest_delay_s_p95_max", 999999999))
idle_max = float(thresholds.get("idle_cpu_mean_pct_max", 999999999.0))
load_max = float(thresholds.get("load_cpu_mean_pct_max", 999999999.0))
fp_max = int(thresholds.get("false_positive_all_max", 999999999))
require_cleanup_clean = bool(thresholds.get("require_cleanup_clean", True))

failures = []
if measured["runs_completed"] < minimum_runs:
    failures.append(f"runs_completed {measured['runs_completed']} < {minimum_runs}")
if measured["latency_e2e_ms_p95"] > latency_max:
    failures.append(f"latency_e2e_ms_p95 {measured['latency_e2e_ms_p95']} > {latency_max}")
if measured["ingest_delay_s_p95"] > ingest_max:
    failures.append(f"ingest_delay_s_p95 {measured['ingest_delay_s_p95']} > {ingest_max}")
if measured["idle_cpu_mean_pct"] > idle_max:
    failures.append(f"idle_cpu_mean_pct {measured['idle_cpu_mean_pct']} > {idle_max}")
if measured["load_cpu_mean_pct"] > load_max:
    failures.append(f"load_cpu_mean_pct {measured['load_cpu_mean_pct']} > {load_max}")
if measured["false_positive_all_max"] > fp_max:
    failures.append(f"false_positive_all_max {measured['false_positive_all_max']} > {fp_max}")
if require_cleanup_clean and not measured["cleanup_all_runs_clean"]:
    failures.append("cleanup_all_runs_clean is false")

status = "pass" if not failures else "fail"

artifact = {
    "suite": "competitive_benchmark_eval",
    "recorded_at_utc": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "inputs": {
        "suite_metrics_path": str(suite_path),
        "target_profile_path": str(profile_path),
    },
    "target_profile": profile,
    "measured": measured,
    "status": status,
    "failures": failures,
}

out_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
out_latest.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
print(f"__COMP_JSON__={out_path}")
print(f"__COMP_STATUS__={status}")
PY
)"

COMP_JSON_PATH="$(printf '%s\n' "${PY_OUTPUT}" | awk -F= '/^__COMP_JSON__=/{print $2}' | tail -n1)"
COMP_STATUS="$(printf '%s\n' "${PY_OUTPUT}" | awk -F= '/^__COMP_STATUS__=/{print $2}' | tail -n1)"

if [[ -z "${COMP_JSON_PATH}" ]]; then
  echo "failed to resolve competitive eval artifact path" >&2
  exit 1
fi

echo "wrote competitive benchmark eval artifact: ${COMP_JSON_PATH}"
echo "updated latest competitive eval artifact: ${OUT_LATEST_JSON}"
echo "competitive status: ${COMP_STATUS}"

if [[ "${GATES_ENABLED}" == "true" && "${COMP_STATUS}" == "fail" ]]; then
  exit 1
fi
