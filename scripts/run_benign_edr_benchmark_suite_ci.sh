#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_SCRIPT_DEFAULT="${ROOT_DIR}/scripts/run_benign_edr_benchmark.sh"
OUT_DIR_DEFAULT="${ROOT_DIR}/artifacts/benign-edr-benchmark-suite"
RUNS_DEFAULT=10

LATENCY_P95_MAX_MS_DEFAULT=60000
INGEST_P95_MAX_S_DEFAULT=30
IDLE_CPU_MAX_PCT_DEFAULT=5
LOAD_CPU_MAX_PCT_DEFAULT=95
FALSE_POSITIVE_MAX_DEFAULT=0

RUNS="${RUNS_DEFAULT}"
BENCH_SCRIPT="${BENCH_SCRIPT_DEFAULT}"
OUT_DIR="${OUT_DIR_DEFAULT}"

LATENCY_P95_MAX_MS="${LATENCY_P95_MAX_MS_DEFAULT}"
INGEST_P95_MAX_S="${INGEST_P95_MAX_S_DEFAULT}"
IDLE_CPU_MAX_PCT="${IDLE_CPU_MAX_PCT_DEFAULT}"
LOAD_CPU_MAX_PCT="${LOAD_CPU_MAX_PCT_DEFAULT}"
FALSE_POSITIVE_MAX="${FALSE_POSITIVE_MAX_DEFAULT}"

GATES_ENABLED=true
REQUIRE_CLEANUP=true

BENCH_ARGS=()

usage() {
  cat <<EOF
Usage: $(basename "$0") [options] [-- <benchmark-args>]

Options:
  --runs <n>                      Number of benchmark runs (default: ${RUNS_DEFAULT})
  --benchmark-script <path>       Benchmark script path (default: ${BENCH_SCRIPT_DEFAULT})
  --out-dir <path>                Suite output dir (default: ${OUT_DIR_DEFAULT})

Gate options:
  --latency-p95-max-ms <n>        Max sample-level e2e p95 latency (default: ${LATENCY_P95_MAX_MS_DEFAULT})
  --ingest-p95-max-s <n>          Max sample-level ingest p95 seconds (default: ${INGEST_P95_MAX_S_DEFAULT})
  --idle-cpu-max-pct <n>          Max mean idle CPU percent across runs (default: ${IDLE_CPU_MAX_PCT_DEFAULT})
  --load-cpu-max-pct <n>          Max mean load CPU percent across runs (default: ${LOAD_CPU_MAX_PCT_DEFAULT})
  --false-positive-max <n>        Max 'all severities' false-positive count (default: ${FALSE_POSITIVE_MAX_DEFAULT})
  --allow-dirty-cleanup           Do not require replay env cleanup gate
  --no-gates                      Produce artifact only; skip gate failure exit

  -h, --help                      Show this help

Examples:
  $(basename "$0") --runs 10 -- --samples 3 --latency-query-per-page 10
  $(basename "$0") --runs 3 --no-gates -- --samples 1 --idle-window-secs 20
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs)
      RUNS="$2"; shift 2 ;;
    --benchmark-script)
      BENCH_SCRIPT="$2"; shift 2 ;;
    --out-dir)
      OUT_DIR="$2"; shift 2 ;;
    --latency-p95-max-ms)
      LATENCY_P95_MAX_MS="$2"; shift 2 ;;
    --ingest-p95-max-s)
      INGEST_P95_MAX_S="$2"; shift 2 ;;
    --idle-cpu-max-pct)
      IDLE_CPU_MAX_PCT="$2"; shift 2 ;;
    --load-cpu-max-pct)
      LOAD_CPU_MAX_PCT="$2"; shift 2 ;;
    --false-positive-max)
      FALSE_POSITIVE_MAX="$2"; shift 2 ;;
    --allow-dirty-cleanup)
      REQUIRE_CLEANUP=false; shift ;;
    --no-gates)
      GATES_ENABLED=false; shift ;;
    -h|--help)
      usage
      exit 0 ;;
    --)
      shift
      BENCH_ARGS=("$@")
      break ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 1 ;;
  esac
done

for bin in python3 jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing required tool: $bin" >&2
    exit 1
  fi
done

if [[ ! -x "${BENCH_SCRIPT}" ]]; then
  echo "benchmark script is not executable: ${BENCH_SCRIPT}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
RUN_ARTIFACT_DIR="${OUT_DIR}/runs"
mkdir -p "${RUN_ARTIFACT_DIR}"
RUN_ID="$(date -u +"%Y%m%dT%H%M%SZ")"
OUT_JSON="${OUT_DIR}/metrics-${RUN_ID}.json"
OUT_LATEST_JSON="${OUT_DIR}/metrics.json"
RUN_PATHS_FILE="$(mktemp)"

cleanup() {
  rm -f "${RUN_PATHS_FILE}" || true
}
trap cleanup EXIT

echo "running benign EDR benchmark suite: runs=${RUNS}"
for run_idx in $(seq 1 "${RUNS}"); do
  echo "[run ${run_idx}/${RUNS}] starting"
  run_log="$(mktemp)"
  if ! "${BENCH_SCRIPT}" --out-dir "${RUN_ARTIFACT_DIR}" "${BENCH_ARGS[@]}" 2>&1 | tee "${run_log}"; then
    echo "benchmark run ${run_idx} failed" >&2
    rm -f "${run_log}"
    exit 1
  fi

  run_artifact_path="$(awk -F': ' '/^wrote benchmark artifact: /{print $2}' "${run_log}" | tail -n1)"
  rm -f "${run_log}"

  if [[ -z "${run_artifact_path}" ]]; then
    run_artifact_path="${RUN_ARTIFACT_DIR}/metrics.json"
  fi

  if [[ ! -f "${run_artifact_path}" ]]; then
    echo "unable to locate run artifact for run ${run_idx}" >&2
    exit 1
  fi

  echo "${run_idx}|${run_artifact_path}" >> "${RUN_PATHS_FILE}"
  echo "[run ${run_idx}/${RUNS}] artifact=${run_artifact_path}"
done

if (( ${#BENCH_ARGS[@]} > 0 )); then
  BENCH_ARGS_JSON="$(printf '%s\n' "${BENCH_ARGS[@]}" | jq -R . | jq -s .)"
else
  BENCH_ARGS_JSON="[]"
fi

PY_OUTPUT="$(BENCH_ARGS_JSON="${BENCH_ARGS_JSON}" python3 - <<PY
import json
import math
import os
import datetime as dt
from pathlib import Path
from statistics import mean, median

runs_file = Path(${RUN_PATHS_FILE@Q})
out_path = Path(${OUT_JSON@Q})
out_latest_path = Path(${OUT_LATEST_JSON@Q})

def pct(values, q):
    if not values:
        return 0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil((q / 100.0) * len(ordered)) - 1))
    return ordered[idx]

run_entries = []
all_e2e = []
all_ingest = []
idle_cpu_values = []
load_cpu_values = []
fp_all_values = []
cleanup_values = []

for raw in runs_file.read_text(encoding="utf-8").splitlines():
    raw = raw.strip()
    if not raw:
        continue
    run_id, artifact_path = raw.split("|", 1)
    payload = json.loads(Path(artifact_path).read_text(encoding="utf-8"))

    latency_samples = payload.get("latency", {}).get("samples", [])
    ok_samples = [s for s in latency_samples if s.get("status") == "ok"]
    e2e_vals = [int(s.get("e2e_ms", 0)) for s in ok_samples]
    ingest_vals = [int(s.get("ingest_delay_s", 0)) for s in ok_samples]

    all_e2e.extend(e2e_vals)
    all_ingest.extend(ingest_vals)

    idle_cpu = float(payload.get("resource", {}).get("idle", {}).get("cpu_avg_percent", 0.0))
    load_cpu = float(payload.get("resource", {}).get("load", {}).get("cpu_avg_percent", 0.0))
    fp_all = int(payload.get("false_positive_window", {}).get("counts", {}).get("all", 0))
    cleanup_ok = bool(payload.get("cleanup", {}).get("replay_env_cleared", False))

    idle_cpu_values.append(idle_cpu)
    load_cpu_values.append(load_cpu)
    fp_all_values.append(fp_all)
    cleanup_values.append(cleanup_ok)

    run_entries.append({
        "run": int(run_id),
        "artifact_path": artifact_path,
        "latency_ok_samples": len(ok_samples),
        "latency_e2e_ms_p95": pct(e2e_vals, 95) if e2e_vals else 0,
        "latency_ingest_s_p95": pct(ingest_vals, 95) if ingest_vals else 0,
        "idle_cpu_avg_percent": round(idle_cpu, 2),
        "load_cpu_avg_percent": round(load_cpu, 2),
        "false_positive_all": fp_all,
        "cleanup_ok": cleanup_ok,
    })

run_entries.sort(key=lambda r: r["run"])

summary = {
    "runs_completed": len(run_entries),
    "latency": {
        "sample_count": len(all_e2e),
        "e2e_ms_mean": round(mean(all_e2e), 2) if all_e2e else 0,
        "e2e_ms_median": int(median(all_e2e)) if all_e2e else 0,
        "e2e_ms_p95": int(pct(all_e2e, 95)) if all_e2e else 0,
        "ingest_s_mean": round(mean(all_ingest), 2) if all_ingest else 0,
        "ingest_s_p95": int(pct(all_ingest, 95)) if all_ingest else 0,
    },
    "resource": {
        "idle_cpu_mean_percent": round(mean(idle_cpu_values), 2) if idle_cpu_values else 0,
        "idle_cpu_p95_percent": round(pct(idle_cpu_values, 95), 2) if idle_cpu_values else 0,
        "load_cpu_mean_percent": round(mean(load_cpu_values), 2) if load_cpu_values else 0,
        "load_cpu_p95_percent": round(pct(load_cpu_values, 95), 2) if load_cpu_values else 0,
    },
    "false_positive": {
        "all_mean": round(mean(fp_all_values), 2) if fp_all_values else 0,
        "all_max": max(fp_all_values) if fp_all_values else 0,
    },
    "cleanup": {
        "all_runs_clean": all(cleanup_values) if cleanup_values else False,
    },
}

latency_p95_max_ms = int(${LATENCY_P95_MAX_MS})
ingest_p95_max_s = int(${INGEST_P95_MAX_S})
idle_cpu_max_pct = float(${IDLE_CPU_MAX_PCT})
load_cpu_max_pct = float(${LOAD_CPU_MAX_PCT})
false_positive_max = int(${FALSE_POSITIVE_MAX})

failures = []
if summary["latency"]["sample_count"] <= 0:
    failures.append("no successful latency samples captured")
if summary["latency"]["e2e_ms_p95"] > latency_p95_max_ms:
    failures.append(f"latency p95 {summary['latency']['e2e_ms_p95']}ms > {latency_p95_max_ms}ms")
if summary["latency"]["ingest_s_p95"] > ingest_p95_max_s:
    failures.append(f"ingest p95 {summary['latency']['ingest_s_p95']}s > {ingest_p95_max_s}s")
if summary["resource"]["idle_cpu_mean_percent"] > idle_cpu_max_pct:
    failures.append(f"idle cpu mean {summary['resource']['idle_cpu_mean_percent']}% > {idle_cpu_max_pct}%")
if summary["resource"]["load_cpu_mean_percent"] > load_cpu_max_pct:
    failures.append(f"load cpu mean {summary['resource']['load_cpu_mean_percent']}% > {load_cpu_max_pct}%")
if summary["false_positive"]["all_max"] > false_positive_max:
    failures.append(f"false positives max {summary['false_positive']['all_max']} > {false_positive_max}")
if ${REQUIRE_CLEANUP@Q}.lower() == "true" and not summary["cleanup"]["all_runs_clean"]:
    failures.append("cleanup check failed for at least one run")

gates_enabled = (${GATES_ENABLED@Q}.lower() == "true")
gate_status = "pass" if (not gates_enabled or not failures) else "fail"

artifact = {
    "suite": "benign_edr_benchmark_suite",
    "recorded_at_utc": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "inputs": {
        "runs_requested": int(${RUNS}),
        "benchmark_script": ${BENCH_SCRIPT@Q},
        "benchmark_args": json.loads(os.environ.get("BENCH_ARGS_JSON", "[]")),
    },
    "gates": {
        "enabled": gates_enabled,
        "require_cleanup": (${REQUIRE_CLEANUP@Q}.lower() == "true"),
        "thresholds": {
            "latency_p95_max_ms": latency_p95_max_ms,
            "ingest_p95_max_s": ingest_p95_max_s,
            "idle_cpu_mean_max_pct": idle_cpu_max_pct,
            "load_cpu_mean_max_pct": load_cpu_max_pct,
            "false_positive_all_max": false_positive_max,
        },
        "status": gate_status,
        "failures": failures,
    },
    "runs": run_entries,
    "summary": summary,
}

out_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
out_latest_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
print(f"__SUITE_JSON__={out_path}")
print(f"__GATE_STATUS__={gate_status}")
PY
)"

SUITE_JSON_PATH="$(printf '%s\n' "${PY_OUTPUT}" | awk -F= '/^__SUITE_JSON__=/{print $2}' | tail -n1)"
GATE_STATUS="$(printf '%s\n' "${PY_OUTPUT}" | awk -F= '/^__GATE_STATUS__=/{print $2}' | tail -n1)"

if [[ -z "${SUITE_JSON_PATH}" ]]; then
  echo "failed to determine suite artifact path" >&2
  exit 1
fi

echo "wrote benign EDR benchmark suite artifact: ${SUITE_JSON_PATH}"
echo "updated latest suite artifact: ${OUT_LATEST_JSON}"
echo "gate status: ${GATE_STATUS}"

if [[ "${GATE_STATUS}" == "fail" ]]; then
  exit 1
fi
