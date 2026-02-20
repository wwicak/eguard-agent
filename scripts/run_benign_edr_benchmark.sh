#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR_DEFAULT="${ROOT_DIR}/artifacts/benign-edr-benchmark"

VM_HOST_DEFAULT="edr@27.112.78.178"
API_HOST_DEFAULT="eguard@157.10.161.219"
API_BASE_URL_DEFAULT="http://127.0.0.1:22224"
AGENT_ID_DEFAULT="agent-dev-1"

SAMPLES_DEFAULT=3
LATENCY_TIMEOUT_SECS_DEFAULT=90
LATENCY_POLL_INTERVAL_SECS_DEFAULT=1
IDLE_WINDOW_SECS_DEFAULT=60
LOAD_WINDOW_SECS_DEFAULT=30
WARMUP_SECS_DEFAULT=30
FALSE_POSITIVE_WINDOW_SECS_DEFAULT=120
LOAD_EVENT_COUNT_DEFAULT=300
LOAD_EVENT_SPACING_NS_DEFAULT=100000000
LOAD_MEASURE_DELAY_SECS_DEFAULT=3
LATENCY_QUERY_PER_PAGE_DEFAULT=20

VM_REPLAY_DROPIN="/etc/systemd/system/eguard-agent.service.d/12-replay.conf"
VM_SINGLE_REPLAY_FILE="/tmp/eguard-replay-one.ndjson"
VM_LOAD_REPLAY_FILE="/tmp/eguard-replay-load.ndjson"

VM_HOST="${VM_HOST_DEFAULT}"
API_HOST="${API_HOST_DEFAULT}"
API_BASE_URL="${API_BASE_URL_DEFAULT}"
AGENT_ID="${AGENT_ID_DEFAULT}"
OUT_DIR="${OUT_DIR_DEFAULT}"

SAMPLES="${SAMPLES_DEFAULT}"
LATENCY_TIMEOUT_SECS="${LATENCY_TIMEOUT_SECS_DEFAULT}"
LATENCY_POLL_INTERVAL_SECS="${LATENCY_POLL_INTERVAL_SECS_DEFAULT}"
IDLE_WINDOW_SECS="${IDLE_WINDOW_SECS_DEFAULT}"
LOAD_WINDOW_SECS="${LOAD_WINDOW_SECS_DEFAULT}"
WARMUP_SECS="${WARMUP_SECS_DEFAULT}"
FALSE_POSITIVE_WINDOW_SECS="${FALSE_POSITIVE_WINDOW_SECS_DEFAULT}"
LOAD_EVENT_COUNT="${LOAD_EVENT_COUNT_DEFAULT}"
LOAD_EVENT_SPACING_NS="${LOAD_EVENT_SPACING_NS_DEFAULT}"
LOAD_MEASURE_DELAY_SECS="${LOAD_MEASURE_DELAY_SECS_DEFAULT}"
LATENCY_QUERY_PER_PAGE="${LATENCY_QUERY_PER_PAGE_DEFAULT}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --vm-host <user@host>              VM SSH target (default: ${VM_HOST_DEFAULT})
  --api-host <user@host>             API SSH target (default: ${API_HOST_DEFAULT})
  --api-base-url <url>               API base URL reachable from api host (default: ${API_BASE_URL_DEFAULT})
  --agent-id <id>                    Agent ID to query (default: ${AGENT_ID_DEFAULT})
  --samples <n>                      Latency sample count (default: ${SAMPLES_DEFAULT})
  --latency-timeout-secs <n>         Poll timeout per sample (default: ${LATENCY_TIMEOUT_SECS_DEFAULT})
  --latency-poll-interval-secs <n>   Poll interval seconds (default: ${LATENCY_POLL_INTERVAL_SECS_DEFAULT})
  --latency-query-per-page <n>       Endpoint events page size during latency polling (default: ${LATENCY_QUERY_PER_PAGE_DEFAULT})
  --idle-window-secs <n>             Idle resource window seconds (default: ${IDLE_WINDOW_SECS_DEFAULT})
  --load-window-secs <n>             Load resource window seconds (default: ${LOAD_WINDOW_SECS_DEFAULT})
  --warmup-secs <n>                  Warmup seconds before idle capture (default: ${WARMUP_SECS_DEFAULT})
  --false-positive-window-secs <n>   Quiet window for false-positive counts (default: ${FALSE_POSITIVE_WINDOW_SECS_DEFAULT})
  --load-event-count <n>             Synthetic replay events for load run (default: ${LOAD_EVENT_COUNT_DEFAULT})
  --load-event-spacing-ns <n>        Spacing between synthetic load events (default: ${LOAD_EVENT_SPACING_NS_DEFAULT})
  --load-measure-delay-secs <n>      Delay after replay restart before load capture (default: ${LOAD_MEASURE_DELAY_SECS_DEFAULT})
  --out-dir <path>                   Output directory (default: ${OUT_DIR_DEFAULT})
  -h, --help                         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm-host)
      VM_HOST="$2"; shift 2 ;;
    --api-host)
      API_HOST="$2"; shift 2 ;;
    --api-base-url)
      API_BASE_URL="$2"; shift 2 ;;
    --agent-id)
      AGENT_ID="$2"; shift 2 ;;
    --samples)
      SAMPLES="$2"; shift 2 ;;
    --latency-timeout-secs)
      LATENCY_TIMEOUT_SECS="$2"; shift 2 ;;
    --latency-poll-interval-secs)
      LATENCY_POLL_INTERVAL_SECS="$2"; shift 2 ;;
    --latency-query-per-page)
      LATENCY_QUERY_PER_PAGE="$2"; shift 2 ;;
    --idle-window-secs)
      IDLE_WINDOW_SECS="$2"; shift 2 ;;
    --load-window-secs)
      LOAD_WINDOW_SECS="$2"; shift 2 ;;
    --warmup-secs)
      WARMUP_SECS="$2"; shift 2 ;;
    --false-positive-window-secs)
      FALSE_POSITIVE_WINDOW_SECS="$2"; shift 2 ;;
    --load-event-count)
      LOAD_EVENT_COUNT="$2"; shift 2 ;;
    --load-event-spacing-ns)
      LOAD_EVENT_SPACING_NS="$2"; shift 2 ;;
    --load-measure-delay-secs)
      LOAD_MEASURE_DELAY_SECS="$2"; shift 2 ;;
    --out-dir)
      OUT_DIR="$2"; shift 2 ;;
    -h|--help)
      usage
      exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1 ;;
  esac
done

for bin in ssh jq python3; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing required tool: $bin" >&2
    exit 1
  fi
done

mkdir -p "${OUT_DIR}"
RUN_ID="$(date -u +"%Y%m%dT%H%M%SZ")"
OUT_JSON="${OUT_DIR}/metrics-${RUN_ID}.json"
OUT_LATEST_JSON="${OUT_DIR}/metrics.json"
SAMPLES_JSONL="$(mktemp)"

ssh_vm() {
  ssh -o BatchMode=yes -o ConnectTimeout=15 "${VM_HOST}" "$@"
}

ssh_api() {
  ssh -o BatchMode=yes -o ConnectTimeout=15 "${API_HOST}" "$@"
}

urlencode() {
  python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1"
}

set_replay_path() {
  local replay_path="$1"
  ssh_vm "set -euo pipefail; cat <<'CONF' | sudo tee ${VM_REPLAY_DROPIN} >/dev/null
[Service]
Environment=EGUARD_EBPF_REPLAY_PATH=${replay_path}
CONF
sudo systemctl daemon-reload
sudo systemctl restart eguard-agent >/dev/null 2>&1"
}

clear_replay_path() {
  ssh_vm "set -euo pipefail; sudo rm -f ${VM_REPLAY_DROPIN}; sudo systemctl daemon-reload; sudo systemctl restart eguard-agent >/dev/null 2>&1"
}

vm_prop() {
  local key="$1"
  ssh_vm "sudo systemctl show eguard-agent -p ${key} --value"
}

cleanup() {
  clear_replay_path || true
}
trap cleanup EXIT

echo "[1/5] verifying services are reachable"
ssh_vm "sudo systemctl is-active eguard-agent >/dev/null"
ssh_api "curl -fsS '${API_BASE_URL}/api/v1/endpoint-events?agent_id=${AGENT_ID}&per_page=1' >/dev/null"

echo "[2/5] collecting latency samples (${SAMPLES})"
for sample in $(seq 1 "${SAMPLES}"); do
  t0_ms="$(date +%s%3N)"
  marker="lat-marker-${sample}-${t0_ms}"

  ssh_vm "python3 - <<'PY'
import json,time
marker='${marker}'
obj={
  'event_type':'lsm_block',
  'pid':6000,
  'uid':1000,
  'ts_ns':int(time.time()*1_000_000_000),
  'reason':7,
  'subject':marker,
}
with open('${VM_SINGLE_REPLAY_FILE}','w',encoding='utf-8') as f:
    f.write(json.dumps(obj)+'\\n')
print(marker)
PY" >/dev/null

  set_replay_path "${VM_SINGLE_REPLAY_FILE}"

  found=""
  for _ in $(seq 1 "${LATENCY_TIMEOUT_SECS}"); do
    row_json="$(ssh_api "curl -fsS '${API_BASE_URL}/api/v1/endpoint-events?agent_id=${AGENT_ID}&severity=critical&per_page=${LATENCY_QUERY_PER_PAGE}' | jq -c --arg m '${marker}' '.items[] | select((.event_data.event.command_line // \"\") == \$m) | {id,created_at,observed_at_unix:(.event_data.observed_at_unix // 0)}' | head -n1" || true)"
    if [[ -n "${row_json}" ]]; then
      found="${row_json}"
      break
    fi
    sleep "${LATENCY_POLL_INTERVAL_SECS}"
  done

  if [[ -z "${found}" ]]; then
    jq -cn \
      --arg sample "${sample}" \
      --arg marker "${marker}" \
      --arg t0_ms "${t0_ms}" \
      '{sample:($sample|tonumber),marker:$marker,t0_ms:($t0_ms|tonumber),status:"not_found"}' >> "${SAMPLES_JSONL}"
    echo "  sample ${sample}: marker ${marker} not found within timeout"
    continue
  fi

  t_found_ms="$(date +%s%3N)"
  id="$(printf '%s' "${found}" | jq -r '.id')"
  created_at="$(printf '%s' "${found}" | jq -r '.created_at')"
  observed_unix="$(printf '%s' "${found}" | jq -r '.observed_at_unix')"
  created_epoch_utc="$(date -u -d "${created_at}" +%s)"
  e2e_ms="$(( t_found_ms - t0_ms ))"
  ingest_delay_s="$(( created_epoch_utc - observed_unix ))"

  jq -cn \
    --arg sample "${sample}" \
    --arg marker "${marker}" \
    --arg t0_ms "${t0_ms}" \
    --arg t_found_ms "${t_found_ms}" \
    --arg id "${id}" \
    --arg created_at "${created_at}" \
    --arg observed_unix "${observed_unix}" \
    --arg e2e_ms "${e2e_ms}" \
    --arg ingest_delay_s "${ingest_delay_s}" \
    '{
      sample:($sample|tonumber),
      marker:$marker,
      t0_ms:($t0_ms|tonumber),
      t_found_ms:($t_found_ms|tonumber),
      id:($id|tonumber),
      created_at_utc:$created_at,
      observed_unix:($observed_unix|tonumber),
      e2e_ms:($e2e_ms|tonumber),
      ingest_delay_s:($ingest_delay_s|tonumber),
      status:"ok"
    }' >> "${SAMPLES_JSONL}"

  echo "  sample ${sample}: id=${id} e2e_ms=${e2e_ms} ingest_delay_s=${ingest_delay_s}"
done


echo "[3/5] collecting resource baseline"
clear_replay_path
sleep "${WARMUP_SECS}"

idle_start_cpu_ns="$(vm_prop CPUUsageNSec)"
idle_start_mem_bytes="$(vm_prop MemoryCurrent)"
idle_start_peak_bytes="$(vm_prop MemoryPeak)"
sleep "${IDLE_WINDOW_SECS}"

idle_end_cpu_ns="$(vm_prop CPUUsageNSec)"
idle_end_mem_bytes="$(vm_prop MemoryCurrent)"
idle_end_peak_bytes="$(vm_prop MemoryPeak)"

ssh_vm "python3 - <<'PY'
import json,time
base=int(time.time()*1_000_000_000)
spacing_ns=int('${LOAD_EVENT_SPACING_NS}')
with open('${VM_LOAD_REPLAY_FILE}','w',encoding='utf-8') as f:
    for i in range(1, ${LOAD_EVENT_COUNT} + 1):
        obj={
          'event_type':'lsm_block',
          'pid':7000+i,
          'uid':1000,
          'ts_ns':base+i*spacing_ns,
          'reason':7,
          'subject':f'load-marker-{i}',
        }
        f.write(json.dumps(obj)+'\\n')
PY" >/dev/null

set_replay_path "${VM_LOAD_REPLAY_FILE}"
if [[ "${LOAD_MEASURE_DELAY_SECS}" -gt 0 ]]; then
  sleep "${LOAD_MEASURE_DELAY_SECS}"
fi
load_start_cpu_ns="$(vm_prop CPUUsageNSec)"
load_start_mem_bytes="$(vm_prop MemoryCurrent)"
load_start_peak_bytes="$(vm_prop MemoryPeak)"

sleep "${LOAD_WINDOW_SECS}"

load_end_cpu_ns="$(vm_prop CPUUsageNSec)"
load_end_mem_bytes="$(vm_prop MemoryCurrent)"
load_end_peak_bytes="$(vm_prop MemoryPeak)"


echo "[4/5] collecting false-positive counts after replay cleanup"
clear_replay_path
if [[ "${FALSE_POSITIVE_WINDOW_SECS}" -gt 0 ]]; then
  echo "  waiting ${FALSE_POSITIVE_WINDOW_SECS}s quiet window before counting"
  sleep "${FALSE_POSITIVE_WINDOW_SECS}"
fi

from_utc="$(date -u -d "${FALSE_POSITIVE_WINDOW_SECS} seconds ago" '+%Y-%m-%d %H:%M:%S')"
from_utc_enc="$(urlencode "${from_utc}")"

count_total="$(ssh_api "curl -fsS '${API_BASE_URL}/api/v1/endpoint-events?agent_id=${AGENT_ID}&date_from=${from_utc_enc}&per_page=1' | jq -r '.total'")"
count_high="$(ssh_api "curl -fsS '${API_BASE_URL}/api/v1/endpoint-events?agent_id=${AGENT_ID}&date_from=${from_utc_enc}&severity=high&per_page=1' | jq -r '.total'")"
count_critical="$(ssh_api "curl -fsS '${API_BASE_URL}/api/v1/endpoint-events?agent_id=${AGENT_ID}&date_from=${from_utc_enc}&severity=critical&per_page=1' | jq -r '.total'")"
count_medium="$(ssh_api "curl -fsS '${API_BASE_URL}/api/v1/endpoint-events?agent_id=${AGENT_ID}&date_from=${from_utc_enc}&severity=medium&per_page=1' | jq -r '.total'")"
count_info="$(ssh_api "curl -fsS '${API_BASE_URL}/api/v1/endpoint-events?agent_id=${AGENT_ID}&date_from=${from_utc_enc}&severity=info&per_page=1' | jq -r '.total'")"


echo "[5/5] validating cleanup state + writing artifact"
env_line="$(vm_prop Environment)"
cleanup_ok=true
if [[ "${env_line}" == *"EGUARD_EBPF_REPLAY_PATH="* ]]; then
  cleanup_ok=false
fi

python3 - <<PY
import json
import math
from statistics import mean, median
from pathlib import Path

samples_path = Path(${SAMPLES_JSONL@Q})
out_path = Path(${OUT_JSON@Q})
out_latest_path = Path(${OUT_LATEST_JSON@Q})

samples = []
if samples_path.exists():
    for line in samples_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        samples.append(json.loads(line))

ok_samples = [s for s in samples if s.get("status") == "ok"]
lat_values = [int(s["e2e_ms"]) for s in ok_samples]
ingest_values = [int(s["ingest_delay_s"]) for s in ok_samples]

def pct_or_zero(values, q):
    if not values:
        return 0
    ordered = sorted(values)
    idx = max(0, min(len(ordered)-1, math.ceil((q/100)*len(ordered)) - 1))
    return int(ordered[idx])

idle_start_cpu = int(${idle_start_cpu_ns})
idle_end_cpu = int(${idle_end_cpu_ns})
idle_window = max(1, int(${IDLE_WINDOW_SECS}))
idle_cpu_pct = ((idle_end_cpu - idle_start_cpu) / 1_000_000_000) / idle_window * 100.0

load_start_cpu = int(${load_start_cpu_ns})
load_end_cpu = int(${load_end_cpu_ns})
load_window = max(1, int(${LOAD_WINDOW_SECS}))
load_cpu_pct = ((load_end_cpu - load_start_cpu) / 1_000_000_000) / load_window * 100.0

artifact = {
    "suite": "benign_edr_benchmark",
    "recorded_at_utc": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "inputs": {
        "vm_host": ${VM_HOST@Q},
        "api_host": ${API_HOST@Q},
        "api_base_url": ${API_BASE_URL@Q},
        "agent_id": ${AGENT_ID@Q},
        "samples_requested": int(${SAMPLES}),
        "latency_timeout_secs": int(${LATENCY_TIMEOUT_SECS}),
        "latency_poll_interval_secs": int(${LATENCY_POLL_INTERVAL_SECS}),
        "latency_query_per_page": int(${LATENCY_QUERY_PER_PAGE}),
        "idle_window_secs": int(${IDLE_WINDOW_SECS}),
        "load_window_secs": int(${LOAD_WINDOW_SECS}),
        "warmup_secs": int(${WARMUP_SECS}),
        "false_positive_window_secs": int(${FALSE_POSITIVE_WINDOW_SECS}),
        "load_event_count": int(${LOAD_EVENT_COUNT}),
        "load_event_spacing_ns": int(${LOAD_EVENT_SPACING_NS}),
        "load_measure_delay_secs": int(${LOAD_MEASURE_DELAY_SECS}),
    },
    "latency": {
        "samples": samples,
        "summary": {
            "ok_samples": len(ok_samples),
            "not_found_samples": len(samples) - len(ok_samples),
            "e2e_ms_mean": round(mean(lat_values), 2) if lat_values else 0,
            "e2e_ms_median": int(median(lat_values)) if lat_values else 0,
            "e2e_ms_p95": pct_or_zero(lat_values, 95),
            "ingest_delay_s_mean": round(mean(ingest_values), 2) if ingest_values else 0,
            "ingest_delay_s_p95": pct_or_zero(ingest_values, 95),
        },
    },
    "resource": {
        "idle": {
            "window_secs": idle_window,
            "cpu_usage_ns_start": idle_start_cpu,
            "cpu_usage_ns_end": idle_end_cpu,
            "cpu_avg_percent": round(idle_cpu_pct, 2),
            "memory_bytes_start": int(${idle_start_mem_bytes}),
            "memory_bytes_end": int(${idle_end_mem_bytes}),
            "memory_peak_bytes_end": int(${idle_end_peak_bytes}),
        },
        "load": {
            "window_secs": load_window,
            "cpu_usage_ns_start": load_start_cpu,
            "cpu_usage_ns_end": load_end_cpu,
            "cpu_avg_percent": round(load_cpu_pct, 2),
            "memory_bytes_start": int(${load_start_mem_bytes}),
            "memory_bytes_end": int(${load_end_mem_bytes}),
            "memory_peak_bytes_end": int(${load_end_peak_bytes}),
        },
    },
    "false_positive_window": {
        "from_utc": ${from_utc@Q},
        "counts": {
            "all": int(${count_total}),
            "high": int(${count_high}),
            "critical": int(${count_critical}),
            "medium": int(${count_medium}),
            "info": int(${count_info}),
        },
    },
    "cleanup": {
        "replay_env_cleared": (${cleanup_ok@Q}.lower() == "true"),
        "final_environment": ${env_line@Q},
    },
}

out_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
out_latest_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
print(out_path)
PY

rm -f "${SAMPLES_JSONL}"
trap - EXIT
cleanup

echo "wrote benchmark artifact: ${OUT_JSON}"
echo "updated latest artifact: ${OUT_LATEST_JSON}"
