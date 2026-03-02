#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

DATE_TAG="${EGUARD_PERF_DATE:-$(date -u +%Y%m%dT%H%M%SZ)}"
PLATFORM="linux"
OUT_ROOT="${EGUARD_PERF_OUT_DIR:-${ROOT_DIR}/artifacts/perf/${DATE_TAG}/${PLATFORM}}"

RUNS_PER_MODE="${EGUARD_PERF_RUNS_PER_MODE:-10}"
WARMUP_RUNS="${EGUARD_PERF_WARMUP_RUNS:-2}"
ORDER_PATTERN="${EGUARD_PERF_ORDER_PATTERN:-OFF,ON,ON,OFF}"
SCENARIOS_CSV="${EGUARD_PERF_SCENARIOS:-idle,office,build,ransomware,command-latency}"

AGENT_SERVICE="${EGUARD_AGENT_SERVICE:-eguard-agent.service}"
AGENT_PROCESS_NAME="${EGUARD_AGENT_PROCESS_NAME:-eguard-agent}"
AGENT_SETTLE_SECONDS="${EGUARD_AGENT_SETTLE_SECONDS:-2}"
SKIP_SERVICE_CONTROL="${EGUARD_PERF_SKIP_SERVICE_CONTROL:-0}"

SECTOR_SIZE_BYTES=512

log() {
  printf '[linux_phase3] %s\n' "$*"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

systemctl_run() {
  if [[ "$(id -u)" -eq 0 ]]; then
    systemctl "$@"
  else
    sudo systemctl "$@"
  fi
}

normalize_mode() {
  local m="${1^^}"
  if [[ "$m" != "ON" && "$m" != "OFF" ]]; then
    echo "invalid mode in ORDER_PATTERN: $1" >&2
    exit 2
  fi
  printf '%s' "$m"
}

split_csv() {
  local csv="$1"
  local item
  IFS=',' read -r -a _tmp <<< "$csv"
  for item in "${_tmp[@]}"; do
    item="${item## }"
    item="${item%% }"
    [[ -n "$item" ]] && printf '%s\n' "$item"
  done
}

build_warmup_sequence() {
  local count="$1"
  local -a pattern=()
  local p
  while IFS= read -r p; do
    pattern+=("$(normalize_mode "$p")")
  done < <(split_csv "$ORDER_PATTERN")

  if [[ "${#pattern[@]}" -eq 0 ]]; then
    echo "ORDER_PATTERN must not be empty" >&2
    exit 2
  fi

  local idx=0
  while (( idx < count )); do
    local mode="${pattern[$(( idx % ${#pattern[@]} ))]}"
    printf '%s\n' "$mode"
    ((idx+=1))
  done
}

build_measured_sequence() {
  local runs_per_mode="$1"
  local -a pattern=()
  local p
  while IFS= read -r p; do
    pattern+=("$(normalize_mode "$p")")
  done < <(split_csv "$ORDER_PATTERN")

  if [[ "${#pattern[@]}" -eq 0 ]]; then
    echo "ORDER_PATTERN must not be empty" >&2
    exit 2
  fi

  local on_count=0
  local off_count=0

  while (( on_count < runs_per_mode || off_count < runs_per_mode )); do
    for p in "${pattern[@]}"; do
      if [[ "$p" == "ON" && $on_count -lt $runs_per_mode ]]; then
        printf 'ON\n'
        ((on_count+=1))
      elif [[ "$p" == "OFF" && $off_count -lt $runs_per_mode ]]; then
        printf 'OFF\n'
        ((off_count+=1))
      fi

      if (( on_count >= runs_per_mode && off_count >= runs_per_mode )); then
        break 2
      fi
    done
  done
}

detect_root_disk_device() {
  local source name parent
  source="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
  if [[ -z "$source" || "$source" != /dev/* ]]; then
    printf ''
    return
  fi
  name="${source#/dev/}"
  parent="$(lsblk -no pkname "/dev/${name}" 2>/dev/null || true)"
  if [[ -n "$parent" ]]; then
    printf '%s' "$parent"
  else
    printf '%s' "$name"
  fi
}

read_cpu_counters() {
  # total_jiffies iowait_jiffies
  awk '/^cpu / {print ($2+$3+$4+$5+$6+$7+$8+$9+$10), $6; exit}' /proc/stat
}

read_disk_counters() {
  local dev="$1"
  if [[ -z "$dev" ]]; then
    printf '0 0 0 0 0 0\n'
    return
  fi
  awk -v dev="$dev" '
    $3 == dev {print $6, $10, $7, $11, $4, $8; found=1; exit}
    END { if (!found) print 0,0,0,0,0,0 }
  ' /proc/diskstats
}

agent_pid() {
  pgrep -xo "$AGENT_PROCESS_NAME" || true
}

read_agent_cpu_secs() {
  local pid="$1"
  if [[ -z "$pid" || ! -r "/proc/${pid}/stat" ]]; then
    printf ''
    return
  fi
  local hz
  hz="$(getconf CLK_TCK)"
  awk -v hz="$hz" '{printf "%.6f", (($14+$15)/hz)}' "/proc/${pid}/stat"
}

read_agent_rss_kb() {
  local pid="$1"
  if [[ -z "$pid" || ! -r "/proc/${pid}/status" ]]; then
    printf ''
    return
  fi
  awk '/^VmRSS:/ {print $2; exit}' "/proc/${pid}/status"
}

set_agent_mode() {
  local mode="$1"
  if [[ "$SKIP_SERVICE_CONTROL" == "1" ]]; then
    return
  fi
  if [[ "$mode" == "ON" ]]; then
    systemctl_run start "$AGENT_SERVICE" >/dev/null 2>&1 || true
  else
    systemctl_run stop "$AGENT_SERVICE" >/dev/null 2>&1 || true
  fi
  sleep "$AGENT_SETTLE_SECONDS"
}

run_command_latency_workload() {
  python3 - <<'PY'
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

base = os.getenv('EGUARD_PERF_COMMAND_LATENCY_BASE_URL', '').strip().rstrip('/')
agent_id = os.getenv('EGUARD_PERF_COMMAND_LATENCY_AGENT_ID', '').strip()
token = os.getenv('EGUARD_PERF_COMMAND_LATENCY_BEARER', '').strip()
timeout_s = float(os.getenv('EGUARD_PERF_COMMAND_LATENCY_TIMEOUT_S', '30'))
poll_s = float(os.getenv('EGUARD_PERF_COMMAND_LATENCY_POLL_S', '1.5'))

if not base or not agent_id:
    time.sleep(0.25)
    raise SystemExit(0)

headers = {'Content-Type': 'application/json'}
if token:
    headers['Authorization'] = f'Bearer {token}'

payload = {
    'agent_id': agent_id,
    'command_type': 'scan',
    'command_data': {
        'quick': True,
        'reason': 'phase3-command-latency'
    }
}

enqueue_url = f"{base}/api/v1/endpoint-command/enqueue"
req = urllib.request.Request(enqueue_url, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')

try:
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        body = resp.read().decode('utf-8', errors='replace')
except Exception:
    time.sleep(0.25)
    raise SystemExit(0)

try:
    parsed = json.loads(body)
except Exception:
    time.sleep(0.25)
    raise SystemExit(0)

command_id = parsed.get('command_id') or parsed.get('id')
if not command_id:
    time.sleep(0.25)
    raise SystemExit(0)

status_url = f"{base}/api/v1/endpoint/commands?agent_id={urllib.parse.quote(agent_id)}&limit=100"
deadline = time.time() + timeout_s
terminal = {'completed', 'failed', 'timeout'}

while time.time() < deadline:
    req = urllib.request.Request(status_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            body = resp.read().decode('utf-8', errors='replace')
        parsed = json.loads(body)
    except Exception:
        time.sleep(poll_s)
        continue

    rows = []
    if isinstance(parsed, dict):
        if isinstance(parsed.get('commands'), list):
            rows = parsed['commands']
        elif isinstance(parsed.get('items'), list):
            rows = parsed['items']

    for row in rows:
        if isinstance(row, dict) and row.get('command_id') == command_id:
            status = str(row.get('status', '')).lower()
            if status in terminal:
                raise SystemExit(0)
    time.sleep(poll_s)

raise SystemExit(0)
PY
}

run_workload() {
  local scenario="$1"
  local scenario_upper custom_var custom_cmd
  scenario_upper="${scenario^^}"
  scenario_upper="${scenario_upper//-/_}"
  custom_var="EGUARD_PERF_SCENARIO_${scenario_upper}_CMD"
  custom_cmd="${!custom_var:-}"

  if [[ -n "$custom_cmd" ]]; then
    bash -lc "$custom_cmd"
    return
  fi

  case "$scenario" in
    idle)
      sleep "${EGUARD_PERF_IDLE_SECONDS:-300}"
      ;;
    office)
      python3 - <<'PY'
import os
import pathlib
import shutil

base = pathlib.Path('/tmp/eguard-perf-office')
if base.exists():
    shutil.rmtree(base)
base.mkdir(parents=True, exist_ok=True)

count = int(os.getenv('EGUARD_PERF_OFFICE_FILES', '2000'))
size = int(os.getenv('EGUARD_PERF_FILE_SIZE_BYTES', '4096'))
payload = b'A' * size

for i in range(count):
    p = base / f'doc-{i:05d}.txt'
    p.write_bytes(payload)

for i in range(0, count, 3):
    p = base / f'doc-{i:05d}.txt'
    _ = p.read_bytes()

for i in range(0, count, 2):
    p = base / f'doc-{i:05d}.txt'
    p.write_bytes(payload + b'\nrev=2')

for i in range(0, count, 10):
    p = base / f'doc-{i:05d}.txt'
    tmp = base / f'doc-{i:05d}.bak'
    p.rename(tmp)
    tmp.rename(p)

shutil.rmtree(base, ignore_errors=True)
PY
      ;;
    build)
      python3 - <<'PY'
import hashlib
import os
import pathlib
import shutil

root = pathlib.Path('/tmp/eguard-perf-build')
if root.exists():
    shutil.rmtree(root)
(root / 'src').mkdir(parents=True, exist_ok=True)
(root / 'out').mkdir(parents=True, exist_ok=True)

count = int(os.getenv('EGUARD_PERF_BUILD_FILES', '3500'))
size = int(os.getenv('EGUARD_PERF_FILE_SIZE_BYTES', '4096'))
chunk = b'B' * size

for i in range(count):
    sub = root / 'src' / f'mod-{i % 64:02d}'
    sub.mkdir(parents=True, exist_ok=True)
    (sub / f'unit-{i:05d}.c').write_bytes(chunk)

for src in (root / 'src').rglob('*.c'):
    data = src.read_bytes()
    digest = hashlib.sha256(data).hexdigest().encode()
    dst = root / 'out' / src.relative_to(root / 'src')
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.with_suffix('.o').write_bytes(digest)

shutil.rmtree(root, ignore_errors=True)
PY
      ;;
    ransomware)
      python3 - <<'PY'
import os
import pathlib
import shutil

root = pathlib.Path('/tmp/eguard-perf-ransomware')
if root.exists():
    shutil.rmtree(root)
root.mkdir(parents=True, exist_ok=True)

count = int(os.getenv('EGUARD_PERF_RANSOMWARE_FILES', '6000'))
size = int(os.getenv('EGUARD_PERF_FILE_SIZE_BYTES', '4096'))
seed = b'C' * size
rewrite = b'X' * size

for i in range(count):
    p = root / f'victim-{i:05d}.dat'
    p.write_bytes(seed)

for i in range(count):
    p = root / f'victim-{i:05d}.dat'
    p.write_bytes(rewrite)
    p.rename(root / f'victim-{i:05d}.locked')

shutil.rmtree(root, ignore_errors=True)
PY
      ;;
    command-latency)
      run_command_latency_workload
      ;;
    *)
      echo "unknown scenario: ${scenario}" >&2
      exit 2
      ;;
  esac
}

append_json_line() {
  local file="$1"
  local json="$2"
  printf '%s\n' "$json" >> "$file"
}

finalize_json_array() {
  local jsonl_file="$1"
  local out_file="$2"
  python3 - "$jsonl_file" "$out_file" <<'PY'
import json
import pathlib
import sys

jsonl = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
rows = []
if jsonl.exists():
    for line in jsonl.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
out.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding='utf-8')
PY
}

need_cmd python3
need_cmd awk
need_cmd findmnt
need_cmd lsblk

mkdir -p "$OUT_ROOT"
DISK_DEVICE="$(detect_root_disk_device)"

log "date_tag=${DATE_TAG} out_root=${OUT_ROOT} runs_per_mode=${RUNS_PER_MODE} warmup_runs=${WARMUP_RUNS} disk_device=${DISK_DEVICE:-unknown}"

mapfile -t SCENARIOS < <(split_csv "$SCENARIOS_CSV")
if [[ "${#SCENARIOS[@]}" -eq 0 ]]; then
  echo "EGUARD_PERF_SCENARIOS produced no scenarios" >&2
  exit 2
fi

for scenario in "${SCENARIOS[@]}"; do
  scenario_dir="${OUT_ROOT}/${scenario}"
  mkdir -p "$scenario_dir"
  jsonl_file="${scenario_dir}/raw.jsonl"
  raw_json="${scenario_dir}/raw.json"
  : > "$jsonl_file"

  log "scenario=${scenario}: starting"

  mapfile -t warmup_seq < <(build_warmup_sequence "$WARMUP_RUNS")
  mapfile -t measured_seq < <(build_measured_sequence "$RUNS_PER_MODE")

  run_number=0
  measured_on_idx=0
  measured_off_idx=0

  for mode in "${warmup_seq[@]}" "${measured_seq[@]}"; do
    [[ -z "$mode" ]] && continue
    warmup=false
    phase="measured"
    if (( run_number < WARMUP_RUNS )); then
      warmup=true
      phase="warmup"
    fi

    set_agent_mode "$mode"

    read -r cpu_total_before iowait_before < <(read_cpu_counters)
    read -r read_sec_before write_sec_before read_ms_before write_ms_before reads_before writes_before < <(read_disk_counters "$DISK_DEVICE")

    pid_before=""
    cpu_agent_before=""
    if [[ "$mode" == "ON" ]]; then
      pid_before="$(agent_pid)"
      cpu_agent_before="$(read_agent_cpu_secs "$pid_before")"
    fi

    start_ns="$(date +%s%N)"
    run_workload "$scenario"
    end_ns="$(date +%s%N)"

    read -r cpu_total_after iowait_after < <(read_cpu_counters)
    read -r read_sec_after write_sec_after read_ms_after write_ms_after reads_after writes_after < <(read_disk_counters "$DISK_DEVICE")

    pid_after=""
    cpu_agent_after=""
    rss_kb=""
    if [[ "$mode" == "ON" ]]; then
      pid_after="$(agent_pid)"
      cpu_agent_after="$(read_agent_cpu_secs "$pid_after")"
      rss_kb="$(read_agent_rss_kb "$pid_after")"
    fi

    mode_index_json="null"
    if [[ "$warmup" == false ]]; then
      if [[ "$mode" == "ON" ]]; then
        measured_on_idx=$((measured_on_idx + 1))
        mode_index_json="$measured_on_idx"
      else
        measured_off_idx=$((measured_off_idx + 1))
        mode_index_json="$measured_off_idx"
      fi
    fi

    json_line="$(python3 - "$start_ns" "$end_ns" "$cpu_total_before" "$cpu_total_after" "$iowait_before" "$iowait_after" "$read_sec_before" "$read_sec_after" "$write_sec_before" "$write_sec_after" "$read_ms_before" "$read_ms_after" "$write_ms_before" "$write_ms_after" "$reads_before" "$reads_after" "$writes_before" "$writes_after" "$SECTOR_SIZE_BYTES" "$mode" "$scenario" "$phase" "$warmup" "$run_number" "$mode_index_json" "$cpu_agent_before" "$cpu_agent_after" "$rss_kb" "$pid_before" "$pid_after" <<'PY'
import json
import math
import sys

(
    start_ns,
    end_ns,
    cpu_total_before,
    cpu_total_after,
    iowait_before,
    iowait_after,
    read_sec_before,
    read_sec_after,
    write_sec_before,
    write_sec_after,
    read_ms_before,
    read_ms_after,
    write_ms_before,
    write_ms_after,
    reads_before,
    reads_after,
    writes_before,
    writes_after,
    sector_size,
    mode,
    scenario,
    phase,
    warmup,
    run_number,
    mode_index_json,
    cpu_agent_before,
    cpu_agent_after,
    rss_kb,
    pid_before,
    pid_after,
) = sys.argv[1:]

start_ns = int(start_ns)
end_ns = int(end_ns)

def to_int(v: str) -> int:
    try:
        return int(float(v))
    except Exception:
        return 0

def to_float(v: str):
    try:
        return float(v)
    except Exception:
        return None

cpu_total_delta = max(0, to_int(cpu_total_after) - to_int(cpu_total_before))
iowait_delta = max(0, to_int(iowait_after) - to_int(iowait_before))

read_sectors = max(0, to_int(read_sec_after) - to_int(read_sec_before))
write_sectors = max(0, to_int(write_sec_after) - to_int(write_sec_before))
read_ops = max(0, to_int(reads_after) - to_int(reads_before))
write_ops = max(0, to_int(writes_after) - to_int(writes_before))
read_ms = max(0, to_int(read_ms_after) - to_int(read_ms_before))
write_ms = max(0, to_int(write_ms_after) - to_int(write_ms_before))

io_ops = read_ops + write_ops
io_ms = read_ms + write_ms

await_ms = None
if io_ops > 0:
    await_ms = io_ms / io_ops

iowait_pct = None
if cpu_total_delta > 0:
    iowait_pct = (iowait_delta / cpu_total_delta) * 100.0

cpu_before = to_float(cpu_agent_before)
cpu_after = to_float(cpu_agent_after)
agent_cpu_delta = None
if cpu_before is not None and cpu_after is not None and cpu_after >= cpu_before:
    agent_cpu_delta = cpu_after - cpu_before

rss_val = None
if rss_kb.strip():
    try:
        rss_val = int(float(rss_kb))
    except Exception:
        rss_val = None

mode_index = None
if mode_index_json != 'null':
    try:
        mode_index = int(mode_index_json)
    except Exception:
        mode_index = None

obj = {
    'platform': 'linux',
    'scenario': scenario,
    'mode': mode,
    'phase': phase,
    'warmup': warmup.lower() == 'true',
    'run_number': int(run_number),
    'mode_run_index': mode_index,
    'elapsed_s': (end_ns - start_ns) / 1_000_000_000.0,
    'agent_cpu_s': agent_cpu_delta,
    'agent_rss_kb': rss_val,
    'cpu_iowait_pct': iowait_pct,
    'disk_await_ms': await_ms,
    'disk_read_bytes': read_sectors * int(sector_size),
    'disk_write_bytes': write_sectors * int(sector_size),
    'agent_pid_before': int(pid_before) if pid_before.strip().isdigit() else None,
    'agent_pid_after': int(pid_after) if pid_after.strip().isdigit() else None,
}
print(json.dumps(obj, sort_keys=True))
PY
)"

    append_json_line "$jsonl_file" "$json_line"
    run_number=$((run_number + 1))
  done

  finalize_json_array "$jsonl_file" "$raw_json"

  python3 - "$scenario_dir/metadata.json" "$scenario" "$RUNS_PER_MODE" "$WARMUP_RUNS" "$ORDER_PATTERN" "$AGENT_SERVICE" "$AGENT_PROCESS_NAME" "$DISK_DEVICE" <<'PY'
import json
import pathlib
import sys

out_path, scenario, runs, warmups, order, svc, proc, disk = sys.argv[1:]
obj = {
    'scenario': scenario,
    'runs_per_mode': int(runs),
    'warmup_runs': int(warmups),
    'order_pattern': order,
    'agent_service': svc,
    'agent_process_name': proc,
    'disk_device': disk or None,
}
pathlib.Path(out_path).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding='utf-8')
PY

  rm -f "$jsonl_file"
  log "scenario=${scenario}: wrote ${raw_json}"
done

log "done"
