#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
state_dir="$root_dir/artifacts/verification-suite"

follow_mode="${1:-}"

log_path_file="$state_dir/current-run.logpath"
if [[ -f "$log_path_file" ]]; then
  log_path="$(tr -d '\n' < "$log_path_file")"
else
  log_path="$state_dir/run-latest.log"
fi

if [[ ! -f "$log_path" ]]; then
  echo "[verification-stream] no log available: $log_path" >&2
  exit 1
fi

pid_file="$state_dir/current-run.pid"
exit_file="$state_dir/current-run.exit"

status="unknown"
if [[ -f "$pid_file" ]]; then
  pid="$(tr -d '\n' < "$pid_file")"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    status="running(pid=$pid)"
  else
    status="exited(pid=${pid:-n/a})"
  fi
fi

if [[ -f "$exit_file" ]]; then
  exit_code="$(tr -d '\n' < "$exit_file")"
  status="$status exit_code=$exit_code"
fi

echo "[verification-stream] log=$log_path"
echo "[verification-stream] status=$status"

if [[ "$follow_mode" == "--follow" ]]; then
  tail -n 120 -f "$log_path"
else
  tail -n 120 "$log_path"
fi
