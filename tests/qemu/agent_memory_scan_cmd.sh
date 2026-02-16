#!/bin/sh
set -e

mkdir -p /tmp/eguard-bundle

cp /payload/bin/memory_scan_stub /tmp/memory_scan_stub
chmod +x /tmp/memory_scan_stub
/tmp/memory_scan_stub >/tmp/memory_stub.log 2>&1 &
scan_pid=$!
rm -f /tmp/memory_scan_stub

: > /tmp/replay.ndjson

export EGUARD_BUNDLE_PATH=/tmp/eguard-bundle
export EGUARD_AUTONOMOUS_RESPONSE=false
export EGUARD_BASELINE_SKIP_LEARNING=1
export EGUARD_AGENT_MODE=active
export EGUARD_TRANSPORT_MODE=http
export EGUARD_SERVER_ADDR=127.0.0.1:9
export EGUARD_EBPF_REPLAY_PATH=/tmp/replay.ndjson
export EGUARD_MEMORY_SCAN_ENABLED=true
export EGUARD_MEMORY_SCAN_INTERVAL_SECS=1
export EGUARD_MEMORY_SCAN_MODE=all
export EGUARD_MEMORY_SCAN_MAX_PIDS=4
export EGUARD_SELF_PROTECT_ENABLE_TIMING=0
export EGUARD_SELF_PROTECT_ENABLE_TRACER_PID=0
export EGUARD_SELF_PROTECT_DROP_CAPS=false
export EGUARD_SELF_PROTECT_RESTRICT_PTRACE=false
export EGUARD_DEBUG_EVENT_LOG=1
export RUST_LOG=info
export RUST_LOG_STYLE=never
export NO_COLOR=1

/payload/bin/agent-core >/tmp/agent.log 2>&1 &
agent_pid=$!

sleep 20

if ! grep -E "debug memory scan detection" /tmp/agent.log | grep -q "rule_name=eguard_shellcode_marker"; then
  echo "memory scan detection not observed" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  kill "$scan_pid" 2>/dev/null || true
  exit 1
fi

kill "$agent_pid" 2>/dev/null || true
wait "$agent_pid" 2>/dev/null || true
kill "$scan_pid" 2>/dev/null || true

echo "agent memory scan ok"
