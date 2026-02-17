#!/bin/sh
set -e

mkdir -p /tmp/eguard-bundle
mkdir -p /tmp

cat > /tmp/replay.ndjson <<EOF
{"event_type":"process_exec","pid":5000,"uid":0,"ts_ns":500000,"comm":"bash","path":"/bin/bash","cmdline":"/bin/bash -lc whoami"}
{"event_type":"module_load","pid":5001,"uid":0,"ts_ns":1000000,"module_name":"rootkit_hide"}
EOF

export EGUARD_BUNDLE_PATH=/tmp/eguard-bundle
export EGUARD_AUTONOMOUS_RESPONSE=false
export EGUARD_BASELINE_SKIP_LEARNING=1
export EGUARD_AGENT_MODE=degraded
export EGUARD_TRANSPORT_MODE=http
export EGUARD_SERVER_ADDR=127.0.0.1:9
export EGUARD_BUFFER_BACKEND=memory
export EGUARD_EBPF_REPLAY_PATH=/tmp/replay.ndjson
export EGUARD_SELF_PROTECT_ENABLE_TIMING=0
export EGUARD_SELF_PROTECT_ENABLE_TRACER_PID=0
export EGUARD_SELF_PROTECTION_INTEGRITY_CHECK_INTERVAL_SECS=0
export EGUARD_SELF_PROTECT_LAZY_BASELINE=1
export EGUARD_DEBUG_EVENT_LOG=1
export EGUARD_DEBUG_REPLAY_LOG=1
export EGUARD_DEBUG_TICK_LOG=1
export RUST_LOG=info
export RUST_LOG_STYLE=never
export NO_COLOR=1

/payload/bin/agent-core >/tmp/agent.log 2>&1 &
agent_pid=$!

sleep 30

if ! kill -0 "$agent_pid" 2>/dev/null; then
  echo "agent exited before processing replay" >&2
  echo "--- replay file ---" >&2
  cat /tmp/replay.ndjson >&2 || true
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  exit 1
fi

if ! grep -Eq 'kernel_module_rootkit.*confidence=(High|VeryHigh|Definite)' /tmp/agent.log; then
  echo "kernel integrity indicator not observed" >&2
  echo "--- replay file ---" >&2
  cat /tmp/replay.ndjson >&2 || true
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  exit 1
fi

kill "$agent_pid" 2>/dev/null || true
wait "$agent_pid" 2>/dev/null || true

echo "agent kernel integrity harness ok"
