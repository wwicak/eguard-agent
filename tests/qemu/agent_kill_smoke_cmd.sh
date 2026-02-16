#!/bin/sh
set -e

mkdir -p /tmp/eguard-bundle/ioc /var/lib/eguard-agent/quarantine

echo "eguard-kill-smoke" > /tmp/evil.txt
hash=$(sha256sum /tmp/evil.txt | awk '{print $1}')
if [ -z "$hash" ]; then
  echo "failed to compute hash" >&2
  exit 1
fi

echo "$hash" > /tmp/eguard-bundle/ioc/hashes.txt

export EGUARD_BUNDLE_PATH=/tmp/eguard-bundle
export EGUARD_AUTONOMOUS_RESPONSE=true
export EGUARD_BASELINE_SKIP_LEARNING=1
export EGUARD_AGENT_MODE=active
export EGUARD_TRANSPORT_MODE=http
export EGUARD_SERVER_ADDR=127.0.0.1:9
export EGUARD_EBPF_REPLAY_PATH=/tmp/replay.ndjson
export EGUARD_SELF_PROTECT_ENABLE_TIMING=0
export EGUARD_SELF_PROTECT_ENABLE_TRACER_PID=0
export EGUARD_DEBUG_EVENT_LOG=1
export RUST_LOG=info

/bin/busybox tail -f /tmp/evil.txt >/dev/null 2>&1 &
evil_pid=$!

cat > /tmp/replay.ndjson <<EOF
{"event_type":"file_open","pid":$evil_pid,"uid":0,"ts_ns":0,"file_path":"/tmp/evil.txt","flags":0,"mode":0}
EOF

/payload/bin/agent-core >/tmp/agent.log 2>&1 &
agent_pid=$!

sleep 5

if kill -0 "$evil_pid" 2>/dev/null; then
  echo "evil process still running" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  exit 1
fi

if [ ! -f "/var/lib/eguard-agent/quarantine/$hash" ]; then
  echo "quarantine file missing" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  exit 1
fi

kill "$agent_pid" 2>/dev/null || true
wait "$agent_pid" 2>/dev/null || true

echo "agent kill smoke ok"
