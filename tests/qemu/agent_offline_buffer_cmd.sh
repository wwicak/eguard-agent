#!/bin/sh
set -e

mkdir -p /tmp/eguard-bundle /var/lib/eguard-agent
rm -f /var/lib/eguard-agent/offline-events.db

cat > /tmp/replay.ndjson <<EOF
{"event_type":"process_exec","pid":6101,"uid":0,"ts_ns":1000000,"ppid":1,"comm":"bash","path":"/usr/bin/bash","cmdline":"bash -c echo offline1","cgroup_id":0}
{"event_type":"process_exec","pid":6102,"uid":0,"ts_ns":2000000,"ppid":1,"comm":"bash","path":"/usr/bin/bash","cmdline":"bash -c echo offline2","cgroup_id":0}
EOF

export EGUARD_BUNDLE_PATH=/tmp/eguard-bundle
export EGUARD_AUTONOMOUS_RESPONSE=false
export EGUARD_BASELINE_SKIP_LEARNING=1
export EGUARD_AGENT_MODE=degraded
export EGUARD_TRANSPORT_MODE=http
export EGUARD_SERVER_ADDR=127.0.0.1:8081
export EGUARD_EBPF_REPLAY_PATH=/tmp/replay.ndjson
export EGUARD_SELF_PROTECT_ENABLE_TIMING=0
export EGUARD_SELF_PROTECT_ENABLE_TRACER_PID=0
export EGUARD_DEBUG_OFFLINE_LOG=1
export RUST_LOG=info
export RUST_LOG_STYLE=never
export NO_COLOR=1

/payload/bin/agent-core >/tmp/agent_degraded.log 2>&1 &
agent_pid=$!

sleep 8
kill "$agent_pid" 2>/dev/null || true
wait "$agent_pid" 2>/dev/null || true

if ! grep -q "server unavailable, buffered event" /tmp/agent_degraded.log; then
  echo "offline buffer did not record events" >&2
  echo "--- degraded log ---" >&2
  cat /tmp/agent_degraded.log >&2 || true
  exit 1
fi

/payload/bin/http_stub >/tmp/server.log 2>&1 &
server_pid=$!

sleep 1

cat > /tmp/replay_flush.ndjson <<EOF
{"event_type":"process_exec","pid":6201,"uid":0,"ts_ns":3000000,"ppid":1,"comm":"bash","path":"/usr/bin/bash","cmdline":"bash -c echo flush","cgroup_id":0}
EOF

export EGUARD_AGENT_MODE=active
export EGUARD_EBPF_REPLAY_PATH=/tmp/replay_flush.ndjson

/payload/bin/agent-core >/tmp/agent_flush.log 2>&1 &
flush_pid=$!

sleep 8

if ! grep -q "offline buffer flushed" /tmp/agent_flush.log; then
  echo "offline buffer flush not observed" >&2
  echo "--- flush log ---" >&2
  cat /tmp/agent_flush.log >&2 || true
  if [ -f /tmp/server.log ]; then
    echo "--- server log ---" >&2
    cat /tmp/server.log >&2 || true
  fi
  kill "$flush_pid" 2>/dev/null || true
  kill "$server_pid" 2>/dev/null || true
  exit 1
fi

if ! grep -q "pending_after=0" /tmp/agent_flush.log; then
  echo "offline buffer pending_after=0 not observed" >&2
  echo "--- flush log ---" >&2
  cat /tmp/agent_flush.log >&2 || true
  if [ -f /tmp/server.log ]; then
    echo "--- server log ---" >&2
    cat /tmp/server.log >&2 || true
  fi
  kill "$flush_pid" 2>/dev/null || true
  kill "$server_pid" 2>/dev/null || true
  exit 1
fi

kill "$flush_pid" 2>/dev/null || true
wait "$flush_pid" 2>/dev/null || true
kill "$server_pid" 2>/dev/null || true

echo "agent offline buffer ok"
