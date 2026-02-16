#!/bin/sh
set -e

mkdir -p /tmp/eguard-bundle

if [ ! -x /payload/bin/qemu_process_stub ]; then
  echo "missing qemu_process_stub" >&2
  exit 1
fi

cp /payload/bin/qemu_process_stub /tmp/nginx
cp /payload/bin/qemu_process_stub /tmp/bash
chmod +x /tmp/nginx /tmp/bash

/tmp/nginx --spawn /tmp/bash /tmp/bash /tmp/bash1.pid /tmp/bash2.pid &
nginx_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if [ -s /tmp/bash1.pid ] && [ -s /tmp/bash2.pid ]; then
    break
  fi
  sleep 0.2
done

if [ ! -s /tmp/bash1.pid ] || [ ! -s /tmp/bash2.pid ]; then
  echo "child pid files missing" >&2
  exit 1
fi

bash_pid=$(cat /tmp/bash1.pid)
bash2_pid=$(cat /tmp/bash2.pid)

cat > /tmp/replay.ndjson <<EOF
{"event_type":"process_exec","pid":$bash_pid,"uid":0,"ts_ns":0,"ppid":$nginx_pid,"comm":"bash","path":"/tmp/bash","cmdline":"/tmp/bash 20","cgroup_id":0}
{"event_type":"tcp_connect","pid":$bash2_pid,"uid":0,"ts_ns":0,"ppid":$nginx_pid,"dst_port":9001,"dst_ip":"203.0.113.20","src_port":45678,"src_ip":"198.51.100.20"}
EOF

export EGUARD_BUNDLE_PATH=/tmp/eguard-bundle
export EGUARD_AUTONOMOUS_RESPONSE=true
export EGUARD_BASELINE_SKIP_LEARNING=1
export EGUARD_AGENT_MODE=degraded
export EGUARD_TRANSPORT_MODE=http
export EGUARD_SERVER_ADDR=127.0.0.1:9
export EGUARD_EBPF_REPLAY_PATH=/tmp/replay.ndjson
export EGUARD_SELF_PROTECT_ENABLE_TIMING=0
export EGUARD_SELF_PROTECT_ENABLE_TRACER_PID=0
export EGUARD_DEBUG_EVENT_LOG=1
export RUST_LOG=info
export RUST_LOG_STYLE=never
export NO_COLOR=1

/payload/bin/agent-core >/tmp/agent.log 2>&1 &
agent_pid=$!

sleep 8

if ! grep -E "event_class=NetworkConnect.*pid=${bash2_pid}.*confidence=(High|VeryHigh)" /tmp/agent.log >/dev/null 2>&1; then
  echo "multi-pid chain not detected" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  kill "$nginx_pid" 2>/dev/null || true
  kill "$bash_pid" 2>/dev/null || true
  kill "$bash2_pid" 2>/dev/null || true
  exit 1
fi

kill "$agent_pid" 2>/dev/null || true
wait "$agent_pid" 2>/dev/null || true
kill "$nginx_pid" 2>/dev/null || true
kill "$bash_pid" 2>/dev/null || true
kill "$bash2_pid" 2>/dev/null || true

echo "agent multi-pid chain ok"
