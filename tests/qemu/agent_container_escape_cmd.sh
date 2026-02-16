#!/bin/sh
set -e

mkdir -p /tmp/eguard-bundle

container_id=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
cg_root=/sys/fs/cgroup
cg_path="$cg_root/docker/$container_id"
mkdir -p "$cg_path"

/bin/busybox sleep 30 >/dev/null 2>&1 &
stub_pid=$!

echo "$stub_pid" > "$cg_path/cgroup.procs"

cat > /tmp/replay.ndjson <<EOF
{"event_type":"process_exec","pid":$stub_pid,"uid":0,"ts_ns":1000000,"ppid":1,"comm":"sleep","path":"/bin/busybox","cmdline":"/bin/busybox sleep 30","cgroup_id":0}
EOF

export EGUARD_BUNDLE_PATH=/tmp/eguard-bundle
export EGUARD_AUTONOMOUS_RESPONSE=false
export EGUARD_BASELINE_SKIP_LEARNING=1
export EGUARD_AGENT_MODE=active
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

sleep 10

if ! grep -q "killchain_container_escape" /tmp/agent.log; then
  echo "container escape detection not observed" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  kill "$stub_pid" 2>/dev/null || true
  exit 1
fi

if ! grep -q "killchain_container_privileged" /tmp/agent.log; then
  echo "privileged container detection not observed" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  kill "$stub_pid" 2>/dev/null || true
  exit 1
fi

kill "$agent_pid" 2>/dev/null || true
wait "$agent_pid" 2>/dev/null || true
kill "$stub_pid" 2>/dev/null || true

rmdir "$cg_path" 2>/dev/null || true

echo "agent container escape ok"
