#!/bin/sh
set -e

mkdir -p /tmp/eguard-bundle /root/.ssh /etc

echo "root:*:19700:0:99999:7:::" > /etc/shadow
cat <<'EOF' > /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
ZWd1YXJkLXRlc3Qta2V5
-----END OPENSSH PRIVATE KEY-----
EOF

/bin/busybox sleep 30 >/dev/null 2>&1 &
stub_pid=$!

cat > /tmp/replay.ndjson <<EOF
{"event_type":"file_open","pid":$stub_pid,"uid":1000,"ts_ns":1000000,"file_path":"/etc/shadow","flags":0,"mode":0}
{"event_type":"file_open","pid":$stub_pid,"uid":1000,"ts_ns":2000000,"file_path":"/root/.ssh/id_rsa","flags":0,"mode":0}
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

sleep 20

if ! grep -q 'file_path=Some("/etc/shadow").*killchain_credential_theft' /tmp/agent.log; then
  echo "credential theft detection for /etc/shadow not observed" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  kill "$stub_pid" 2>/dev/null || true
  exit 1
fi

if ! grep -q 'file_path=Some("/root/.ssh/id_rsa").*killchain_credential_theft' /tmp/agent.log; then
  echo "credential theft detection for /root/.ssh/id_rsa not observed" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  kill "$stub_pid" 2>/dev/null || true
  exit 1
fi

kill "$agent_pid" 2>/dev/null || true
wait "$agent_pid" 2>/dev/null || true
kill "$stub_pid" 2>/dev/null || true

echo "agent credential theft ok"
