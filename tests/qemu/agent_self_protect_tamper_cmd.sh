#!/bin/sh
set -e

mkdir -p /etc/eguard-agent
printf 'agent_id = "demo"\n' > /etc/eguard-agent/agent.conf

export EGUARD_SELF_PROTECTION_INTEGRITY_CHECK_INTERVAL_SECS=1
export EGUARD_AUTONOMOUS_RESPONSE=false
export EGUARD_AGENT_MODE=active
export EGUARD_TRANSPORT_MODE=http
export EGUARD_SERVER_ADDR=127.0.0.1:9
export EGUARD_SELF_PROTECT_ENABLE_TIMING=0
export EGUARD_SELF_PROTECT_ENABLE_TRACER_PID=0
export RUST_LOG=info
export RUST_LOG_STYLE=never
export NO_COLOR=1
# agent_tamper

/payload/bin/agent-core >/tmp/agent.log 2>&1 &
agent_pid=$!

sleep 3

# /proc/self/exe inside agent resolves to /proc/$agent_pid/exe
agent_exe="/proc/$agent_pid/exe"

echo "# tamper" >> /etc/eguard-agent/agent.conf
printf 'x' | dd of="$agent_exe" bs=1 seek=4 count=1 conv=notrunc 2>/dev/null

sleep 6

if ! grep -q "runtime_integrity_mismatch" /tmp/agent.log; then
  echo "runtime integrity tamper not observed" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  exit 1
fi

if ! grep -q "runtime_config_tamper" /tmp/agent.log; then
  echo "runtime config tamper not observed" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  exit 1
fi

kill "$agent_pid" 2>/dev/null || true
wait "$agent_pid" 2>/dev/null || true

echo "agent self-protect tamper harness ok"
