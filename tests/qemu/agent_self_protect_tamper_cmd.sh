#!/bin/sh
set -e

mkdir -p /etc/eguard-agent
mkdir -p /tmp
printf 'agent_id = "demo"\n' > /etc/eguard-agent/agent.conf
printf 'baseline' > /tmp/agent_integrity_target

export EGUARD_SELF_PROTECTION_INTEGRITY_CHECK_INTERVAL_SECS=1
export EGUARD_AUTONOMOUS_RESPONSE=false
export EGUARD_AGENT_MODE=active
export EGUARD_TRANSPORT_MODE=http
export EGUARD_SERVER_ADDR=127.0.0.1:9
export EGUARD_SELF_PROTECT_ENABLE_TIMING=0
export EGUARD_SELF_PROTECT_ENABLE_TRACER_PID=0
export EGUARD_SELF_PROTECT_RUNTIME_INTEGRITY_PATHS="/tmp/agent_integrity_target"
export EGUARD_DEBUG_SELF_PROTECT_LOG=1
export EGUARD_SELF_PROTECT_RUN_ONCE=1
export EGUARD_SELF_PROTECT_RUN_ONCE_DELAY_SECS=6
export RUST_LOG=info
export RUST_LOG_STYLE=never
export NO_COLOR=1
# agent_tamper

/bin/stdbuf -oL -eL /payload/bin/agent-core >/tmp/agent.log 2>&1 &
agent_pid=$!

sleep 2

echo "# tamper" >> /etc/eguard-agent/agent.conf
printf 'tampered' > /tmp/agent_integrity_target

agent_status=0
wait "$agent_pid" 2>/dev/null || agent_status=$?
if [ "$agent_status" -ne 0 ]; then
  echo "agent exited with status $agent_status" >&2
  cat /tmp/agent.log >&2 || true
  exit 1
fi

if ! grep -q "runtime_integrity_mismatch" /tmp/agent.log; then
  echo "runtime integrity tamper not observed" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  exit 1
fi

if ! grep -q "runtime_config_tamper" /tmp/agent.log; then
  echo "runtime config tamper not observed" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  exit 1
fi

echo "agent self-protect tamper harness ok"
