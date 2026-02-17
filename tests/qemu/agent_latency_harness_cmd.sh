#!/bin/sh
set -e

mkdir -p /tmp/eguard-bundle

cat > /tmp/replay.ndjson <<EOF
EOF

for i in $(seq 1 60); do
  ts=$((i * 1000000))
  pid=$((5000 + i))
  echo "{\"event_type\":\"process_exec\",\"pid\":$pid,\"uid\":0,\"ts_ns\":$ts,\"ppid\":1,\"comm\":\"bash\",\"path\":\"/usr/bin/bash\",\"cmdline\":\"bash -c echo $i\",\"cgroup_id\":0}" >> /tmp/replay.ndjson
 done

export EGUARD_BUNDLE_PATH=/tmp/eguard-bundle
export EGUARD_AUTONOMOUS_RESPONSE=false
export EGUARD_BASELINE_SKIP_LEARNING=1
export EGUARD_AGENT_MODE=degraded
export EGUARD_TRANSPORT_MODE=http
export EGUARD_SERVER_ADDR=127.0.0.1:9
export EGUARD_EBPF_REPLAY_PATH=/tmp/replay.ndjson
export EGUARD_SELF_PROTECT_ENABLE_TIMING=0
export EGUARD_SELF_PROTECT_ENABLE_TRACER_PID=0
export EGUARD_DEBUG_LATENCY_LOG=1
export RUST_LOG=info
export RUST_LOG_STYLE=never
export NO_COLOR=1

/payload/bin/agent-core >/tmp/agent.log 2>&1 &
agent_pid=$!

sleep 12

grep 'debug detection latency' /tmp/agent.log \
  | awk -F 'evaluate_micros=' '{print $2}' \
  | awk '{print $1}' > /tmp/latencies_raw.txt

tail -n +6 /tmp/latencies_raw.txt > /tmp/latencies.txt

count=$(wc -l < /tmp/latencies.txt | awk '{print $1}')
if [ "$count" -lt 10 ]; then
  echo "insufficient latency samples: $count" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  exit 1
fi

sort -n /tmp/latencies.txt > /tmp/latencies_sorted.txt
p95_idx=$(( (count * 95 + 99) / 100 ))
p99_idx=$(( (count * 99 + 99) / 100 ))

p95=$(awk -v n=$p95_idx 'NR==n {print; exit}' /tmp/latencies_sorted.txt)
p99=$(awk -v n=$p99_idx 'NR==n {print; exit}' /tmp/latencies_sorted.txt)

if [ -z "$p95" ] || [ -z "$p99" ]; then
  echo "failed to compute latency percentiles" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  exit 1
fi

echo "LATENCY_P95_US=$p95"
echo "LATENCY_P99_US=$p99"

if [ "$p95" -gt 20000 ]; then
  echo "p95 latency too high: $p95" >&2
  kill "$agent_pid" 2>/dev/null || true
  exit 1
fi

if [ "$p99" -gt 30000 ]; then
  echo "p99 latency too high: $p99" >&2
  kill "$agent_pid" 2>/dev/null || true
  exit 1
fi

kill "$agent_pid" 2>/dev/null || true
wait "$agent_pid" 2>/dev/null || true

echo "agent latency harness ok"
