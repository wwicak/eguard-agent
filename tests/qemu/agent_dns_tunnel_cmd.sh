#!/bin/sh
set -e

mkdir -p /tmp/eguard-bundle

/bin/busybox sleep 30 >/dev/null 2>&1 &
probe_pid=$!

cat > /tmp/replay.ndjson <<EOF
{"event_type":"dns_query","pid":$probe_pid,"uid":0,"ts_ns":1000000,"ppid":1,"domain":"x7f3a2b9d2c7f.dynamic-dns.net","qtype":1,"qclass":1}
{"event_type":"dns_query","pid":$probe_pid,"uid":0,"ts_ns":2000000,"ppid":1,"domain":"q9x8c7v6b5n4m3l2.example.net","qtype":1,"qclass":1}
{"event_type":"dns_query","pid":$probe_pid,"uid":0,"ts_ns":3000000,"ppid":1,"domain":"m3n5b7v9c1x2z4d6.example.net","qtype":1,"qclass":1}
{"event_type":"dns_query","pid":$probe_pid,"uid":0,"ts_ns":4000000,"ppid":1,"domain":"x7f3a2b9d2c7f.dynamic-dns.net","qtype":1,"qclass":1}
{"event_type":"dns_query","pid":$probe_pid,"uid":0,"ts_ns":5000000,"ppid":1,"domain":"k9j8h7g6f5d4s3a2.example.net","qtype":1,"qclass":1}
{"event_type":"dns_query","pid":$probe_pid,"uid":0,"ts_ns":6000000,"ppid":1,"domain":"z9x8c7v6b5n4m3l2.example.net","qtype":1,"qclass":1}
{"event_type":"dns_query","pid":$probe_pid,"uid":0,"ts_ns":7000000,"ppid":1,"domain":"x7f3a2b9d2c7f.dynamic-dns.net","qtype":1,"qclass":1}
{"event_type":"dns_query","pid":$probe_pid,"uid":0,"ts_ns":8000000,"ppid":1,"domain":"q9x8c7v6b5n4m3l2.example.net","qtype":1,"qclass":1}
EOF

export EGUARD_BUNDLE_PATH=/tmp/eguard-bundle
export EGUARD_AUTONOMOUS_RESPONSE=false
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

sleep 10

if ! grep -E "event_class=DnsQuery.*confidence=(Medium|High|VeryHigh|Definite)" /tmp/agent.log >/dev/null 2>&1; then
  echo "dns tunneling detection not observed" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  kill "$probe_pid" 2>/dev/null || true
  exit 1
fi

kill "$agent_pid" 2>/dev/null || true
wait "$agent_pid" 2>/dev/null || true
kill "$probe_pid" 2>/dev/null || true

echo "agent dns tunneling ok"
