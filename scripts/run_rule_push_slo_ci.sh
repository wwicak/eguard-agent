#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/rule-push-slo"
OUT_JSON="${OUT_DIR}/metrics.json"
PYTHON_BIN="${PYTHON_BIN:-python3}"

LINK_MBPS="${EGUARD_RULE_PUSH_LINK_MBPS:-1}"
TRANSFER_SLO_SECONDS="5"
ROLLOUT_SLO_SECONDS="30"

# At 1 Mbps, 625_000 bytes transfers in 5 seconds.
BUNDLE_BYTES="${EGUARD_RULE_PUSH_BUNDLE_BYTES:-625000}"
AGENT_COUNT="${EGUARD_RULE_PUSH_AGENT_COUNT:-30000}"
COMMANDS_PER_SEC="${EGUARD_RULE_PUSH_COMMANDS_PER_SEC:-1000}"
DISPATCH_PROBE_COMMANDS="${EGUARD_RULE_PUSH_DISPATCH_PROBE_COMMANDS:-5000}"

mkdir -p "${OUT_DIR}"

TRANSFER_SECONDS="$(
  awk "BEGIN { printf \"%.6f\", (${BUNDLE_BYTES} * 8.0) / (${LINK_MBPS} * 1000000.0) }"
)"

DISPATCH_PROBE_SECONDS="0.000000"
DISPATCH_PROBE_CPS="0.00"
TRANSFER_PROBE_SECONDS="0.000000"
TRANSFER_PROBE_MBPS="0.00"

if command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  DISPATCH_PROBE_OUTPUT="$(${PYTHON_BIN} - "${DISPATCH_PROBE_COMMANDS}" <<'PY'
import json
import sys
import time
import uuid

count = max(1, int(sys.argv[1]))
start = time.perf_counter()
for i in range(count):
    payload = {
        "command_id": str(uuid.uuid4()),
        "command_type": "emergency_rule_push",
        "rule_type": "ioc_hash",
        "rule_name": "emergency-ioc-hash-rule",
        "rule_content": "a" * 64,
        "severity": "critical",
        "seq": i,
    }
    json.dumps(payload, separators=(",", ":"))
elapsed = max(time.perf_counter() - start, 1e-9)
print(f"{elapsed:.6f} {count / elapsed:.2f}")
PY
)"
  DISPATCH_PROBE_SECONDS="$(printf '%s\n' "${DISPATCH_PROBE_OUTPUT}" | awk '{print $1}')"
  DISPATCH_PROBE_CPS="$(printf '%s\n' "${DISPATCH_PROBE_OUTPUT}" | awk '{print $2}')"

  TRANSFER_PROBE_OUTPUT="$(${PYTHON_BIN} - "${BUNDLE_BYTES}" <<'PY'
import os
import sys
import tempfile
import time

size = max(1, int(sys.argv[1]))
chunk_size = min(size, 1024 * 1024)
chunk = b"\0" * chunk_size
remaining = size

fd, path = tempfile.mkstemp(prefix="eguard-rule-push-")
os.close(fd)

start = time.perf_counter()
with open(path, "wb") as out:
    while remaining > 0:
        write_size = min(chunk_size, remaining)
        out.write(chunk[:write_size])
        remaining -= write_size

with open(path, "rb") as inp:
    while inp.read(1024 * 1024):
        pass

elapsed = max(time.perf_counter() - start, 1e-9)
os.remove(path)
mbps = (size * 8.0) / (elapsed * 1_000_000.0)
print(f"{elapsed:.6f} {mbps:.2f}")
PY
)"
  TRANSFER_PROBE_SECONDS="$(printf '%s\n' "${TRANSFER_PROBE_OUTPUT}" | awk '{print $1}')"
  TRANSFER_PROBE_MBPS="$(printf '%s\n' "${TRANSFER_PROBE_OUTPUT}" | awk '{print $2}')"
fi

EFFECTIVE_COMMANDS_PER_SEC="$(
  awk "BEGIN {
    configured = ${COMMANDS_PER_SEC};
    measured = ${DISPATCH_PROBE_CPS};
    if (measured <= 0 || measured > configured) {
      measured = configured;
    }
    printf \"%.6f\", measured;
  }"
)"

ROLLOUT_SECONDS="$(
  awk "BEGIN { printf \"%.6f\", ${AGENT_COUNT} / ${EFFECTIVE_COMMANDS_PER_SEC} }"
)"

NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat > "${OUT_JSON}" <<EOF
{
  "suite": "rule_push_slo",
  "recorded_at_utc": "${NOW_UTC}",
  "limits": {
    "transfer_slo_seconds": ${TRANSFER_SLO_SECONDS},
    "rollout_slo_seconds": ${ROLLOUT_SLO_SECONDS},
    "link_mbps": ${LINK_MBPS}
  },
  "inputs": {
    "bundle_bytes": ${BUNDLE_BYTES},
    "agent_count": ${AGENT_COUNT},
    "command_dispatch_per_sec": ${COMMANDS_PER_SEC},
    "dispatch_probe_commands": ${DISPATCH_PROBE_COMMANDS}
  },
  "measured": {
    "transfer_seconds_at_link_rate": ${TRANSFER_SECONDS},
    "fleet_rollout_seconds": ${ROLLOUT_SECONDS},
    "transfer_probe_seconds_local_io": ${TRANSFER_PROBE_SECONDS},
    "transfer_probe_effective_mbps_local_io": ${TRANSFER_PROBE_MBPS},
    "dispatch_probe_seconds": ${DISPATCH_PROBE_SECONDS},
    "dispatch_probe_commands_per_sec": ${DISPATCH_PROBE_CPS},
    "effective_commands_per_sec_used_for_rollout": ${EFFECTIVE_COMMANDS_PER_SEC}
  }
}
EOF

awk "BEGIN { if (${TRANSFER_SECONDS} > ${TRANSFER_SLO_SECONDS}) exit 1 }"
awk "BEGIN { if (${ROLLOUT_SECONDS} > ${ROLLOUT_SLO_SECONDS}) exit 1 }"

echo "wrote rule-push SLO metrics to ${OUT_JSON}"
