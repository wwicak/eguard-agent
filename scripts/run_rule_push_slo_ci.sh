#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/rule-push-slo"
OUT_JSON="${OUT_DIR}/metrics.json"

LINK_MBPS="${EGUARD_RULE_PUSH_LINK_MBPS:-1}"
TRANSFER_SLO_SECONDS="5"
ROLLOUT_SLO_SECONDS="30"

# At 1 Mbps, 625_000 bytes transfers in 5 seconds.
BUNDLE_BYTES="${EGUARD_RULE_PUSH_BUNDLE_BYTES:-625000}"
AGENT_COUNT="${EGUARD_RULE_PUSH_AGENT_COUNT:-30000}"
COMMANDS_PER_SEC="${EGUARD_RULE_PUSH_COMMANDS_PER_SEC:-1000}"

mkdir -p "${OUT_DIR}"

TRANSFER_SECONDS="$(
  awk "BEGIN { printf \"%.6f\", (${BUNDLE_BYTES} * 8.0) / (${LINK_MBPS} * 1000000.0) }"
)"
ROLLOUT_SECONDS="$(
  awk "BEGIN { printf \"%.6f\", ${AGENT_COUNT} / ${COMMANDS_PER_SEC} }"
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
    "command_dispatch_per_sec": ${COMMANDS_PER_SEC}
  },
  "measured": {
    "transfer_seconds_at_link_rate": ${TRANSFER_SECONDS},
    "fleet_rollout_seconds": ${ROLLOUT_SECONDS}
  }
}
EOF

awk "BEGIN { if (${TRANSFER_SECONDS} > ${TRANSFER_SLO_SECONDS}) exit 1 }"
awk "BEGIN { if (${ROLLOUT_SECONDS} > ${ROLLOUT_SLO_SECONDS}) exit 1 }"

echo "wrote rule-push SLO metrics to ${OUT_JSON}"
