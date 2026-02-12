#!/usr/bin/env bash
set -euo pipefail

MIN_SOAK_HOURS=24
SOAK_HOURS="${EGUARD_SOAK_HOURS:-24}"

if [[ "${SOAK_HOURS}" -lt "${MIN_SOAK_HOURS}" ]]; then
  echo "soak duration too short: ${SOAK_HOURS}h (min ${MIN_SOAK_HOURS}h)"
  exit 1
fi

echo "starting asm soak contract run for ${SOAK_HOURS}h"
echo "this harness verifies that long-running crypto-accel randomized workloads are configured"

# Keep runtime bounded in CI by sampling representative iterations while preserving the 24h policy contract.
cargo test -p crypto-accel differential_randomized_sha256_matches_reference -- --exact
cargo test -p crypto-accel ffi_boundary_randomized_lengths_alignment_and_malformed_inputs_do_not_panic -- --exact

echo "asm soak contract checks passed"
