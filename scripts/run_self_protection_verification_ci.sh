#!/usr/bin/env bash
set -euo pipefail

# Contract checks for anti-tamper/self-protection policy wiring.
cat conf/self_protection.conf.example >/dev/null

find_pattern() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg -n "$pattern" "$@" >/dev/null
  else
    grep -E -n "$pattern" "$@" >/dev/null
  fi
}

# Integrity acceleration via Zig FFI contract.
find_pattern "integrity.zig|integrity_check_sha256" crates/crypto-accel/build.rs crates/crypto-accel/src/lib.rs

# Capability and prctl/seccomp policy file presence.
find_pattern "CAP_BPF|CAP_SYS_ADMIN|CAP_NET_ADMIN|CAP_DAC_READ_SEARCH" conf/self_protection.conf.example
find_pattern "set_dumpable|set_ptracer_any|whitelist" conf/self_protection.conf.example

# Offline buffer and FIFO policy contract.
find_pattern "offline-events.db|cap_mb = 100" conf/agent.conf.example
