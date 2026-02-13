#!/usr/bin/env bash
set -euo pipefail

# Contract checks for anti-tamper/self-protection policy wiring.
cat conf/self_protection.conf.example >/dev/null

# Integrity acceleration via Zig FFI contract.
rg -n "integrity.zig|integrity_check_sha256" crates/crypto-accel/build.rs crates/crypto-accel/src/lib.rs >/dev/null

# Capability and prctl/seccomp policy file presence.
rg -n "CAP_BPF|CAP_SYS_ADMIN|CAP_NET_ADMIN|CAP_DAC_READ_SEARCH" conf/self_protection.conf.example >/dev/null
rg -n "set_dumpable|set_ptracer_any|whitelist" conf/self_protection.conf.example >/dev/null

# Offline buffer and FIFO policy contract.
rg -n "offline-events.db|cap_mb = 100" conf/agent.conf.example >/dev/null
