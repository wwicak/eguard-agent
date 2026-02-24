#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/release-profile-opt"
OUT_JSON="${OUT_DIR}/metrics.json"
PGO_ENABLED="${EGUARD_ENABLE_PGO:-0}"
BOLT_ENABLED="${EGUARD_ENABLE_BOLT:-0}"

mkdir -p "${OUT_DIR}"
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

START_NS="$(date +%s%N)"
cargo build --release -p agent-core --features platform-linux/ebpf-libbpf
END_NS="$(date +%s%N)"
BASELINE_BUILD_MS="$(( (END_NS - START_NS) / 1000000 ))"

LLVM_PROFDATA_AVAILABLE=false
if command -v llvm-profdata >/dev/null 2>&1; then
  LLVM_PROFDATA_AVAILABLE=true
fi

LLVM_BOLT_AVAILABLE=false
if command -v llvm-bolt >/dev/null 2>&1; then
  LLVM_BOLT_AVAILABLE=true
fi

PGO_STATUS="disabled"
if [[ "${PGO_ENABLED}" == "1" ]]; then
  if [[ "${LLVM_PROFDATA_AVAILABLE}" != "true" ]]; then
    echo "PGO requested but llvm-profdata is unavailable"
    exit 1
  fi

  PGO_DIR="${OUT_DIR}/pgo"
  rm -rf "${PGO_DIR}"
  mkdir -p "${PGO_DIR}/raw"

  RUSTFLAGS="-Cprofile-generate=${PGO_DIR}/raw -Clto=thin" cargo build --release -p agent-core --features platform-linux/ebpf-libbpf
  ./target/release/agent-core --help >/dev/null 2>&1 || true
  llvm-profdata merge -o "${PGO_DIR}/default.profdata" "${PGO_DIR}"/raw/*.profraw
  RUSTFLAGS="-Cprofile-use=${PGO_DIR}/default.profdata -Clto=thin" cargo build --release -p agent-core --features platform-linux/ebpf-libbpf
  PGO_STATUS="applied"
fi

BOLT_STATUS="disabled"
if [[ "${BOLT_ENABLED}" == "1" ]]; then
  if [[ "${LLVM_BOLT_AVAILABLE}" != "true" ]]; then
    echo "BOLT requested but llvm-bolt is unavailable"
    exit 1
  fi
  BOLT_STATUS="available_not_applied"
fi

cat > "${OUT_JSON}" <<EOF
{
  "suite": "release_profile_opt",
  "recorded_at_utc": "${NOW_UTC}",
  "baseline_release_build_ms": ${BASELINE_BUILD_MS},
  "lto_mode": "thin",
  "pgo": {
    "enabled": ${PGO_ENABLED},
    "status": "${PGO_STATUS}",
    "llvm_profdata_available": ${LLVM_PROFDATA_AVAILABLE}
  },
  "bolt": {
    "enabled": ${BOLT_ENABLED},
    "status": "${BOLT_STATUS}",
    "llvm_bolt_available": ${LLVM_BOLT_AVAILABLE}
  }
}
EOF

echo "wrote release profile optimization metrics to ${OUT_JSON}"
