#!/usr/bin/env bash
set -euo pipefail

log_stage() {
  echo "[verification-suite] $(date -u +%Y-%m-%dT%H:%M:%SZ) :: $1"
}

artifact_dir="artifacts/verification-suite"
mkdir -p "$artifact_dir"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# AC-VER-023 / AC-VER-024
log_stage "cargo audit"
cargo audit
log_stage "cargo clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings

# AC-VER-052 / AC-VER-053 / AC-VER-054
log_stage "bundle signature contract gate"
bash scripts/run_bundle_signature_contract_ci.sh

# Ensure agent runtime ingests the generated signed bundle artifact.
log_stage "agent-core signed bundle ingestion contract"
bundle_fixture="${repo_root}/artifacts/bundle-signature-contract/fixture.bundle.tar.zst"
bundle_pubhex_file="${bundle_fixture}.pub.hex"
bash scripts/run_agent_bundle_ingestion_contract_ci.sh \
  --bundle "${bundle_fixture}" \
  --pubhex-file "${bundle_pubhex_file}" \
  --test-selector lifecycle::tests::load_bundle_rules_reads_ci_generated_signed_bundle
bash scripts/run_agent_bundle_ingestion_contract_ci.sh \
  --bundle "${bundle_fixture}" \
  --pubhex-file "${bundle_pubhex_file}" \
  --test-selector lifecycle::tests::load_bundle_rules_rejects_tampered_ci_generated_signed_bundle

# AC-VER-025
log_stage "cargo fuzz protobuf_parse"
cargo +nightly fuzz run protobuf_parse -- -max_total_time=30 -verbosity=0
log_stage "cargo fuzz detection_inputs"
cargo +nightly fuzz run detection_inputs -- -max_total_time=30 -verbosity=0

# AC-VER-026
log_stage "cargo miri setup"
cargo +nightly miri setup
log_stage "cargo miri detection tests"
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test -p detection --lib -- --test-threads=1

# AC-VER-027 build prerequisite
log_stage "cargo build release agent-core"
cargo build --release -p agent-core

# AC-VER-027 / AC-ATP-070 / AC-ATP-071
log_stage "binary hardening probe"
bash scripts/run_binary_hardening_gate_ci.sh target/release/agent-core

# AC-VER-028 / AC-ATP-043
log_stage "strace process/network probe"
if command -v strace >/dev/null 2>&1; then
  strace_log="$artifact_dir/strace-$(date -u +%Y%m%dT%H%M%SZ).log"
  timeout 60 strace -f -e trace=%process,%network ./target/release/agent-core --help >/dev/null 2>"$strace_log" || true
  echo "[verification-suite] strace output captured: $strace_log"
else
  echo "[verification-suite] strace unavailable; skipping AC-VER-028 trace probe"
fi

# AC-VER-029 / AC-ATP-082 / AC-ATP-083 / AC-ATP-084 / AC-ATP-085 / AC-ATP-086 / AC-ATP-087
log_stage "grpc-client enrollment test aliases"
cargo test -p grpc-client enrollment_rejects_expired_or_wrong_ca_certificates -- --exact
cargo test -p grpc-client client::tests::enrollment_rejects_expired_or_wrong_ca_certificates -- --exact

# AC-VER-030
log_stage "platform-linux lsm payload parse test"
cargo test -p platform-linux ebpf::tests::parses_structured_lsm_block_payload -- --exact

# Ensure sharded runtimes consume IOC indicators from threat-intel bundles.
log_stage "agent-core shard IOC reload test"
cargo test -p agent-core lifecycle::tests::reload_detection_state_from_bundle_populates_ioc_layers_on_all_shards -- --exact

# AC-VER-031 / AC-VER-032 (profiling + release profile optimization gates)
log_stage "perf profile gate"
bash scripts/run_perf_profile_gate_ci.sh
log_stage "release profile optimization gate"
bash scripts/run_release_profile_opt_ci.sh

# AC-DET-093 / AC-DET-094 (replay quality precision/recall/FAR gate)
log_stage "detection quality gate"
bash scripts/run_detection_quality_gate_ci.sh

# AC-VER-033 (sustained drop-rate pressure check)
log_stage "ebpf drop-rate pressure gate"
bash scripts/run_ebpf_drop_rate_pressure_ci.sh

log_stage "verification suite completed"
