#!/usr/bin/env bash
set -euo pipefail

# AC-VER-023 / AC-VER-024
cargo audit
cargo clippy --workspace --all-targets --all-features -- -D warnings

# AC-VER-025
cargo fuzz run protobuf_parse -- -max_total_time=30
cargo fuzz run detection_inputs -- -max_total_time=30

# AC-VER-026
cargo +nightly miri test -p detection --lib

# AC-VER-027 / AC-ATP-070 / AC-ATP-071
checksec --file target/release/agent-core

# AC-VER-028 / AC-ATP-043
strace -f -e trace=%process,%network ./target/release/agent-core --help || true

# AC-VER-029 / AC-ATP-082 / AC-ATP-083 / AC-ATP-084 / AC-ATP-085 / AC-ATP-086 / AC-ATP-087
cargo test -p grpc-client enrollment_rejects_expired_or_wrong_ca_certificates -- --exact

# AC-VER-030
cargo test -p platform-linux ebpf::tests::parses_structured_lsm_block_payload -- --exact
