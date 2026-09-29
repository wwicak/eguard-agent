#!/usr/bin/env bash
# Run after cargo builds platform-linux (provides the vendored libbpf archive).
set -euo pipefail
cd "$(dirname "$0")/.."
btf="${1:?usage: test_ebpf_generation_core.sh /path/to/linux-5.4.btf}"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
target="${CARGO_TARGET_DIR:-$PWD/target}"
# Use the crate version from the lockfile, not an arbitrary cached source.
version=$(awk '/name = "libbpf-sys"/{getline; gsub(/"/, "", $3); print $3; exit}' Cargo.lock)
source_dir=$(find "$cargo_home/registry/src" -path "*/libbpf-sys-$version/libbpf/src" -type d -print -quit)
archive=$(find "$target" -path '*/build/libbpf-sys-*/out/libbpf.a' -print -quit)
: "${source_dir:?build platform-linux first}"
: "${archive:?build platform-linux first}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cc -I "$(dirname "$archive")/include" -I "$source_dir" \
    zig/ebpf/tests/core_generation.c "$archive" -lelf -lz -o "$work/core-generation"
for object in zig-out/ebpf/*.o zig-out/ebpf-perf/*.o; do
    "$work/core-generation" "$object" "$btf"
done
