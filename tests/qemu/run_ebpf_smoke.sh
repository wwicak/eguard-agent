#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo_root"

if ! command -v zig >/dev/null 2>&1; then
  echo "zig is required for eBPF artifacts" >&2
  exit 1
fi

zig build ebpf-artifacts

cargo build -p platform-linux --features ebpf-libbpf --bin ebpf_smoke

objects_dir="$repo_root/zig-out/ebpf"
if [[ ! -d "$objects_dir" ]]; then
  echo "missing ebpf objects dir: $objects_dir" >&2
  exit 1
fi

binary="$repo_root/target/debug/ebpf_smoke"
if [[ ! -x "$binary" ]]; then
  echo "missing ebpf_smoke binary: $binary" >&2
  exit 1
fi

"$repo_root/tests/qemu/run_qemu_command.sh" "$binary" \
  --objects-dir "/host$objects_dir" \
  --duration-ms 2500 \
  --min-process-exec 1
