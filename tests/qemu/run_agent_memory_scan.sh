#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo_root"

if ! command -v zig >/dev/null 2>&1; then
  echo "zig is required for eBPF artifacts" >&2
  exit 1
fi

zig build ebpf-artifacts

cargo build -p agent-core --features platform-linux/ebpf-libbpf

agent_bin="$repo_root/target/debug/agent-core"
if [[ ! -x "$agent_bin" ]]; then
  echo "missing agent-core binary: $agent_bin" >&2
  exit 1
fi

stub_bin="$repo_root/target/memory_scan_stub"
zig cc -target x86_64-linux-gnu -mcpu=baseline "$repo_root/tests/qemu/memory_scan_stub.c" -O2 -o "$stub_bin"

export QEMU_EXTRA_BINARIES="$agent_bin:$stub_bin"

"$repo_root/tests/qemu/run_qemu_command.sh" "$repo_root/tests/qemu/agent_memory_scan_cmd.sh"
