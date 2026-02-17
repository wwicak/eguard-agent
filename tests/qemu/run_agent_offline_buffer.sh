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

http_stub_src="$repo_root/tests/qemu/http_stub.c"
http_stub_bin="$repo_root/target/debug/http_stub"
zig cc -O2 -target x86_64-linux-gnu -mcpu=baseline -o "$http_stub_bin" "$http_stub_src"

export QEMU_EXTRA_BINARIES="$agent_bin:$http_stub_bin"

"$repo_root/tests/qemu/run_qemu_command.sh" "$repo_root/tests/qemu/agent_offline_buffer_cmd.sh"
