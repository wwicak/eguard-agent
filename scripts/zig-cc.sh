#!/bin/bash
# Use zig as a C/C++ compiler with glibc version targeting.
# This ensures the resulting binary is compatible with a minimum glibc version.
#
# glibc targets:
#   - Non-eBPF builds: 2.31 (Ubuntu 20.04+)
#   - eBPF builds: 2.35 (Ubuntu 22.04+) — because libelf links against newer glibc
#
# Override: EGUARD_GLIBC_TARGET=2.35 cargo build ...
#
# Usage: Set as linker in .cargo/config.toml:
#   [target.x86_64-unknown-linux-gnu]
#   linker = "scripts/zig-cc.sh"

GLIBC_TARGET="${EGUARD_GLIBC_TARGET:-2.31}"

# Pass through system library paths so zig can find -lelf, -lz, etc.
EXTRA_ARGS=()
for dir in /usr/lib/x86_64-linux-gnu /usr/lib64 /lib/x86_64-linux-gnu /lib64; do
    [ -d "$dir" ] && EXTRA_ARGS+=("-L$dir")
done

exec zig cc -target "x86_64-linux-gnu.${GLIBC_TARGET}" "${EXTRA_ARGS[@]}" "$@"
