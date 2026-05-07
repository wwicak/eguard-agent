#!/bin/bash
# Use zig as a C/C++ compiler/linker.
#
# Default target: x86_64-linux-gnu.
# Override: EGUARD_ZIG_TARGET=x86_64-linux-gnu cargo build ...
#
# EGUARD_GLIBC_TARGET is kept for CI compatibility but Zig 0.14+ rejects
# glibc-version suffixes in -target (for example, .2.31).
#
# For eBPF builds that link -lelf -lz, static versions of these libraries
# are used so the binary doesn't inherit the build host's newer glibc
# requirement from its shared libelf/libz.

GLIBC_TARGET="${EGUARD_GLIBC_TARGET:-2.31}"
ZIG_BIN="${ZIG:-zig}"
ZIG_TARGET="${EGUARD_ZIG_TARGET:-x86_64-linux-gnu}"

if ! command -v "${ZIG_BIN}" >/dev/null 2>&1; then
    echo "zig-cc.sh: Zig compiler not found on PATH; install Zig or set ZIG=/path/to/zig" >&2
    exit 127
fi

EXTRA_ARGS=()

# Add system library search paths
for dir in /usr/lib/x86_64-linux-gnu /usr/lib64 /lib/x86_64-linux-gnu /lib64; do
    [ -d "$dir" ] && EXTRA_ARGS+=("-L$dir")
done

# Force static linking of libelf and libz to avoid inheriting their
# glibc floor from the build host's shared libraries.
# Pass-through: convert -lelf → -Bstatic -lelf -Bdynamic (and same for -lz)
REWRITTEN_ARGS=()
for arg in "$@"; do
    case "$arg" in
        -lelf) REWRITTEN_ARGS+=("-Wl,-Bstatic" "-lelf" "-Wl,-Bdynamic") ;;
        -lz)   REWRITTEN_ARGS+=("-Wl,-Bstatic" "-lz" "-Wl,-Bdynamic") ;;
        *)     REWRITTEN_ARGS+=("$arg") ;;
    esac
done

exec "${ZIG_BIN}" cc -target "${ZIG_TARGET}" "${EXTRA_ARGS[@]}" "${REWRITTEN_ARGS[@]}"
