#!/bin/bash
# Use zig as a C/C++ compiler with glibc version targeting.
# This ensures the resulting binary is compatible with a minimum glibc version.
#
# Default target: glibc 2.31 (Ubuntu 20.04+ / Debian 10+)
# Override: EGUARD_GLIBC_TARGET=2.35 cargo build ...
#
# For eBPF builds that link -lelf -lz, static versions of these libraries
# are used so the binary doesn't inherit the build host's newer glibc
# requirement from its shared libelf/libz.

GLIBC_TARGET="${EGUARD_GLIBC_TARGET:-2.31}"

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

exec zig cc -target "x86_64-linux-gnu.${GLIBC_TARGET}" "${EXTRA_ARGS[@]}" "${REWRITTEN_ARGS[@]}"
