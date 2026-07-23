#!/bin/bash
# Use zig as a C/C++ compiler/linker.
# This ensures the resulting binary is compatible with a minimum glibc version.
#
# Default target: the host Linux ABI. Override with EGUARD_ZIG_TARGET when
# producing a deliberately cross-targeted build.
#
# eBPF builds use the runner's dynamic libelf/libz so the linker and glibc
# ABI remain consistent with the Ubuntu runner image.

ZIG_TARGET="${EGUARD_ZIG_TARGET:-x86_64-linux-gnu}"

EXTRA_ARGS=()

# Add system library search paths
for dir in /usr/lib/x86_64-linux-gnu /usr/lib64 /lib/x86_64-linux-gnu /lib64; do
    [ -d "$dir" ] && EXTRA_ARGS+=("-L$dir")
done

# Force static linking of libelf and libz to avoid inheriting their
# Do not force libelf/libz static. Ubuntu's static libelf is compiled against
# the runner's newer glibc and can reference __isoc23_* symbols that are not
# available when linking against Zig's older glibc target. Dynamic linking is
# correct for this CI benchmark, which runs on the same Ubuntu image.
exec "${ZIG:-zig}" cc -target "${ZIG_TARGET}" "${EXTRA_ARGS[@]}" "$@"
