#!/usr/bin/env bash
set -euo pipefail

kernel="${QEMU_KERNEL:-}"
initrd="${QEMU_INITRD:-}"

if [[ -z "$kernel" ]]; then
  kernel=$(ls /boot/vmlinuz-* 2>/dev/null | sort | tail -n 1)
fi
if [[ -z "$kernel" || ! -f "$kernel" ]]; then
  echo "qemu smoke: missing kernel image" >&2
  exit 1
fi

if [[ -z "$initrd" ]]; then
  initrd="/boot/initrd.img-${kernel##*/vmlinuz-}"
fi
if [[ ! -f "$initrd" ]]; then
  initrd=$(ls /boot/initrd.img-* 2>/dev/null | sort | tail -n 1)
fi
if [[ -z "$initrd" || ! -f "$initrd" ]]; then
  echo "qemu smoke: missing initrd image" >&2
  exit 1
fi

command_input=$'echo QEMU_SMOKE_OK\n'

set +e
output=$(timeout 25s bash -c "printf '%s' \"$command_input\" | qemu-system-x86_64 -accel tcg -m 256M -nographic -no-reboot -kernel '$kernel' -initrd '$initrd' -append 'console=ttyS0 rdinit=/bin/sh'" 2>&1)
status=$?
set -e

if ! grep -q "QEMU_SMOKE_OK" <<< "$output"; then
  echo "$output" >&2
  echo "qemu smoke: output marker not found" >&2
  exit 1
fi

if [[ $status -ne 0 ]]; then
  echo "qemu smoke: non-zero exit status $status (output marker found)" >&2
fi

echo "qemu smoke: ok"
