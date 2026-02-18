#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <command>" >&2
  exit 2
fi

kernel="${QEMU_KERNEL:-}"
if [[ -z "$kernel" ]]; then
  kernel=$(ls /boot/vmlinuz-* 2>/dev/null | sort | tail -n 1)
fi
if [[ -z "$kernel" || ! -f "$kernel" ]]; then
  echo "qemu command: missing kernel image" >&2
  exit 1
fi

initrd="${QEMU_INITRD:-}"
if [[ -z "$initrd" ]]; then
  initrd="/boot/initrd.img-${kernel##*/vmlinuz-}"
fi
if [[ ! -f "$initrd" ]]; then
  initrd=$(ls /boot/initrd.img-* 2>/dev/null | sort | tail -n 1)
fi
if [[ -z "$initrd" || ! -f "$initrd" ]]; then
  echo "qemu command: missing initrd image" >&2
  exit 1
fi

exec_path="$1"
shift

workdir=$(mktemp -d)
init_dir="$workdir/initramfs"
payload_dir="$init_dir/payload"

mkdir -p "$init_dir/bin" "$init_dir/proc" "$init_dir/sys" "$init_dir/dev" "$init_dir/host" \
  "$init_dir/lib/x86_64-linux-gnu" "$init_dir/lib64" "$payload_dir"

cp /usr/bin/busybox "$init_dir/bin/busybox"
for app in sh mount mkdir echo cat sleep poweroff insmod uname ip ifconfig sha256sum cp chmod awk grep wget udhcpc route tar gzip gunzip unzip base64 wc ping basename rm head sort tail seq nc httpd dd; do
  ln -s /bin/busybox "$init_dir/bin/$app"
done

for lib in /lib/x86_64-linux-gnu/libresolv.so.2 /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libnss_dns.so.2 /lib/x86_64-linux-gnu/libnss_files.so.2 /lib64/ld-linux-x86-64.so.2; do
  if [[ -f "$lib" ]]; then
    mkdir -p "$init_dir$(dirname "$lib")"
    cp "$lib" "$init_dir$lib"
  fi
done

if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
  mkdir -p "$init_dir/etc/ssl/certs"
  cp /etc/ssl/certs/ca-certificates.crt "$init_dir/etc/ssl/certs/"
fi

resolve_host_entry() {
  local name="$1"
  local ip
  ip=$(getent ahosts "$name" | awk '/STREAM/ {print $1; exit}')
  if [[ -n "$ip" ]]; then
    echo "$ip $name"
  fi
}

mkdir -p "$init_dir/etc"
{
  echo "127.0.0.1 localhost"
  for host in github.com github-releases.githubusercontent.com objects.githubusercontent.com release-assets.githubusercontent.com secure.eicar.org mb-api.abuse.ch; do
    entry=$(resolve_host_entry "$host")
    if [[ -n "$entry" ]]; then
      echo "$entry"
    fi
  done
} > "$init_dir/etc/hosts"

kernel_release="${kernel##*/vmlinuz-}"
module_root="/lib/modules/$kernel_release"
modules=(
  "kernel/drivers/virtio/virtio.ko"
  "kernel/drivers/virtio/virtio_ring.ko"
  "kernel/drivers/virtio/virtio_pci_legacy_dev.ko"
  "kernel/drivers/virtio/virtio_pci_modern_dev.ko"
  "kernel/drivers/virtio/virtio_pci.ko"
  "kernel/drivers/net/ethernet/intel/e1000/e1000.ko"
  "kernel/fs/netfs/netfs.ko"
  "kernel/fs/fscache/fscache.ko"
  "kernel/net/9p/9pnet.ko"
  "kernel/net/9p/9pnet_virtio.ko"
  "kernel/fs/9p/9p.ko"
)
for mod in "${modules[@]}"; do
  src="$module_root/$mod"
  if [[ -f "$src" ]]; then
    mkdir -p "$init_dir$(dirname "$src")"
    cp "$src" "$init_dir$src"
  fi
done

copy_binary() {
  local src="$1"
  local dest="$2"
  if [[ -f "$src" ]]; then
    mkdir -p "$(dirname "$dest")"
    cp "$src" "$dest"
    chmod +x "$dest" || true
    while IFS= read -r lib; do
      if [[ -f "$lib" ]]; then
        mkdir -p "$init_dir$(dirname "$lib")"
        cp "$lib" "$init_dir$lib"
      fi
    done < <(ldd "$src" | awk '{for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i}')
  fi
}

if [[ -x /usr/bin/curl ]]; then
  copy_binary /usr/bin/curl "$init_dir/bin/curl"
fi

if [[ -x /usr/bin/stdbuf ]]; then
  copy_binary /usr/bin/stdbuf "$init_dir/bin/stdbuf"
fi
if [[ -f /usr/libexec/coreutils/libstdbuf.so ]]; then
  mkdir -p "$init_dir/usr/libexec/coreutils"
  cp /usr/libexec/coreutils/libstdbuf.so "$init_dir/usr/libexec/coreutils/"
fi

command="$exec_path $*"
if [[ -f "$exec_path" ]]; then
  mkdir -p "$payload_dir/bin"
  copy_binary "$exec_path" "$payload_dir/bin/exec"
  command="/payload/bin/exec $*"
fi

if [[ -n "${QEMU_EXTRA_BINARIES:-}" ]]; then
  IFS=':' read -r -a extra_bins <<< "$QEMU_EXTRA_BINARIES"
  for extra in "${extra_bins[@]}"; do
    [[ -z "$extra" ]] && continue
    base=$(basename "$extra")
    copy_binary "$extra" "$payload_dir/bin/$base"
  done
fi

env_exports=""
if [[ -n "${QEMU_ENV_VARS:-}" ]]; then
  IFS=',' read -r -a env_list <<< "$QEMU_ENV_VARS"
  for name in "${env_list[@]}"; do
    [[ -z "$name" ]] && continue
    value="${!name-}"
    if [[ -n "$value" ]]; then
      env_exports+=$'export '
      env_exports+="${name}=${value}"
      env_exports+=$'\n'
    fi
  done
fi

printf '#!/bin/sh\nset -e\n%s%s\n' "$env_exports" "$command" > "$payload_dir/command.sh"
chmod +x "$payload_dir/command.sh"

# Provide minimal repo files for acceptance tests that read from repo root.
mkdir -p "$init_dir/home/dimas/eguard-agent/tests/qemu"
mkdir -p "$init_dir/home/dimas/eguard-agent/crates/acceptance"
cp /home/dimas/eguard-agent/tests/qemu/run_qemu_command.sh "$init_dir/home/dimas/eguard-agent/tests/qemu/" 2>/dev/null || true
cp /home/dimas/eguard-agent/tests/qemu/run_ebpf_smoke.sh "$init_dir/home/dimas/eguard-agent/tests/qemu/" 2>/dev/null || true
cp /home/dimas/eguard-agent/tests/qemu/run_agent_kill_smoke.sh "$init_dir/home/dimas/eguard-agent/tests/qemu/" 2>/dev/null || true
cp /home/dimas/eguard-agent/tests/qemu/agent_kill_smoke_cmd.sh "$init_dir/home/dimas/eguard-agent/tests/qemu/" 2>/dev/null || true
mkdir -p "$init_dir/home/dimas/eguard-agent/threat-intel/processing"
cp /home/dimas/eguard-agent/threat-intel/processing/signature_ml_train_model.py \
  "$init_dir/home/dimas/eguard-agent/threat-intel/processing/" 2>/dev/null || true

cat > "$init_dir/init" <<'EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev

mkdir -p /sys/fs/cgroup
mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null || true

mkdir -p /sys/kernel/tracing /sys/kernel/debug /sys/fs/bpf
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null || true

kernel_release=$(uname -r)
mod_base="/lib/modules/$kernel_release"
for mod in \
  "$mod_base/kernel/drivers/virtio/virtio.ko" \
  "$mod_base/kernel/drivers/virtio/virtio_ring.ko" \
  "$mod_base/kernel/drivers/virtio/virtio_pci_legacy_dev.ko" \
  "$mod_base/kernel/drivers/virtio/virtio_pci_modern_dev.ko" \
  "$mod_base/kernel/drivers/virtio/virtio_pci.ko" \
  "$mod_base/kernel/drivers/net/ethernet/intel/e1000/e1000.ko" \
  "$mod_base/kernel/fs/netfs/netfs.ko" \
  "$mod_base/kernel/fs/fscache/fscache.ko" \
  "$mod_base/kernel/net/9p/9pnet.ko" \
  "$mod_base/kernel/net/9p/9pnet_virtio.ko" \
  "$mod_base/kernel/fs/9p/9p.ko"; do
  if [ -f "$mod" ]; then
    insmod "$mod" 2>/dev/null || true
  fi
done

ip link set eth0 up 2>/dev/null || ifconfig eth0 up 2>/dev/null || true
for _ in 1 2 3 4 5; do
  udhcpc -i eth0 -q -t 1 -n >/dev/null 2>&1 && break
  sleep 1
done
ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up 2>/dev/null || true
ip route add default via 10.0.2.2 2>/dev/null || true
mkdir -p /etc
cat > /etc/resolv.conf <<'RESOLV_CONF'
nameserver 10.0.2.3
nameserver 8.8.8.8
nameserver 1.1.1.1
RESOLV_CONF
cat > /etc/nsswitch.conf <<'NSSWITCH_CONF'
hosts: files dns
NSSWITCH_CONF
if [ ! -f /etc/hosts ]; then
  echo "127.0.0.1 localhost" > /etc/hosts
fi
ip route add 10.0.2.0/24 dev eth0 2>/dev/null || true
for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10; do
  ip route add blackhole "$cidr" 2>/dev/null || true
done

mount -t 9p -o trans=virtio,version=9p2000.L hostroot /host || echo "qemu: 9p mount failed"

status=0
if [ -x /payload/command.sh ]; then
  /payload/command.sh || status=$?
else
  echo "qemu: missing payload command" >&2
  status=127
fi

echo "QEMU_CMD_STATUS=$status"
poweroff -f
EOF
chmod +x "$init_dir/init"

( cd "$init_dir" && find . -print0 | cpio --null -ov --format=newc > "$workdir/initramfs.cpio" )

output=$(timeout 300s qemu-system-x86_64 -accel tcg -m 2048 -nographic -no-reboot \
  -kernel "$kernel" -initrd "$workdir/initramfs.cpio" \
  -append "console=ttyS0 rdinit=/init qemu_script=/payload/command.sh" \
  -netdev user,id=net0 \
  -device e1000,netdev=net0 \
  -virtfs local,path=/,mount_tag=hostroot,security_model=none,readonly=on 2>&1 || true)

if ! grep -q "QEMU_CMD_STATUS=0" <<< "$output"; then
  echo "$output" >&2
  echo "qemu command: command failed" >&2
  exit 1
fi

echo "$output" | tail -n 50

echo "qemu command: ok"
