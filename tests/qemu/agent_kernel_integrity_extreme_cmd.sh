#!/bin/sh
set -e

scan_root=/tmp/kernel_scan
mkdir -p "$scan_root/sys_module" "$scan_root/tracefs" "$scan_root/bpffs"

cat > "$scan_root/proc_modules" <<'EOF'
good 0 0 - Live 0
proc_only 0 0 - Live 0
EOF

mkdir -p "$scan_root/sys_module/good"
mkdir -p "$scan_root/sys_module/sys_only"

echo "1" > "$scan_root/sys_module/sys_only/taint"
echo "" > "$scan_root/sys_module/sys_only/signer"

echo "p:kprobes/evil __x64_sys_execve" > "$scan_root/tracefs/kprobe_events"
echo "function" > "$scan_root/tracefs/current_tracer"
echo "sys_execve" > "$scan_root/tracefs/set_ftrace_filter"

echo "selinux,bpf" > "$scan_root/lsm"
mkdir -p "$scan_root/bpffs/evil_prog"

export EGUARD_KERNEL_INTEGRITY_ENABLED=1
export EGUARD_KERNEL_INTEGRITY_INTERVAL_SECS=1
export EGUARD_KERNEL_INTEGRITY_PROC_MODULES_PATH="$scan_root/proc_modules"
export EGUARD_KERNEL_INTEGRITY_SYS_MODULES_PATH="$scan_root/sys_module"
export EGUARD_KERNEL_INTEGRITY_KPROBE_EVENTS_PATH="$scan_root/tracefs/kprobe_events"
export EGUARD_KERNEL_INTEGRITY_TRACER_PATH="$scan_root/tracefs/current_tracer"
export EGUARD_KERNEL_INTEGRITY_FTRACE_FILTER_PATH="$scan_root/tracefs/set_ftrace_filter"
export EGUARD_KERNEL_INTEGRITY_LSM_PATH="$scan_root/lsm"
export EGUARD_KERNEL_INTEGRITY_BPF_FS_PATH="$scan_root/bpffs"

export EGUARD_AUTONOMOUS_RESPONSE=false
export EGUARD_BASELINE_SKIP_LEARNING=1
export EGUARD_AGENT_MODE=degraded
export EGUARD_TRANSPORT_MODE=http
export EGUARD_SERVER_ADDR=127.0.0.1:9
export EGUARD_BUFFER_BACKEND=memory
export EGUARD_SELF_PROTECT_ENABLE_TIMING=0
export EGUARD_SELF_PROTECT_ENABLE_TRACER_PID=0
export EGUARD_SELF_PROTECTION_INTEGRITY_CHECK_INTERVAL_SECS=0
export EGUARD_SELF_PROTECT_LAZY_BASELINE=1
export EGUARD_DEBUG_EVENT_LOG=1
export EGUARD_DEBUG_TICK_LOG=1
export RUST_LOG=info
export RUST_LOG_STYLE=never
export NO_COLOR=1

/payload/bin/agent-core >/tmp/agent.log 2>&1 &
agent_pid=$!

sleep 8

if ! kill -0 "$agent_pid" 2>/dev/null; then
  echo "agent exited before kernel integrity scan" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  exit 1
fi

if ! grep -Eq 'debug kernel integrity scan detection' /tmp/agent.log; then
  echo "kernel integrity scan log missing" >&2
  echo "--- agent log ---" >&2
  cat /tmp/agent.log >&2 || true
  kill "$agent_pid" 2>/dev/null || true
  exit 1
fi

for marker in hidden_module_sysfs:sys_only hidden_module_proc:proc_only tainted_module:sys_only kprobe_hook:__x64_sys_execve ftrace_tracer:function lsm_bpf_enabled bpffs_pinned_object:evil_prog; do
  if ! grep -Fq "$marker" /tmp/agent.log; then
    echo "missing kernel integrity marker $marker" >&2
    echo "--- agent log ---" >&2
    cat /tmp/agent.log >&2 || true
    kill "$agent_pid" 2>/dev/null || true
    exit 1
  fi
done

kill "$agent_pid" 2>/dev/null || true
wait "$agent_pid" 2>/dev/null || true

echo "agent kernel integrity extreme harness ok"
