use std::fs;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::lifecycle::command_pipeline::command_utils::{
    internal_process_systemd_run_env_arg, mark_internal_command,
};

use super::request::NormalizedUpdateRequest;

pub(super) fn spawn_update_worker(
    command_id: &str,
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    let format = request
        .package_kind()
        .as_linux_format()
        .ok_or_else(|| "unsupported linux update package".to_string())?;

    let script_path = update_dir.join("apply-agent-update-worker.sh");
    write_linux_update_worker_script(&script_path)?;

    let base_args = vec![
        "--command-id".to_string(),
        command_id.to_string(),
        "--update-dir".to_string(),
        update_dir.to_string_lossy().to_string(),
        "--version".to_string(),
        request.version().to_string(),
        "--checksum".to_string(),
        request.checksum_sha256().to_string(),
        "--url".to_string(),
        request.package_url().to_string(),
        "--format".to_string(),
        format.to_string(),
    ];

    // The detached transient unit is the only context in which the worker can
    // safely signal the agent's main process during the restart cycle: it lives
    // in its own systemd unit, so the agent cgroup's teardown does not kill it.
    let mut detached_args = base_args.clone();
    detached_args.push("--restart-mode".to_string());
    detached_args.push("detached".to_string());
    if let Ok(detail) = spawn_worker_via_systemd_run(&script_path, &detached_args) {
        return Ok(detail);
    }

    // Fallback: systemd-run is unavailable, so the worker runs as a child inside
    // the agent's own cgroup. It must NOT kill the agent (control-group teardown
    // would kill the worker mid-restart), so it is marked attached and the script
    // installs the package but reports a deferred-restart failure instead.
    let mut script_args = base_args;
    script_args.push("--restart-mode".to_string());
    script_args.push("attached".to_string());

    let log_path = update_dir.join("apply-agent-update-worker.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|err| format!("open update log {}: {}", log_path.display(), err))?;
    let stderr_file = log_file
        .try_clone()
        .map_err(|err| format!("clone update log {}: {}", log_path.display(), err))?;

    let mut command = Command::new("/bin/bash");
    mark_internal_command(
        command
            .arg(&script_path)
            .args(&script_args)
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr_file)),
    )
    .spawn()
    .map_err(|err| format!("spawn update worker: {}", err))?;

    Ok(format!(
        "agent update worker started (url={}, format={})",
        request.package_url(),
        format
    ))
}

fn write_linux_update_worker_script(path: &Path) -> Result<(), String> {
    const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail

COMMAND_ID=""
UPDATE_DIR=""
VERSION=""
CHECKSUM=""
PACKAGE_URL=""
FORMAT=""
# Fail closed: only an explicit "detached" (a worker in its own systemd-run
# transient unit) is allowed to signal/cycle the agent. If the flag is ever
# missing, we stay "attached" and refuse to kill — an unapplied update is
# recoverable, a brick is not.
RESTART_MODE="attached"
# Canonical package-managed binary path. verify_installed_version() and the
# post-restart inode gate both key on this so success requires the LIVE process
# to be executing exactly this freshly installed file (not an alternate ExecStart
# or a lingering deleted inode).
INSTALLED_BIN="/usr/bin/eguard-agent"

write_outcome() {
  local status="$1"
  local detail="$2"
  local outcome_path="$UPDATE_DIR/update-outcome-${COMMAND_ID}.txt"
  printf '%s\n%s\n%s\n' "$COMMAND_ID" "$status" "$detail" > "$outcome_path"
}

fail_outcome() {
  local detail="$1"
  write_outcome "failed" "$detail"
  echo "$detail" >&2
  exit 1
}

normalize_version() {
  printf '%s' "${1:-}" | tr -d '\r' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/^[vV]//'
}

verify_installed_version() {
  if [[ ! -x "$INSTALLED_BIN" ]]; then
    fail_outcome "agent binary missing after package install: $INSTALLED_BIN"
  fi

  # Same discipline as probe_running_version: clear the runtime version override
  # (the agent honors EGUARD_AGENT_VERSION at runtime) and bound the check so a
  # hanging binary cannot stall this worker while it holds the update lock.
  local actual_version=""
  actual_version="$(env -u EGUARD_AGENT_VERSION timeout 10 "$INSTALLED_BIN" --version 2>&1 | head -n 1)" \
    || fail_outcome "agent binary version check failed after package install"

  if [[ "$(normalize_version "$actual_version")" != "$(normalize_version "$VERSION")" ]]; then
    fail_outcome "agent binary version mismatch after package install: expected $VERSION got $actual_version"
  fi

  printf '%s' "$actual_version"
}

# Emit the service MainPID (may be empty or "0"); never aborts the script.
service_main_pid() {
  systemctl show -p MainPID eguard-agent 2>/dev/null | sed -n 's/^MainPID=//p' || true
}

# Human-readable path of the running agent binary, for DIAGNOSTICS ONLY (never
# used to authorize success). Prefers the live /proc/<pid>/exe target, else the
# unit ExecStart path.
running_binary_path() {
  local pid="${1:-}"
  local exe=""
  if [[ -n "$pid" && "$pid" != "0" ]]; then
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    # An in-place replacement of a running binary reads back as "<path> (deleted)".
    exe="${exe% (deleted)}"
    if [[ -n "$exe" ]]; then
      printf '%s' "$exe"
      return 0
    fi
  fi
  systemctl show -p ExecStart eguard-agent 2>/dev/null | head -n 1 \
    | sed -n 's/.*path=\([^ ;]*\).*/\1/p' || true
}

# Authoritative version of the process actually running as MainPID: execute the
# /proc/<pid>/exe magic symlink DIRECTLY so we run the live inode even after an
# in-place package replace. Resolving the path via readlink and running that
# path would execute the NEW on-disk binary and mask an un-restarted old
# process. EGUARD_AGENT_VERSION is cleared so --version reflects the compiled
# binary identity rather than the worker's inherited environment. Emits the
# normalized version, or empty when the process cannot be probed.
probe_running_version() {
  local pid="${1:-}"
  [[ -n "$pid" && "$pid" != "0" ]] || return 0
  local out=""
  out="$(env -u EGUARD_AGENT_VERSION timeout 10 "/proc/$pid/exe" --version 2>/dev/null | head -n 1 || true)"
  normalize_version "$out"
}

# Stable identity ("<pid>:<starttime-ticks>") of a running process instance, used
# to prove the service cycled to a NEW instance. starttime is field 22 of
# /proc/<pid>/stat; comm (field 2) is parenthesised and may contain spaces or
# ')', so fields are counted after the final ')'. Emits empty when absent.
proc_identity() {
  local pid="${1:-}"
  [[ -n "$pid" && "$pid" != "0" ]] || return 0
  local stat=""
  stat="$(cat "/proc/$pid/stat" 2>/dev/null || true)"
  [[ -n "$stat" ]] || return 0
  local rest="${stat##*) }"
  local start=""
  start="$(printf '%s\n' "$rest" | awk '{print $20}' || true)"
  # Fail closed: a missing/non-numeric start time yields an empty identity rather
  # than a bare "<pid>:" that -n would accept as a valid instance.
  [[ "$start" =~ ^[0-9]+$ ]] || return 0
  printf '%s:%s' "$pid" "$start"
}

# One full success-gate attempt against the CURRENT MainPID. On success prints
# "<version> (pid <pid>: <binary>)" and returns 0; otherwise prints nothing and
# returns 1. Requires, as independent gates: the unit active; a live MainPID; the
# live inode reporting the TARGET version ($1); a genuinely NEW process instance
# vs the pre-kill identity ($2, so a same-version reinstall cannot pass on the
# un-cycled old process); the live inode being the package-installed file (not an
# alternate ExecStart or a deleted inode); then, after a short stability dwell,
# the SAME instance still active on the installed inode. Used both in the confirm
# loop and as a final admission check before rollback.
try_confirm_target() {
  local target_norm="$1" before_ident="$2"
  systemctl is-active --quiet eguard-agent || return 1
  local cur_pid=""
  cur_pid="$(service_main_pid)"
  [[ -n "$cur_pid" && "$cur_pid" != "0" ]] || return 1
  local observed="" cur_ident=""
  observed="$(probe_running_version "$cur_pid")"
  cur_ident="$(proc_identity "$cur_pid")"
  [[ -n "$observed" && "$observed" == "$target_norm" && -n "$cur_ident" && "$cur_ident" != "$before_ident" && "/proc/$cur_pid/exe" -ef "$INSTALLED_BIN" ]] || return 1
  # Stability dwell: a target can pass --version / reach READY and then crash.
  sleep 3
  local recheck_pid=""
  recheck_pid="$(service_main_pid)"
  [[ "$recheck_pid" == "$cur_pid" && "$(proc_identity "$recheck_pid")" == "$cur_ident" && "/proc/$recheck_pid/exe" -ef "$INSTALLED_BIN" ]] || return 1
  systemctl is-active --quiet eguard-agent || return 1
  printf '%s (pid %s: %s)' "$observed" "$cur_pid" "$(running_binary_path "$cur_pid")"
  return 0
}

# Cycle the service onto the freshly installed binary and confirm the LIVE
# process reached the target version before declaring success.
#
# The packaged unit sets RefuseManualStop=yes, so `systemctl stop`/`restart` are
# refused (rc=4) and never cycle the process; `systemctl start` on an already
# active unit is a no-op. The only sanctioned cycle is to signal the main
# process and let Restart=always relaunch it. We signal only the main process
# (--kill-who=main) so systemd's KillMode does not also reap other processes we
# rely on. An ATTACHED fallback worker never reaches this code (the RESTART_MODE
# guard below returns first); the DETACHED worker lives in its own systemd-run
# transient unit and therefore survives the agent cgroup's teardown. Success is gated on
# the LIVE inode: it must be the freshly installed package file AND report the
# target --version, so a non-package/manual install layout (service executing a
# binary the package did not update) is reported as failed instead of a silent
# no-op. Emits "<version> (pid <pid>: <binary>)" on success.
#
# Success additionally requires the live process to be a NEW instance relative to
# the pre-kill process: a same-version hotfix reinstall would otherwise match the
# target version on the still-running old process and complete without ever
# cycling onto the freshly installed binary.
restart_and_confirm_update() {
  # A fallback (attached) worker runs inside the agent's own cgroup; signalling
  # the agent would trigger control-group teardown and kill this worker before it
  # could observe or recover the service. Such a worker must not cycle the
  # service: the package install stands and the restart is deferred to the next
  # natural (re)start, reported honestly as a failure so the operator can act.
  if [[ "$RESTART_MODE" != "detached" ]]; then
    fail_outcome "package installed but the agent was not restarted: a safe self-restart needs the detached update worker (a systemd-run transient unit), which was unavailable; the new version will take effect on the next agent restart or reboot"
  fi

  local target_norm=""
  target_norm="$(normalize_version "$VERSION")"

  local before_pid="" before_ident=""
  before_pid="$(service_main_pid)"
  before_ident="$(proc_identity "$before_pid")"

  # Snapshot the currently-running binary BEFORE the kill so we can roll back if
  # the freshly installed payload passes --version yet cannot stay started
  # (Type=notify never signals READY, config/runtime incompatibility, crash
  # loop). Copying /proc/<pid>/exe captures the exact live bytes even if the file
  # was replaced in place. Rollback is armed only when it can be bound to a stable
  # prior identity: a nonempty before_ident, a nonempty ExecStart path, a
  # successful copy, and the SAME identity still present immediately after the
  # copy (guards a PID-reuse race where the artifact/path describe different
  # processes). The artifact is 0600 (data, not executed directly).
  local rollback_bin="$UPDATE_DIR/rollback-agent-${COMMAND_ID}.bin"
  local rollback_path=""
  rollback_path="$(running_binary_path "$before_pid")"
  if [[ -n "$before_pid" && "$before_pid" != "0" && -n "$before_ident" && -n "$rollback_path" ]] \
     && cp -f "/proc/$before_pid/exe" "$rollback_bin" 2>/dev/null \
     && [[ -s "$rollback_bin" && "$(proc_identity "$before_pid")" == "$before_ident" ]]; then
    chmod 0600 "$rollback_bin" 2>/dev/null || true
  else
    rm -f "$rollback_bin" 2>/dev/null || true
    rollback_bin=""
  fi

  # Never gate on the signal's exit status: a kill issued inside the RestartSec
  # window legitimately returns "no main process to kill".
  systemctl kill --kill-who=main -s TERM eguard-agent 2>/dev/null || true

  local escalated="no" ok_detail=""
  local start_ts now
  start_ts="$(date +%s)"
  # Loop-admission deadline: each iteration re-checks the clock before doing more
  # work, bounding the confirm phase to roughly this many seconds of iterations.
  # Individual systemctl calls still carry systemd's own sd-bus timeout, so this
  # is not a hard aggregate wall-clock cap. The default comfortably covers a
  # Type=notify start (default TimeoutStartSec=90s) plus the SIGTERM->SIGKILL
  # escalation; it is overridable only to let tests exercise the rollback path
  # quickly.
  local deadline_secs="${EG_UPDATE_CONFIRM_DEADLINE_SECS:-180}"
  [[ "$deadline_secs" =~ ^[0-9]+$ ]] || deadline_secs=180
  local deadline=$((start_ts + deadline_secs))
  while :; do
    now="$(date +%s)"
    [[ "$now" -lt "$deadline" ]] || break

    # Full success gate against the current MainPID (see try_confirm_target).
    if ok_detail="$(try_confirm_target "$target_norm" "$before_ident")"; then
      # Update confirmed: drop the rollback snapshot (no longer needed).
      [[ -z "$rollback_bin" ]] || rm -f "$rollback_bin" 2>/dev/null || true
      printf '%s' "$ok_detail"
      return 0
    fi

    # Not healthy on target yet. If the unit is down (a custom unit without
    # Restart=, or a crash between samples), nudge it back up; `systemctl start`
    # is not refused (only manual stop is) and --no-block avoids waiting out
    # TimeoutStartSec. If it still cannot stay up, the deadline path below rolls
    # back to the previously-running binary.
    if ! systemctl is-active --quiet eguard-agent; then
      systemctl reset-failed eguard-agent 2>/dev/null || true
      systemctl start --no-block eguard-agent 2>/dev/null || true
    fi

    # If the old instance ignored SIGTERM, escalate once to SIGKILL. An external
    # kill is not bounded by TimeoutStopSec, so the worker owns this deadline.
    if [[ "$escalated" == "no" && "$((now - start_ts))" -ge 25 ]]; then
      if [[ -n "$before_pid" && "$before_pid" != "0" && "$(service_main_pid)" == "$before_pid" ]]; then
        systemctl kill --kill-who=main -s KILL eguard-agent 2>/dev/null || true
      fi
      escalated="yes"
    fi

    sleep 1
  done

  # Final admission: the target may have become healthy DURING the last sample
  # window. Run the full success gate once more before deciding to roll back, so a
  # healthy new instance that appeared at the deadline boundary is not needlessly
  # rolled back over a good install.
  if ok_detail="$(try_confirm_target "$target_norm" "$before_ident")"; then
    [[ -z "$rollback_bin" ]] || rm -f "$rollback_bin" 2>/dev/null || true
    printf '%s' "$ok_detail"
    return 0
  fi

  # Deadline reached without a confirmed healthy target. Distinguish two very
  # different end states by sampling MainPID across a short window (a single
  # is-active is unreliable: a crash-LOOPING Type=simple/Restart=always unit
  # flickers active for the instant between fork and the immediate exit):
  #   - STABLY active (same non-zero MainPID across the window): the service is
  #     up on SOME binary but never reached the target on the installed inode
  #     (e.g. a non-package/alternate-ExecStart layout). The EDR is protected on
  #     its own binary; report an honest failure and do NOT touch the binary.
  #   - NOT stably active (down, or crash-looping because the new payload exits):
  #     roll back to the pre-update binary and bring the EDR back up.
  local s1="" s2="" a_final=""
  s1="$(service_main_pid)"
  sleep 2
  s2="$(service_main_pid)"
  a_final="$(systemctl is-active eguard-agent 2>/dev/null || true)"
  if [[ "$a_final" == "active" && -n "$s1" && "$s1" != "0" && "$s1" == "$s2" ]]; then
    fail_outcome "running agent service did not reach the updated version after restart: pid ${s2:-none} executes $(running_binary_path "$s2") reporting '$(probe_running_version "$s2")' but expected ${VERSION} (node may use a non-package install layout and require manual reinstall)"
  fi

  # Not stably active: the update could not stay running. Roll back to the
  # pre-update binary snapshot and bring the EDR back up on that known-good
  # executable. The restore is a CHECKED chain: copy to a sibling temp, verify the
  # copied bytes, atomically rename onto the target, and verify the target now
  # holds the snapshot bytes. Only a VERIFIED restore may claim "rolled back";
  # otherwise we report the failure honestly rather than assert a restore that did
  # not happen (a swallowed cp/mv error must never masquerade as recovery).
  if [[ -n "$rollback_bin" && -s "$rollback_bin" && -n "$rollback_path" && -e "$rollback_path" ]]; then
    local rb_tmp="${rollback_path}.eg-rollback.$$"
    local restored="no"
    if cp -f "$rollback_bin" "$rb_tmp" 2>/dev/null && cmp -s "$rollback_bin" "$rb_tmp"; then
      chmod 0755 "$rb_tmp" 2>/dev/null || true
      chown --reference="$rollback_path" "$rb_tmp" 2>/dev/null || true
      if mv -f "$rb_tmp" "$rollback_path" 2>/dev/null && cmp -s "$rollback_bin" "$rollback_path"; then
        restored="yes"
      fi
    fi
    [[ "$restored" == "yes" ]] || rm -f "$rb_tmp" 2>/dev/null || true

    if [[ "$restored" == "yes" ]]; then
      # Bytes are in place. Cycle onto them and require a STABLE live process that
      # is actually executing the restored inode before claiming recovery — not a
      # single is-active sample (crash loops flicker active).
      systemctl reset-failed eguard-agent 2>/dev/null || true
      systemctl kill --kill-who=main -s TERM eguard-agent 2>/dev/null || true
      systemctl start --no-block eguard-agent 2>/dev/null || true
      local r1="" r2="" ra="" recovered="no" rb_i
      for rb_i in $(seq 1 20); do
        r1="$(service_main_pid)"
        sleep 1
        r2="$(service_main_pid)"
        ra="$(systemctl is-active eguard-agent 2>/dev/null || true)"
        if [[ "$ra" == "active" && -n "$r2" && "$r2" != "0" && "$r1" == "$r2" && "/proc/$r2/exe" -ef "$rollback_path" ]]; then
          recovered="yes"
          break
        fi
      done
      if [[ "$recovered" == "yes" ]]; then
        # Recovery confirmed: the snapshot is no longer needed.
        rm -f "$rollback_bin" 2>/dev/null || true
        fail_outcome "update to ${VERSION} failed to stay running; rolled back to the previous binary at ${rollback_path} and the service is active again (manual reinstall recommended)"
      fi
      # Restored bytes are in place but the service is not stably active; KEEP the
      # 0600 snapshot for manual recovery.
      fail_outcome "update to ${VERSION} failed to stay running; restored the previous binary at ${rollback_path} but the service did not return to a stable active state (state=${ra:-unknown}); manual intervention required"
    fi

    # Restore chain failed: the endpoint may still be running the failed update.
    # Report honestly; keep the 0600 snapshot for forensics/manual recovery.
    fail_outcome "update to ${VERSION} failed to stay running and rollback restore FAILED (could not rewrite ${rollback_path}); the endpoint may still be running the failed update — manual intervention required"
  fi
  fail_outcome "agent service did not stay active after update and no rollback artifact was available (state=${a_final:-unknown}, pid=${s2:-none}); manual reinstall required"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --command-id)
      COMMAND_ID="${2:-}"
      shift 2
      ;;
    --update-dir)
      UPDATE_DIR="${2:-}"
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --checksum)
      CHECKSUM="${2:-}"
      shift 2
      ;;
    --url)
      PACKAGE_URL="${2:-}"
      shift 2
      ;;
    --format)
      FORMAT="${2:-}"
      shift 2
      ;;
    --restart-mode)
      RESTART_MODE="${2:-}"
      shift 2
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$COMMAND_ID" || -z "$UPDATE_DIR" || -z "$VERSION" || -z "$CHECKSUM" || -z "$PACKAGE_URL" || -z "$FORMAT" ]]; then
  echo "missing required update worker parameters" >&2
  exit 1
fi

if [[ "$FORMAT" != "deb" && "$FORMAT" != "rpm" ]]; then
  fail_outcome "unsupported format: $FORMAT"
fi

install -d -m 0755 "$UPDATE_DIR"

# Serialize updates host-wide. Every accepted update command spawns its own
# detached worker; overlapping workers would race the package install, the
# service cycle, and the rollback target, which can invalidate the version/inode
# honesty gates (worker A confirming bytes that worker B just replaced). Hold an
# exclusive advisory lock for this worker's whole lifetime; a second concurrent
# update fails honestly instead of interleaving. FD 9 stays open for the rest of
# the script; every child we exec (curl, dpkg/rpm, systemctl, systemd-run, the
# /proc/exe --version probe) is short-lived and exits before the worker, so the
# lock is released when the worker process exits.
LOCK_FILE="/run/eguard-agent-update.lock"
if ! ( : > "$LOCK_FILE" ) 2>/dev/null; then
  LOCK_FILE="$UPDATE_DIR/.update.lock"
fi
exec 9>>"$LOCK_FILE" || fail_outcome "cannot open update lock file ($LOCK_FILE)"
if ! flock -n 9; then
  fail_outcome "another agent update is already in progress on this host; refusing to run concurrently"
fi

# Under the lock (so a rejected concurrent worker never deletes files and the
# sweep cannot race an in-flight worker's fresh artifacts): bound accumulation of
# stale artifacts — 0600 rollback snapshots kept after a failed restore, staged
# packages, and partial downloads — by AGE only (older than a day).
find "$UPDATE_DIR" -maxdepth 1 -type f \( -name 'rollback-agent-*.bin' -o -name 'eguard-agent-*.deb' -o -name 'eguard-agent-*.rpm' -o -name '*.download' \) -mmin +1440 -delete 2>/dev/null || true

# Command-specific staging paths (defense in depth on top of the lock).
pkg_path="$UPDATE_DIR/eguard-agent-${VERSION}-${COMMAND_ID}.${FORMAT}"
tmp_path="${pkg_path}.download"
trap 'rm -f "$tmp_path"' EXIT

curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 900 "$PACKAGE_URL" -o "$tmp_path" || fail_outcome "package download failed from $PACKAGE_URL"
echo "$CHECKSUM  $tmp_path" | sha256sum --check --status || fail_outcome "package checksum verification failed for $PACKAGE_URL"
mv -f "$tmp_path" "$pkg_path"

if [[ "$FORMAT" == "deb" ]]; then
  dpkg -i "$pkg_path" || fail_outcome "deb package install failed for $pkg_path"
else
  rpm_output=""
  if ! rpm_output="$(rpm -Uvh "$pkg_path" 2>&1)"; then
    case "$rpm_output" in
      *"already installed"*|*"conflicts with file from package"*)
        rpm_output="$(rpm -Uvh --replacepkgs --replacefiles "$pkg_path" 2>&1)" \
          || fail_outcome "rpm package install failed for $pkg_path: $rpm_output"
        ;;
      *)
        fail_outcome "rpm package install failed for $pkg_path: $rpm_output"
        ;;
    esac
  fi
fi

installed_version="$(verify_installed_version)"

systemctl daemon-reload || true

running_version="$(restart_and_confirm_update)"

write_outcome "completed" "agent update applied (version=$VERSION, format=$FORMAT, package_version=$installed_version, running=$running_version)"
"#;

    // Write-then-rename onto a UNIQUE per-invocation temp: a later update command
    // rewrites this script while an earlier worker's bash may still be lazily
    // reading it. A shared temp could be O_TRUNC-reopened by a second writer in
    // the window between this writer's write and its rename, activating a torn or
    // empty script (identical bytes do not cure truncation timing). A private
    // (pid + atomic seq) temp cannot be touched by another writer; fs::rename is
    // atomic once the complete temp exists and leaves the old inode intact for a
    // worker still reading the previous script.
    static SCRIPT_TMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp_path = path.with_extension(format!(
        "sh.tmp.{}.{}",
        std::process::id(),
        SCRIPT_TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    if let Err(err) = fs::write(&tmp_path, SCRIPT) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "write update worker script {}: {}",
            tmp_path.display(),
            err
        ));
    }
    match fs::metadata(&tmp_path) {
        Ok(md) => {
            let mut perms = md.permissions();
            perms.set_mode(0o700);
            if let Err(err) = fs::set_permissions(&tmp_path, perms) {
                let _ = fs::remove_file(&tmp_path);
                return Err(format!("chmod script {}: {}", tmp_path.display(), err));
            }
        }
        Err(err) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!(
                "read script metadata {}: {}",
                tmp_path.display(),
                err
            ));
        }
    }
    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "activate update worker script {}: {}",
            path.display(),
            err
        ));
    }
    Ok(())
}

fn spawn_worker_via_systemd_run(
    script_path: &Path,
    script_args: &[String],
) -> Result<String, String> {
    let unit_suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let unit_name = format!("eguard-agent-update-{}", unit_suffix);

    let output = Command::new("systemd-run")
        .arg("--unit")
        .arg(&unit_name)
        .arg("--collect")
        .arg(internal_process_systemd_run_env_arg())
        .arg("/bin/bash")
        .arg(script_path)
        .args(script_args)
        .output()
        .map_err(|err| format!("systemd-run unavailable: {}", err))?;

    if output.status.success() {
        return Ok(format!(
            "agent update worker scheduled ({}, url={})",
            unit_name,
            script_args
                .windows(2)
                .find(|pair| pair[0] == "--url")
                .map(|pair| pair[1].as_str())
                .unwrap_or_default()
        ));
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        Err(format!("systemd-run failed with status {}", output.status))
    } else {
        Err(format!("systemd-run failed: {}", stderr))
    }
}
