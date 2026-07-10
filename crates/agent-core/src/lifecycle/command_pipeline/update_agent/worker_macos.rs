use std::fs;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::lifecycle::command_pipeline::command_utils::mark_internal_command;

use super::request::NormalizedUpdateRequest;

/// Spawn the macOS update worker as a detached background process.
///
/// Production-grade properties:
///
/// * No shell or nohup wrapper. Arguments are passed through `std::process::Command`
///   so there is no string-escaping attack surface and no reliance on bash quoting.
/// * Stdin is wired to `/dev/null` at the syscall level via `Stdio::null()`. This
///   removes any chance of inheriting the agent's controlling terminal (if any)
///   and avoids the macOS `nohup: can't detach from console: Inappropriate ioctl
///   for device` warning that surfaced when we previously wrapped the spawn in
///   `nohup ... &` in a bash `-c` string.
/// * The child detaches via `setsid(2)` in a `pre_exec` hook, so it lives in its
///   own session and process group. A later `launchctl unload` of the running
///   agent (triggered by the worker script near the end of its run) cannot
///   reach into this process group, so the in-flight installer survives the
///   agent reload.
/// * We deliberately `mem::forget` the `Child` handle: the agent should not be
///   blocked waiting on the installer, and the installer reports its outcome
///   via an on-disk `update-outcome-<command_id>.txt` file that the agent loop
///   polls separately.
/// * Stdout and stderr are redirected to the worker's log file, so even
///   pre-exec failures land somewhere observable for postmortem.
pub(super) fn spawn_update_worker(
    command_id: &str,
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    if request.package_kind().as_macos_format() != Some("pkg") {
        return Err(format!(
            "unsupported macOS update package: {:?}",
            request.package_kind()
        ));
    }

    let script_path = update_dir.join("apply-agent-update-worker.sh");
    write_macos_update_worker_script(&script_path)?;

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
    command
        .arg(&script_path)
        .arg("--command-id")
        .arg(command_id)
        .arg("--update-dir")
        .arg(update_dir)
        .arg("--version")
        .arg(request.version())
        .arg("--checksum")
        .arg(request.checksum_sha256())
        .arg("--url")
        .arg(request.package_url())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_file));

    // Detach the child from the agent's session/process group so a later
    // `launchctl unload` of the running agent (triggered by the worker
    // script near the end of its run) does not kill the in-flight
    // installer. `setsid(2)` is called between fork(2) and execve(2) in
    // the child via `pre_exec`.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = mark_internal_command(&mut command)
        .spawn()
        .map_err(|err| format!("spawn macOS update worker: {}", err))?;

    // Detach: the agent must not block on (or reap) the installer.
    // Outcome is reported via update-outcome-<command_id>.txt.
    std::mem::forget(child);

    Ok(format!(
        "macOS agent update worker started (url={}, kind=pkg)",
        request.package_url(),
    ))
}

fn write_macos_update_worker_script(path: &Path) -> Result<(), String> {
    const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail

COMMAND_ID=""
UPDATE_DIR=""
VERSION=""
CHECKSUM=""
PACKAGE_URL=""
PLIST_PATH="/Library/LaunchDaemons/com.eguard.agent.plist"

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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --command-id)  COMMAND_ID="${2:-}";  shift 2 ;;
    --update-dir)  UPDATE_DIR="${2:-}";  shift 2 ;;
    --version)     VERSION="${2:-}";     shift 2 ;;
    --checksum)    CHECKSUM="${2:-}";    shift 2 ;;
    --url)         PACKAGE_URL="${2:-}"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$COMMAND_ID" || -z "$UPDATE_DIR" || -z "$VERSION" || -z "$CHECKSUM" || -z "$PACKAGE_URL" ]]; then
  echo "missing required update worker parameters" >&2
  exit 1
fi

mkdir -p "$UPDATE_DIR"
chmod 0755 "$UPDATE_DIR"
pkg_path="$UPDATE_DIR/eguard-agent-${VERSION}.pkg"
tmp_path="${pkg_path}.download"
trap 'rm -f "$tmp_path"' EXIT

# Download with curl (bundled on every macOS).
/usr/bin/curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 900 \
  "$PACKAGE_URL" -o "$tmp_path" \
  || fail_outcome "package download failed from $PACKAGE_URL"

# Verify sha256 using shasum (macOS does not ship sha256sum by default).
actual="$(/usr/bin/shasum -a 256 "$tmp_path" | /usr/bin/awk '{print $1}')"
if [[ "$actual" != "$CHECKSUM" ]]; then
  fail_outcome "package checksum verification failed for $PACKAGE_URL (expected $CHECKSUM, got $actual)"
fi
mv -f "$tmp_path" "$pkg_path"

# installer(8) replaces the existing /usr/local/bin/eguard-agent and assets.
# It does NOT restart the LaunchDaemon, so we do that ourselves below.
if ! installer_output="$(/usr/sbin/installer -pkg "$pkg_path" -target / 2>&1)"; then
  fail_outcome "installer failed for $pkg_path: $installer_output"
fi

# Reload the LaunchDaemon to pick up the new binary. The worker is detached
# via setsid(2) by the Rust spawn site, so unloading the running agent does
# not kill this process.
/bin/launchctl unload "$PLIST_PATH" 2>/dev/null || true
sleep 1
if ! /bin/launchctl load "$PLIST_PATH" 2>/dev/null; then
  fail_outcome "launchctl load failed for $PLIST_PATH"
fi

write_outcome "completed" "agent update applied (version=$VERSION, format=pkg)"
"#;

    fs::write(path, SCRIPT)
        .map_err(|err| format!("write update worker script {}: {}", path.display(), err))?;
    let mut perms = fs::metadata(path)
        .map_err(|err| format!("read script metadata {}: {}", path.display(), err))?
        .permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms)
        .map_err(|err| format!("chmod script {}: {}", path.display(), err))?;
    Ok(())
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Instant;

    fn fake_request() -> NormalizedUpdateRequest {
        // Build a NormalizedUpdateRequest via its only public constructor —
        // through normalize_update_request — to keep this test honest about
        // the data shape. We use a known-good payload that the validator
        // accepts.
        use crate::lifecycle::command_pipeline::payloads::parse_update_payload;
        use super::super::request::normalize_update_request;
        let payload = parse_update_payload(
            r#"{
              "version": "15.0.99",
              "package_format": "pkg",
              "package_url": "http://127.0.0.1:0/api/v1/agent-install/macos?version=15.0.99",
              "checksum_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }"#,
        );
        normalize_update_request(payload, "127.0.0.1:0").expect("valid update payload")
    }

    #[test]
    fn spawn_returns_quickly_and_does_not_block_on_installer() {
        // The agent's tick loop must not block on the update worker. The spawn
        // primitive should return in well under one second regardless of how
        // long the installer would take.
        let dir = tempfile::tempdir().expect("tempdir");
        let request = fake_request();
        let started = Instant::now();
        let detail = spawn_update_worker("test-cmd-id", &request, dir.path())
            .expect("spawn macOS update worker");
        let elapsed = started.elapsed();
        assert!(detail.contains("macOS agent update worker started"));
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "spawn took {:?}, agent tick loop would block",
            elapsed
        );
        // Script must exist with 0700 perms.
        let script = dir.path().join("apply-agent-update-worker.sh");
        let meta = std::fs::metadata(&script).expect("script written");
        let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777;
        assert_eq!(mode, 0o700, "script mode = {:o}", mode);
    }

    #[test]
    fn rejects_non_pkg_package_kind() {
        // The macOS worker must reject anything other than .pkg up front so
        // the agent reports a clear failure instead of attempting to dpkg/rpm
        // on macOS.
        use crate::lifecycle::command_pipeline::payloads::parse_update_payload;
        use super::super::request::normalize_update_request;
        let payload = parse_update_payload(
            r#"{
              "version": "15.0.99",
              "package_format": "deb",
              "package_url": "http://127.0.0.1:0/api/v1/agent-install/linux-deb?version=15.0.99",
              "checksum_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }"#,
        );
        let request =
            normalize_update_request(payload, "127.0.0.1:0").expect("valid update payload");
        let dir = tempfile::tempdir().expect("tempdir");
        let err = spawn_update_worker("test-cmd-id", &request, dir.path())
            .expect_err("non-pkg must be rejected");
        assert!(
            err.contains("unsupported macOS update package"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn child_runs_in_new_session_via_setsid() {
        // Verify the pre_exec setsid hook by spawning a tiny probe that prints
        // its session id. The probe replaces the bash script for this test
        // by writing a known stdout to the log file.
        let dir = tempfile::tempdir().expect("tempdir");
        let probe = dir.path().join("apply-agent-update-worker.sh");
        std::fs::write(
            &probe,
            "#!/bin/sh\nps -p $$ -o sess= > \"$2/session-id.txt\"\n",
        )
        .expect("write probe");
        let mut perms = std::fs::metadata(&probe)
            .expect("probe meta")
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o700);
        std::fs::set_permissions(&probe, perms).expect("chmod probe");

        // Bypass spawn_update_worker and re-use the same Command pattern so
        // we can wait on the probe and read its captured session id.
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.path().join("probe.log"))
            .expect("open probe log");
        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg(&probe)
            .arg("--update-dir")
            .arg(dir.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(log));
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let status = command.status().expect("probe runs");
        assert!(status.success(), "probe status = {:?}", status);
        let captured = std::fs::read_to_string(dir.path().join("session-id.txt"))
            .expect("session-id captured");
        let child_sid: i32 = captured.trim().parse().expect("session id is numeric");
        let parent_sid = unsafe { libc::getsid(0) };
        assert_ne!(
            child_sid, parent_sid,
            "child session id must differ from parent (setsid did not run)"
        );
    }

    // Suppress unused warnings on non-macOS builds for the helper.
    #[allow(dead_code)]
    fn _force_exit_status_use() -> std::process::ExitStatus {
        std::process::ExitStatus::from_raw(0)
    }
}
