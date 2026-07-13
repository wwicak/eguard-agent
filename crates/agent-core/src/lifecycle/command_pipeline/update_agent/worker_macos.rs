use std::fs;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

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

    let update_lock = acquire_update_lock(update_dir)?;
    let update_lock_fd = update_lock.as_raw_fd();
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
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // Keep the already-held flock alive in the detached worker. The
            // parent drops its copy after spawn; the lock is then released by
            // the kernel on every worker exit path.
            if libc::fcntl(update_lock_fd, libc::F_SETFD, 0) == -1 {
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
    drop(update_lock);

    Ok(format!(
        "macOS agent update worker started (url={}, kind=pkg)",
        request.package_url(),
    ))
}

fn acquire_update_lock(update_dir: &Path) -> Result<fs::File, String> {
    fs::create_dir_all(update_dir)
        .map_err(|err| format!("create update directory {}: {}", update_dir.display(), err))?;
    let lock_path = update_dir.join("agent-update.lock");
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| format!("open update lock {}: {}", lock_path.display(), err))?;
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(
                "another agent update is already in progress on this host; refusing to run concurrently"
                    .to_string(),
            );
        }
        return Err(format!(
            "acquire update lock {}: {}",
            lock_path.display(),
            err
        ));
    }
    Ok(lock)
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
AGENT_PATH="/usr/local/bin/eguard-agent"
pkg_path="$UPDATE_DIR/eguard-agent-${VERSION}-${COMMAND_ID}.pkg"
tmp_path="${pkg_path}.download"
rollback_path="$UPDATE_DIR/rollback-agent-${COMMAND_ID}.bin"
rollback_plist_path="$UPDATE_DIR/rollback-plist-${COMMAND_ID}.plist"
rollback_tmp="${AGENT_PATH}.rollback-${COMMAND_ID}"
rollback_plist_tmp="${PLIST_PATH}.rollback-${COMMAND_ID}"
rollback_version=""
had_plist="no"
retain_rollback="no"
cleanup_artifacts() {
  rm -f "$tmp_path" "$pkg_path" "$rollback_tmp" "$rollback_plist_tmp" 2>/dev/null || true
  if [[ "$retain_rollback" != "yes" ]]; then
    rm -f "$rollback_path" "$rollback_plist_path" 2>/dev/null || true
  fi
}
trap cleanup_artifacts EXIT

# The Rust parent holds the host-wide flock before this worker is spawned.
# Sweep only stale command-specific artifacts while that lock is held.
find "$UPDATE_DIR" -maxdepth 1 -type f \( -name 'eguard-agent-*.pkg' -o -name '*.download' -o -name 'rollback-agent-*.bin' -o -name 'rollback-plist-*.plist' \) -mmin +1440 -delete 2>/dev/null || true

normalize_version() {
  local value="$1"
  value="${value#v}"
  value="${value#V}"
  printf '%s' "$value"
}

binary_version() {
  local path="$1" output
  output="$(env -u EGUARD_AGENT_VERSION "$path" --version 2>&1)" || return 1
  printf '%s' "${output%%$'\n'*}"
}

service_pid() {
  /bin/launchctl print system/com.eguard.agent 2>/dev/null \
    | /usr/bin/awk '/^[[:space:]]*pid = [0-9]+/ { print $3; exit }'
}

process_image_identity() {
  local pid="$1" fields device inode name
  fields="$(/usr/sbin/lsof -a -p "$pid" -d txt -FnDi 2>/dev/null)" || return 1
  device="$(printf '%s\n' "$fields" | /usr/bin/awk '/^D/ { print substr($0, 2); exit }')"
  device="$(printf '%d' "$device" 2>/dev/null)" || return 1
  inode="$(printf '%s\n' "$fields" | /usr/bin/awk '/^i/ { print substr($0, 2); exit }')"
  name="$(printf '%s\n' "$fields" | /usr/bin/awk '/^n/ { print substr($0, 2); exit }')"
  [[ -n "$device" && -n "$inode" && -n "$name" ]] || return 1
  printf '%s:%s:%s' "$device" "$inode" "$name"
}

installed_image_identity() {
  local identity
  identity="$(/usr/bin/stat -f '%d:%i' "$AGENT_PATH" 2>/dev/null)" || return 1
  printf '%s:%s' "$identity" "$AGENT_PATH"
}

verify_live_version() {
  local expected pid1 pid2 image1 image2 installed1 installed2 reported attempt
  expected="$(normalize_version "$1")"
  for attempt in {1..30}; do
    pid1="$(service_pid)"
    if [[ -n "$pid1" ]]; then
      image1="$(process_image_identity "$pid1")" || image1=""
      installed1="$(installed_image_identity)" || installed1=""
      if [[ -n "$image1" && "$image1" == "$installed1" ]]; then
        reported="$(binary_version "$AGENT_PATH")" || reported=""
        sleep 1
        pid2="$(service_pid)"
        image2="$(process_image_identity "$pid2")" || image2=""
        installed2="$(installed_image_identity)" || installed2=""
        if [[ "$pid1" == "$pid2" && "$image1" == "$image2" && "$image2" == "$installed2" && "$(normalize_version "$reported")" == "$expected" ]]; then
          printf '%s:%s' "$pid1" "$reported"
          return 0
        fi
      fi
    fi
    sleep 1
  done
  return 1
}

load_and_verify_installed() {
  local installed_version
  /bin/launchctl load "$PLIST_PATH" 2>/dev/null || true
  installed_version="$(binary_version "$AGENT_PATH")" || return 1
  verify_live_version "$installed_version"
}

rollback_and_fail() {
  local reason="$1" restored_tmp restored_plist_tmp live plist_restored="yes"
  if [[ -s "$rollback_path" && ( "$had_plist" != "yes" || -s "$rollback_plist_path" ) ]]; then
    restored_tmp="${rollback_tmp}.tmp"
    restored_plist_tmp="${rollback_plist_tmp}.tmp"
    if cp -f "$rollback_path" "$restored_tmp" \
      && cmp -s "$rollback_path" "$restored_tmp" \
      && chmod 0755 "$restored_tmp"; then
      if [[ "$had_plist" != "yes" ]] \
        || { cp -f "$rollback_plist_path" "$restored_plist_tmp" \
          && cmp -s "$rollback_plist_path" "$restored_plist_tmp" \
          && chmod 0644 "$restored_plist_tmp"; }; then
        /bin/launchctl unload "$PLIST_PATH" 2>/dev/null || true
        if mv -f "$restored_tmp" "$rollback_tmp" \
          && mv -f "$rollback_tmp" "$AGENT_PATH" \
          && cmp -s "$rollback_path" "$AGENT_PATH"; then
          if [[ "$had_plist" == "yes" ]]; then
            mv -f "$restored_plist_tmp" "$rollback_plist_tmp" \
              && mv -f "$rollback_plist_tmp" "$PLIST_PATH" \
              && cmp -s "$rollback_plist_path" "$PLIST_PATH" \
              || { plist_restored="no"; retain_rollback="yes"; }
          fi
          if live="$(load_and_verify_installed)"; then
            if [[ "$plist_restored" == "yes" ]]; then
              rm -f "$rollback_path" "$rollback_plist_path"
              fail_outcome "$reason; rolled back the previous binary and plist and verified it running ($live)"
            fi
            fail_outcome "$reason; plist restoration comparison failed, but the restored agent was verified running ($live); rollback artifacts retained in $UPDATE_DIR"
          fi
          retain_rollback="yes"
          fail_outcome "$reason; rollback restoration failed and the agent was not verified running; manual intervention required"
        fi
      fi
    fi
    rm -f "$restored_tmp" "$restored_plist_tmp"
    retain_rollback="yes"
    if live="$(load_and_verify_installed)"; then
      fail_outcome "$reason; rollback failed and prior artifacts were retained in $UPDATE_DIR, but the installed agent was verified running ($live); manual intervention required"
    fi
    fail_outcome "$reason; rollback failed, prior artifacts were retained in $UPDATE_DIR, and the agent was not verified running; manual intervention required"
  fi
  if live="$(load_and_verify_installed)"; then
    fail_outcome "$reason; complete prior rollback artifacts were unavailable, but the installed agent was verified running ($live); manual intervention required"
  fi
  fail_outcome "$reason; complete prior rollback artifacts were unavailable and the agent was not verified running; manual intervention required"
}

if [[ -x "$AGENT_PATH" ]]; then
  rollback_version="$(binary_version "$AGENT_PATH")" \
    || fail_outcome "cannot read the currently installed agent version before update"
  cp -f "$AGENT_PATH" "$rollback_path" \
    || fail_outcome "cannot create rollback binary at $rollback_path"
  chmod 0600 "$rollback_path"
  if [[ -f "$PLIST_PATH" ]]; then
    had_plist="yes"
    cp -f "$PLIST_PATH" "$rollback_plist_path" \
      || fail_outcome "cannot create rollback plist at $rollback_plist_path"
    chmod 0600 "$rollback_plist_path"
  fi
fi

/usr/bin/curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 900 \
  "$PACKAGE_URL" -o "$tmp_path" \
  || fail_outcome "package download failed from $PACKAGE_URL"

actual="$(/usr/bin/shasum -a 256 "$tmp_path" | /usr/bin/awk '{print $1}')"
if [[ "$actual" != "$CHECKSUM" ]]; then
  fail_outcome "package checksum verification failed for $PACKAGE_URL (expected $CHECKSUM, got $actual)"
fi
mv -f "$tmp_path" "$pkg_path"

if ! installer_output="$(/usr/sbin/installer -pkg "$pkg_path" -target / 2>&1)"; then
  rollback_and_fail "installer failed for $pkg_path: $installer_output"
fi

/bin/launchctl unload "$PLIST_PATH" 2>/dev/null || true
sleep 1
if ! /bin/launchctl load "$PLIST_PATH" 2>/dev/null; then
  rollback_and_fail "launchctl load failed for $PLIST_PATH"
fi
if ! live="$(verify_live_version "$VERSION")"; then
  rollback_and_fail "running agent service did not reach target version $VERSION after install"
fi

rm -f "$rollback_path" "$rollback_plist_path"
write_outcome "completed" "agent update applied and verified running (version=$VERSION, format=pkg, live=$live)"
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
        use super::super::request::normalize_update_request;
        use crate::lifecycle::command_pipeline::payloads::parse_update_payload;
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
    fn update_lock_rejects_overlap_and_releases() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = acquire_update_lock(dir.path()).expect("first lock");
        let err = acquire_update_lock(dir.path()).expect_err("overlap must be rejected");
        assert_eq!(
            err,
            "another agent update is already in progress on this host; refusing to run concurrently"
        );
        drop(first);
        acquire_update_lock(dir.path()).expect("lock released after holder drop");
    }

    #[test]
    fn generated_worker_rolls_back_binary_and_plist_and_uses_unique_packages() {
        let dir = tempfile::tempdir().expect("tempdir");
        let script_path = dir.path().join("worker.sh");
        write_macos_update_worker_script(&script_path).expect("write worker");
        assert!(
            Command::new("/bin/bash")
                .arg("-n")
                .arg(&script_path)
                .status()
                .expect("bash -n")
                .success(),
            "generated worker must be valid bash"
        );

        let old_source = dir.path().join("old.c");
        let new_source = dir.path().join("new.c");
        let old_binary = dir.path().join("old-agent");
        let new_binary = dir.path().join("new-agent");
        let agent_path = dir.path().join("eguard-agent");
        let plist_path = dir.path().join("com.eguard.agent.plist");
        let old_plist = b"old plist\n";
        fs::write(
            &old_source,
            "#include <stdio.h>\n#include <unistd.h>\nint main(int c,char**v){if(c>1){puts(\"1.0\");return 0;}for(;;)sleep(60);}\n",
        )
        .expect("old source");
        fs::write(
            &new_source,
            "#include <stdio.h>\n#include <unistd.h>\nint main(int c,char**v){if(c>1){puts(\"2.0\");return 0;}for(;;)sleep(60);}\n",
        )
        .expect("new source");
        for (source, output) in [(&old_source, &old_binary), (&new_source, &new_binary)] {
            assert!(Command::new("cc")
                .args(["-o"])
                .arg(output)
                .arg(source)
                .status()
                .expect("compile mock agent")
                .success());
        }
        fs::copy(&old_binary, &agent_path).expect("install old agent");
        fs::write(&plist_path, old_plist).expect("install old plist");

        let launchctl = dir.path().join("launchctl");
        let installer = dir.path().join("installer");
        let curl = dir.path().join("curl");
        let cmp = dir.path().join("cmp");
        fs::write(
            &launchctl,
            r#"#!/bin/bash
printf '%s\n' "$1" >> "$MOCK_LAUNCH_LOG"
case "$1" in
  print) [[ -s "$MOCK_PID" ]] && printf '    pid = %s\n' "$(cat "$MOCK_PID")" ;;
  unload) if [[ -s "$MOCK_PID" ]]; then kill "$(cat "$MOCK_PID")" 2>/dev/null || true; rm -f "$MOCK_PID"; fi ;;
  load) if [[ -s "$MOCK_PID" ]] && kill -0 "$(cat "$MOCK_PID")" 2>/dev/null; then exit 1; fi; nohup "$MOCK_AGENT" >/dev/null 2>&1 & echo $! > "$MOCK_PID"; /bin/sleep 0.1 ;;
esac
"#,
        )
        .expect("launchctl mock");
        fs::write(
            &installer,
            "#!/bin/bash\ncp \"$MOCK_NEW_AGENT\" \"${MOCK_AGENT}.new\"\nmv -f \"${MOCK_AGENT}.new\" \"$MOCK_AGENT\"\nprintf 'new plist\\n' > \"$MOCK_PLIST\"\n",
        )
        .expect("installer mock");
        fs::write(
            &curl,
            "#!/bin/bash\nout=\"${@: -1}\"\nprintf '%s\\n' \"$out\" >> \"$MOCK_CURL_LOG\"\n: > \"$out\"\n",
        )
        .expect("curl mock");
        fs::write(
            &cmp,
            "#!/bin/bash\nif [[ \"$MOCK_CMP_FAILURE\" == final && \"$1\" == *rollback-plist-* && \"$2\" == \"$MOCK_PLIST\" ]]; then exit 1; fi\nif [[ \"$MOCK_CMP_FAILURE\" == staging && \"$1\" == *rollback-plist-* && \"$2\" == *.tmp ]]; then exit 1; fi\nexec /usr/bin/cmp \"$@\"\n",
        )
        .expect("cmp mock");
        for mock in [&launchctl, &installer, &curl, &cmp] {
            let mut permissions = fs::metadata(mock).expect("mock metadata").permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(mock, permissions).expect("chmod mock");
        }

        let script = fs::read_to_string(&script_path)
            .expect("read worker")
            .replace("/usr/local/bin/eguard-agent", agent_path.to_str().unwrap())
            .replace(
                "/Library/LaunchDaemons/com.eguard.agent.plist",
                plist_path.to_str().unwrap(),
            )
            .replace("/bin/launchctl", launchctl.to_str().unwrap())
            .replace("/usr/sbin/installer", installer.to_str().unwrap())
            .replace("/usr/bin/curl", curl.to_str().unwrap())
            .replace("for attempt in {1..30}", "for attempt in {1..2}")
            .replace("sleep 1", "true");
        fs::write(&script_path, script).expect("write test worker");

        let curl_log = dir.path().join("curl.log");
        let launch_log = dir.path().join("launch.log");
        let pid_file = dir.path().join("service.pid");
        let path = format!(
            "{}:{}",
            dir.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        for (command_id, cmp_failure) in
            [("final-compare", "final"), ("staging-compare", "staging")]
        {
            let status = Command::new("/bin/bash")
                .arg(&script_path)
                .args(["--command-id", command_id])
                .arg("--update-dir")
                .arg(dir.path())
                .args([
                    "--version",
                    "9.9",
                    "--checksum",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "--url",
                    "https://example.invalid/agent.pkg",
                ])
                .env("MOCK_PID", &pid_file)
                .env("MOCK_AGENT", &agent_path)
                .env("MOCK_NEW_AGENT", &new_binary)
                .env("MOCK_PLIST", &plist_path)
                .env("MOCK_CURL_LOG", &curl_log)
                .env("MOCK_LAUNCH_LOG", &launch_log)
                .env("MOCK_CMP_FAILURE", cmp_failure)
                .env("PATH", &path)
                .status()
                .expect("run generated worker");
            assert!(!status.success(), "version mismatch must fail honestly");
            if cmp_failure == "final" {
                assert_eq!(
                    fs::read(&agent_path).expect("restored binary"),
                    fs::read(&old_binary).expect("old binary")
                );
                assert_eq!(fs::read(&plist_path).expect("restored plist"), old_plist);
            } else {
                assert_eq!(
                    fs::read(&agent_path).expect("installed binary"),
                    fs::read(&new_binary).expect("new binary")
                );
                assert_eq!(
                    fs::read(&plist_path).expect("installed plist"),
                    b"new plist\n"
                );
            }
            let pid: u32 = fs::read_to_string(&pid_file)
                .expect("restored service pid")
                .trim()
                .parse()
                .expect("numeric restored service pid");
            assert!(
                unsafe { libc::kill(pid as i32, 0) } == 0,
                "restored service must still be running"
            );
            let outcome =
                fs::read_to_string(dir.path().join(format!("update-outcome-{command_id}.txt")))
                    .expect("rollback outcome");
            let expected = if cmp_failure == "final" {
                "plist restoration comparison failed, but the restored agent was verified running"
            } else {
                "rollback failed and prior artifacts were retained in"
            };
            assert!(
                outcome.contains(expected) && outcome.contains("agent was verified running"),
                "rollback failure must report verified availability: {outcome}"
            );
        }
        assert_eq!(
            fs::read_to_string(&launch_log)
                .expect("launchctl log")
                .lines()
                .filter(|action| *action == "load")
                .count(),
            4,
            "each failed update must attempt the new load and the rollback load"
        );
        let packages: Vec<_> = fs::read_to_string(&curl_log)
            .expect("curl destinations")
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(packages.len(), 2);
        assert_ne!(packages[0], packages[1]);
        let _ = Command::new(&launchctl)
            .arg("unload")
            .env("MOCK_PID", &pid_file)
            .env("MOCK_AGENT", &agent_path)
            .status();
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
        use super::super::request::normalize_update_request;
        use crate::lifecycle::command_pipeline::payloads::parse_update_payload;
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
        let mut perms = std::fs::metadata(&probe).expect("probe meta").permissions();
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
