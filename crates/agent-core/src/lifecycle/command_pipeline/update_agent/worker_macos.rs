use std::fs;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::lifecycle::command_pipeline::command_utils::mark_internal_command;

use super::request::NormalizedUpdateRequest;

pub(super) fn spawn_update_worker(
    command_id: &str,
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    // macOS releases ship as .pkg; reject anything else explicitly so callers
    // don't silently get a half-broken install.
    if request.package_kind().as_macos_format() != Some("pkg") {
        return Err(format!(
            "unsupported macOS update package: {:?}",
            request.package_kind()
        ));
    }

    let script_path = update_dir.join("apply-agent-update-worker.sh");
    write_macos_update_worker_script(&script_path)?;

    let script_args = vec![
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
    ];

    let log_path = update_dir.join("apply-agent-update-worker.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|err| format!("open update log {}: {}", log_path.display(), err))?;
    let stderr_file = log_file
        .try_clone()
        .map_err(|err| format!("clone update log {}: {}", log_path.display(), err))?;

    // Detach the worker via nohup so a launchctl unload of the running
    // agent (triggered by the script itself near the end) does not kill
    // the in-flight installer. Redirect stdin from /dev/null explicitly
    // because macOS nohup fails with 'Inappropriate ioctl for device'
    // when stdin is the agent's parent TTY/socket.
    let mut command = Command::new("/bin/bash");
    let nohup_cmd = format!(
        "nohup '{}' {} < /dev/null > '{}' 2>&1 &",
        script_path.display(),
        script_args
            .iter()
            .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join(" "),
        log_path.display(),
    );
    mark_internal_command(
        command
            .arg("-c")
            .arg(&nohup_cmd)
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr_file)),
    )
    .spawn()
    .map_err(|err| format!("spawn macOS update worker: {}", err))?;

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

# Reload the LaunchDaemon to pick up the new binary.
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
