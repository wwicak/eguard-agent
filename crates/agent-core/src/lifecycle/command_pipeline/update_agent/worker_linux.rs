use std::fs;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use super::request::NormalizedUpdateRequest;

pub(super) fn spawn_update_worker(
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    let format = request
        .package_kind()
        .as_linux_format()
        .ok_or_else(|| "unsupported linux update package".to_string())?;

    let script_path = update_dir.join("apply-agent-update-worker.sh");
    write_linux_update_worker_script(&script_path)?;

    let script_args = vec![
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

    if let Ok(detail) = spawn_worker_via_systemd_run(&script_path, &script_args) {
        return Ok(detail);
    }

    let log_path = update_dir.join("apply-agent-update-worker.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|err| format!("open update log {}: {}", log_path.display(), err))?;
    let stderr_file = log_file
        .try_clone()
        .map_err(|err| format!("clone update log {}: {}", log_path.display(), err))?;

    Command::new(&script_path)
        .args(&script_args)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_file))
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

UPDATE_DIR=""
VERSION=""
CHECKSUM=""
PACKAGE_URL=""
FORMAT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
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
    *)
      echo "unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$UPDATE_DIR" || -z "$VERSION" || -z "$CHECKSUM" || -z "$PACKAGE_URL" || -z "$FORMAT" ]]; then
  echo "missing required update worker parameters" >&2
  exit 1
fi

if [[ "$FORMAT" != "deb" && "$FORMAT" != "rpm" ]]; then
  echo "unsupported format: $FORMAT" >&2
  exit 1
fi

install -d -m 0755 "$UPDATE_DIR"
pkg_path="$UPDATE_DIR/eguard-agent-${VERSION}.${FORMAT}"
tmp_path="${pkg_path}.download"
trap 'rm -f "$tmp_path"' EXIT

curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 900 "$PACKAGE_URL" -o "$tmp_path"
echo "$CHECKSUM  $tmp_path" | sha256sum --check --status
mv -f "$tmp_path" "$pkg_path"

if [[ "$FORMAT" == "deb" ]]; then
  dpkg -i "$pkg_path"
else
  rpm -Uvh "$pkg_path"
fi

systemctl daemon-reload || true
systemctl start eguard-agent || true
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
