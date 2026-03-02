use std::fs;
#[cfg(not(target_os = "macos"))]
use std::fs::OpenOptions;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
#[cfg(not(target_os = "macos"))]
use std::process::{Command, Stdio};

use response::{CommandExecution, CommandOutcome};

use super::command_utils::extract_server_host;
use super::paths::resolve_agent_data_dir;
use super::payloads::{parse_update_payload, UpdatePayload};
use super::AgentRuntime;

const UPDATE_BASE_URL_ENV: &str = "EGUARD_AGENT_UPDATE_BASE_URL";
const UPDATE_DEFAULT_HTTPS_PORT_ENV: &str = "EGUARD_AGENT_UPDATE_HTTPS_PORT";
const UPDATE_ALLOW_HTTP_ENV: &str = "EGUARD_AGENT_UPDATE_ALLOW_HTTP";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdatePackageKind {
    LinuxDeb,
    LinuxRpm,
    WindowsExe,
    WindowsMsi,
    MacosPkg,
}

#[derive(Debug, Clone)]
struct NormalizedUpdateRequest {
    version: String,
    package_url: String,
    checksum_sha256: String,
    package_kind: UpdatePackageKind,
}

impl AgentRuntime {
    pub(super) fn apply_agent_update(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload = parse_update_payload(payload_json);
        let request = match normalize_update_request(payload, &self.config.server_addr) {
            Ok(request) => request,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid update payload: {}", err);
                return;
            }
        };

        let update_dir = resolve_agent_data_dir().join("update");
        if let Err(err) = fs::create_dir_all(&update_dir) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("update staging dir failed: {}", err);
            return;
        }

        match spawn_update_worker(&request, &update_dir) {
            Ok(detail) => {
                exec.detail = detail;
            }
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("agent update launch failed: {}", err);
            }
        }
    }
}

fn normalize_update_request(
    payload: UpdatePayload,
    server_addr: &str,
) -> Result<NormalizedUpdateRequest, String> {
    let version = payload.version.trim().to_string();
    if !is_safe_version_string(&version) {
        return Err("version is required and must be a safe token".to_string());
    }

    let checksum_sha256 = normalize_sha256_checksum(&payload.checksum_sha256)?;
    let package_url = resolve_update_url(payload.package_url.trim(), server_addr)?;

    let hinted_kind = parse_package_kind_hint(payload.package_format.trim())?;
    let url_kind = infer_package_kind_from_url(&package_url);
    if let (Some(hinted), Some(inferred)) = (hinted_kind, url_kind) {
        if hinted != inferred {
            return Err("package_format does not match package_url extension".to_string());
        }
    }

    let package_kind = hinted_kind
        .or(url_kind)
        .unwrap_or(default_package_kind_for_target());
    enforce_package_kind_for_target(package_kind)?;

    Ok(NormalizedUpdateRequest {
        version,
        package_url,
        checksum_sha256,
        package_kind,
    })
}

fn is_safe_version_string(raw: &str) -> bool {
    if raw.is_empty() || raw.len() > 64 {
        return false;
    }
    raw.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '+'))
}

fn normalize_sha256_checksum(raw: &str) -> Result<String, String> {
    let checksum = raw.trim().to_ascii_lowercase();
    if checksum.is_empty() {
        return Err("checksum_sha256 is required".to_string());
    }
    if checksum.len() != 64 || !checksum.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("checksum_sha256 must be a 64-char hex digest".to_string());
    }
    Ok(checksum)
}

fn resolve_update_url(raw_url: &str, server_addr: &str) -> Result<String, String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err("package_url is required".to_string());
    }

    if trimmed.starts_with("https://") {
        return Ok(trimmed.to_string());
    }

    if trimmed.starts_with("http://") {
        let allow_http = std::env::var(UPDATE_ALLOW_HTTP_ENV)
            .ok()
            .map(|value| {
                value == "1"
                    || value.eq_ignore_ascii_case("true")
                    || value.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        if !allow_http {
            return Err(format!(
                "http package_url is blocked; set {}=1 to allow",
                UPDATE_ALLOW_HTTP_ENV
            ));
        }
        return Ok(trimmed.to_string());
    }

    if !trimmed.starts_with('/') {
        return Err("package_url must be absolute (https://...) or /api-relative".to_string());
    }

    let base = resolve_update_base_url(server_addr)?;
    Ok(format!("{}{}", base.trim_end_matches('/'), trimmed))
}

fn resolve_update_base_url(server_addr: &str) -> Result<String, String> {
    if let Ok(raw) = std::env::var(UPDATE_BASE_URL_ENV) {
        let value = raw.trim();
        if value.starts_with("https://") || value.starts_with("http://") {
            return Ok(value.trim_end_matches('/').to_string());
        }
        if !value.is_empty() {
            return Err(format!("{} must include http(s)://", UPDATE_BASE_URL_ENV));
        }
    }

    let host = extract_server_host(server_addr);
    if host.trim().is_empty() {
        return Err("unable to derive update host from server_addr".to_string());
    }

    let host_token = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host
    };

    let port = std::env::var(UPDATE_DEFAULT_HTTPS_PORT_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1443".to_string());

    Ok(format!("https://{}:{}", host_token, port))
}

fn parse_package_kind_hint(raw: &str) -> Result<Option<UpdatePackageKind>, String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(None);
    }

    match normalized.as_str() {
        "deb" => Ok(Some(UpdatePackageKind::LinuxDeb)),
        "rpm" => Ok(Some(UpdatePackageKind::LinuxRpm)),
        "exe" => Ok(Some(UpdatePackageKind::WindowsExe)),
        "msi" => Ok(Some(UpdatePackageKind::WindowsMsi)),
        "pkg" => Ok(Some(UpdatePackageKind::MacosPkg)),
        _ => Err("unsupported package_format".to_string()),
    }
}

fn infer_package_kind_from_url(url: &str) -> Option<UpdatePackageKind> {
    let lower = url
        .split('?')
        .next()
        .unwrap_or(url)
        .trim()
        .to_ascii_lowercase();

    if lower.ends_with(".deb") {
        Some(UpdatePackageKind::LinuxDeb)
    } else if lower.ends_with(".rpm") {
        Some(UpdatePackageKind::LinuxRpm)
    } else if lower.ends_with(".exe") {
        Some(UpdatePackageKind::WindowsExe)
    } else if lower.ends_with(".msi") {
        Some(UpdatePackageKind::WindowsMsi)
    } else if lower.ends_with(".pkg") {
        Some(UpdatePackageKind::MacosPkg)
    } else {
        None
    }
}

fn default_package_kind_for_target() -> UpdatePackageKind {
    #[cfg(target_os = "windows")]
    {
        return UpdatePackageKind::WindowsExe;
    }
    #[cfg(target_os = "macos")]
    {
        return UpdatePackageKind::MacosPkg;
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        UpdatePackageKind::LinuxDeb
    }
}

fn enforce_package_kind_for_target(kind: UpdatePackageKind) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        if !matches!(
            kind,
            UpdatePackageKind::WindowsExe | UpdatePackageKind::WindowsMsi
        ) {
            return Err("windows agent accepts only .exe or .msi updates".to_string());
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        if kind != UpdatePackageKind::MacosPkg {
            return Err("macOS agent accepts only .pkg updates".to_string());
        }
        return Ok(());
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if !matches!(
            kind,
            UpdatePackageKind::LinuxDeb | UpdatePackageKind::LinuxRpm
        ) {
            return Err("linux agent accepts only .deb or .rpm updates".to_string());
        }
    }

    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn spawn_update_worker(
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    let format = match request.package_kind {
        UpdatePackageKind::LinuxDeb => "deb",
        UpdatePackageKind::LinuxRpm => "rpm",
        _ => return Err("unsupported linux update package".to_string()),
    };

    let script_path = update_dir.join("apply-agent-update-worker.sh");
    write_linux_update_worker_script(&script_path)?;

    let script_args = vec![
        "--update-dir".to_string(),
        update_dir.to_string_lossy().to_string(),
        "--version".to_string(),
        request.version.clone(),
        "--checksum".to_string(),
        request.checksum_sha256.clone(),
        "--url".to_string(),
        request.package_url.clone(),
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
        request.package_url, format
    ))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
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

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
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

#[cfg(target_os = "windows")]
fn spawn_update_worker(
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    let package_kind = match request.package_kind {
        UpdatePackageKind::WindowsExe => "exe",
        UpdatePackageKind::WindowsMsi => "msi",
        _ => return Err("unsupported windows update package".to_string()),
    };

    let worker_path = update_dir.join("apply-agent-update-worker.ps1");
    write_windows_update_worker_script(&worker_path)?;

    let log_path = update_dir.join("apply-agent-update-worker.log");
    Command::new("powershell")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(&worker_path)
        .arg("-PackageUrl")
        .arg(&request.package_url)
        .arg("-ExpectedSha256")
        .arg(&request.checksum_sha256)
        .arg("-TargetVersion")
        .arg(&request.version)
        .arg("-PackageKind")
        .arg(package_kind)
        .arg("-WorkingDir")
        .arg(update_dir.to_string_lossy().to_string())
        .arg("-LogPath")
        .arg(log_path.to_string_lossy().to_string())
        .spawn()
        .map_err(|err| format!("spawn powershell update worker: {}", err))?;

    Ok(format!(
        "agent update worker started (url={}, kind={})",
        request.package_url, package_kind
    ))
}

#[cfg(target_os = "windows")]
fn write_windows_update_worker_script(path: &Path) -> Result<(), String> {
    const SCRIPT: &str = r#"param(
    [Parameter(Mandatory=$true)] [string]$PackageUrl,
    [Parameter(Mandatory=$true)] [string]$ExpectedSha256,
    [Parameter(Mandatory=$true)] [string]$TargetVersion,
    [Parameter(Mandatory=$true)] [string]$PackageKind,
    [Parameter(Mandatory=$true)] [string]$WorkingDir,
    [Parameter(Mandatory=$true)] [string]$LogPath
)

$ErrorActionPreference = 'Stop'

function Write-Log {
    param([string]$Message)
    $line = "$(Get-Date -Format o) $Message"
    Add-Content -Path $LogPath -Value $line
}

try {
    New-Item -ItemType Directory -Path $WorkingDir -Force | Out-Null
    $ext = if ($PackageKind -eq 'msi') { 'msi' } else { 'exe' }
    $pkgPath = Join-Path $WorkingDir ("eguard-agent-$TargetVersion.$ext")
    $tmpPath = "$pkgPath.download"

    Write-Log "downloading update from $PackageUrl"
    Invoke-WebRequest -Uri $PackageUrl -OutFile $tmpPath -UseBasicParsing

    $actual = (Get-FileHash -Path $tmpPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = $ExpectedSha256.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "sha256 mismatch: expected $expected got $actual"
    }

    Move-Item -Path $tmpPath -Destination $pkgPath -Force
    $serviceName = 'eGuardAgent'

    if ($PackageKind -eq 'msi') {
        Write-Log "installing MSI package"
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $pkgPath, '/qn', '/norestart') -Wait -NoNewWindow
        Start-Service -Name $serviceName -ErrorAction SilentlyContinue
        Write-Log "MSI update finished"
        exit 0
    }

    $agentPath = 'C:\Program Files\eGuard\eguard-agent.exe'
    $backupPath = "${agentPath}.backup-$(Get-Date -Format yyyyMMddHHmmss)"

    Write-Log "stopping service $serviceName"
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    if (Test-Path $agentPath) {
        Copy-Item -Path $agentPath -Destination $backupPath -Force
    }

    Copy-Item -Path $pkgPath -Destination $agentPath -Force
    Start-Service -Name $serviceName
    Write-Log "EXE update finished"
}
catch {
    Write-Log "update failed: $($_.Exception.Message)"
    exit 1
}
"#;

    fs::write(path, SCRIPT)
        .map_err(|err| format!("write update worker script {}: {}", path.display(), err))
}

#[cfg(target_os = "macos")]
fn spawn_update_worker(
    _request: &NormalizedUpdateRequest,
    _update_dir: &Path,
) -> Result<String, String> {
    Err("macOS update worker is not implemented yet".to_string())
}
