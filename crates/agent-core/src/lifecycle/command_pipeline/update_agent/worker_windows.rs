use std::fs;
use std::path::Path;
use std::process::Command;

use super::request::NormalizedUpdateRequest;

pub(super) fn spawn_update_worker(
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    let package_kind = request
        .package_kind()
        .as_windows_kind()
        .ok_or_else(|| "unsupported windows update package".to_string())?;

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
        .arg(request.package_url())
        .arg("-ExpectedSha256")
        .arg(request.checksum_sha256())
        .arg("-TargetVersion")
        .arg(request.version())
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
        request.package_url(),
        package_kind
    ))
}

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
