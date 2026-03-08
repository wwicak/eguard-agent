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

function Get-ServiceProcessId {
    param([string]$ServiceName)
    try {
        $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        return [int]$service.ProcessId
    }
    catch {
        return 0
    }
}

function Restore-ServicePolicy {
    param([string]$ServiceName, [string]$BinaryPath)
    & sc.exe config $ServiceName binPath= "\"$BinaryPath\"" 2>$null | Out-Null
    & sc.exe config $ServiceName start= auto 2>$null | Out-Null
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>$null | Out-Null
    & sc.exe failureflag $ServiceName 1 2>$null | Out-Null
}

function Stop-AgentService {
    param([string]$ServiceName)
    Write-Log "stopping service $ServiceName"
    & sc.exe failure $ServiceName reset= 0 actions= "" 2>$null | Out-Null
    & sc.exe failureflag $ServiceName 0 2>$null | Out-Null
    & sc.exe config $ServiceName start= demand 2>$null | Out-Null
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue

    $stopWait = 0
    while ($stopWait -lt 15) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service -or $service.Status -eq 'Stopped') { break }
        Start-Sleep -Seconds 1
        $stopWait++
    }

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        $runningProc = Get-Process -Name 'eguard-agent' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($runningProc) {
            Write-Log "taskkill fallback for pid $($runningProc.Id)"
            & taskkill /F /PID $runningProc.Id /T | Out-Null
            Start-Sleep -Seconds 3
        }
    }

    $remainingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $remainingProc = Get-Process -Name 'eguard-agent' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (($remainingService -and $remainingService.Status -ne 'Stopped') -or $remainingProc) {
        throw "service or eguard-agent.exe still running after stop attempt"
    }
}

function Verify-FileHash {
    param([string]$Path, [string]$ExpectedSha256)
    $actual = (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = $ExpectedSha256.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "sha256 mismatch: expected $expected got $actual"
    }
    return $actual
}

try {
    New-Item -ItemType Directory -Path $WorkingDir -Force | Out-Null
    $ext = if ($PackageKind -eq 'msi') { 'msi' } else { 'exe' }
    $pkgPath = Join-Path $WorkingDir ("eguard-agent-$TargetVersion.$ext")
    $tmpPath = "$pkgPath.download"
    $serviceName = 'eGuardAgent'
    $agentPath = 'C:\Program Files\eGuard\eguard-agent.exe'
    $backupPath = "${agentPath}.backup-$(Get-Date -Format yyyyMMddHHmmss)"

    Write-Log "downloading update from $PackageUrl"
    Invoke-WebRequest -Uri $PackageUrl -OutFile $tmpPath -UseBasicParsing
    $downloadHash = Verify-FileHash -Path $tmpPath -ExpectedSha256 $ExpectedSha256
    Write-Log "download verified sha256=$downloadHash"

    Move-Item -Path $tmpPath -Destination $pkgPath -Force

    if ($PackageKind -eq 'msi') {
        Stop-AgentService -ServiceName $serviceName
        Write-Log "installing MSI package"
        Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $pkgPath, '/qn', '/norestart') -Wait -NoNewWindow
        Restore-ServicePolicy -ServiceName $serviceName -BinaryPath $agentPath
        Start-Service -Name $serviceName -ErrorAction SilentlyContinue
        Write-Log "MSI update finished"
        exit 0
    }

    Stop-AgentService -ServiceName $serviceName

    if (Test-Path $agentPath) {
        Copy-Item -Path $agentPath -Destination $backupPath -Force
    }

    Copy-Item -Path $pkgPath -Destination $agentPath -Force
    $installedHash = Verify-FileHash -Path $agentPath -ExpectedSha256 $ExpectedSha256
    Restore-ServicePolicy -ServiceName $serviceName -BinaryPath $agentPath
    Start-Service -Name $serviceName
    Write-Log "EXE update finished (installed_sha256=$installedHash)"
}
catch {
    try {
        Restore-ServicePolicy -ServiceName $serviceName -BinaryPath $agentPath
    }
    catch {
        Write-Log "failed to restore service policy after error: $($_.Exception.Message)"
    }
    Write-Log "update failed: $($_.Exception.Message)"
    exit 1
}
"#;

    fs::write(path, SCRIPT)
        .map_err(|err| format!("write update worker script {}: {}", path.display(), err))
}
