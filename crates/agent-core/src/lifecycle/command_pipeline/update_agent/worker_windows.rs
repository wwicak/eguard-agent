use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut std::ffi::c_void,
        buffer: *mut u8,
        buffer_len: u32,
        flags: u32,
    ) -> i32;
}

use super::request::NormalizedUpdateRequest;

pub(super) fn spawn_update_worker(
    command_id: &str,
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    let package_kind = request
        .package_kind()
        .as_windows_kind()
        .ok_or_else(|| "unsupported windows update package".to_string())?;

    let worker_path = update_dir.join("apply-agent-update-worker.ps1");
    write_windows_update_worker_script(&worker_path)?;

    let artifact_id = durable_artifact_id()?;
    let startup_path = update_dir.join(format!("update-startup-{}.txt", artifact_id));
    let _ = fs::remove_file(&startup_path);
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&startup_path)
        .and_then(|mut file| {
            use std::io::Write;
            write!(file, "{}:pending", artifact_id)
        })
        .map_err(|err| format!("reserve update worker startup path: {}", err))?;
    let log_path = update_dir.join("apply-agent-update-worker.log");
    let child = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(&worker_path)
        .arg("-CommandId")
        .arg(command_id)
        .arg("-ArtifactId")
        .arg(&artifact_id)
        .arg("-StartupPath")
        .arg(&startup_path)
        .arg("-StartupToken")
        .arg(&artifact_id)
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
        .map_err(|err| {
            let _ = fs::remove_file(&startup_path);
            format!("spawn powershell update worker: {}", err)
        })?;

    wait_for_worker_startup(child, &startup_path, &artifact_id)?;

    Ok(format!(
        "agent update worker started (url={}, kind={})",
        request.package_url(),
        package_kind
    ))
}

fn wait_for_worker_startup(
    mut child: std::process::Child,
    startup_path: &Path,
    startup_token: &str,
) -> Result<std::process::Child, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Ok(status) = fs::read_to_string(startup_path) {
            match status.trim().strip_prefix(&format!("{}:", startup_token)) {
                Some("ready") => {
                    let _ = fs::remove_file(startup_path);
                    return Ok(child);
                }
                Some("busy") => {
                    let _ = fs::remove_file(startup_path);
                    return Err(
                        "another agent update is already in progress on this host; refusing to run concurrently"
                            .to_string(),
                    );
                }
                _ => {}
            }
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("wait for powershell update worker startup: {}", err))?
        {
            return Err(format!(
                "powershell update worker exited before acquiring the update lock: {}",
                status
            ));
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            return Err(
                "timed out waiting for update worker to acquire the host-wide lock".to_string(),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn durable_artifact_id() -> Result<String, String> {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    let mut bytes = [0u8; 16];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(format!(
            "generate durable update worker token: BCryptGenRandom status 0x{:08x}",
            status as u32
        ));
    }
    Ok(bytes.iter().map(|byte| format!("{:02x}", byte)).collect())
}

fn write_windows_update_worker_script(path: &Path) -> Result<(), String> {
    const SCRIPT: &str = r#"param(
    [Parameter(Mandatory=$true)] [string]$CommandId,
    [Parameter(Mandatory=$true)] [string]$ArtifactId,
    [Parameter(Mandatory=$true)] [string]$StartupPath,
    [Parameter(Mandatory=$true)] [string]$StartupToken,
    [Parameter(Mandatory=$true)] [string]$PackageUrl,
    [Parameter(Mandatory=$true)] [string]$ExpectedSha256,
    [Parameter(Mandatory=$true)] [string]$TargetVersion,
    [Parameter(Mandatory=$true)] [string]$PackageKind,
    [Parameter(Mandatory=$true)] [string]$WorkingDir,
    [Parameter(Mandatory=$true)] [string]$LogPath
)

$ErrorActionPreference = 'Stop'
# Invoke-WebRequest renders a progress bar by default, which slows the package
# download to a crawl (and can appear to hang) in non-interactive/service
# contexts. Suppress it so the download runs at full speed.
$ProgressPreference = 'SilentlyContinue'
$outcomePath = Join-Path $WorkingDir ("update-outcome-" + $CommandId + ".txt")

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

function Get-ServiceBinaryPath {
    param([string]$ServiceName)
    # Let CIM query failures propagate: a transient failure must not be mistaken
    # for "service absent" and cause a silent fall back to a default path (which
    # could update/verify the wrong binary). Only a genuinely missing service
    # yields an empty result.
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    if (-not $service) { return '' }
    $raw = [string]$service.PathName
    if (-not $raw) { return '' }
    $raw = $raw.Trim()
    if ($raw.StartsWith('"')) {
        $end = $raw.IndexOf('"', 1)
        if ($end -gt 1) { return $raw.Substring(1, $end - 1) }
        return $raw.Trim('"')
    }
    $match = [regex]::Match($raw, '^(?<p>.*\.exe)(?=(\s|$))', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($match.Success) { return $match.Groups['p'].Value }
    return $raw
}

function Test-TrackedProcessAlive {
    # True only if the pid is alive AND resolves to the same process instance we
    # captured (verified by start time). Without a captured start time we cannot
    # prove identity, so the pid is treated as NOT tracked -- a reused pid is never
    # mistaken for, or force-killed as, the original agent process.
    param([int]$ProcessId, $StartTime)
    if ($ProcessId -le 0) { return $false }
    if ($null -eq $StartTime) { return $false }
    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $proc) { return $false }
    try { if ($proc.StartTime -ne $StartTime) { return $false } } catch { return $false }
    return $true
}

function Invoke-Sc {
    # Run sc.exe and THROW on any nonzero exit. Native nonzero exits do not throw
    # under Windows PowerShell 5.1 even with $ErrorActionPreference='Stop', so
    # critical service-policy operations (suppressing/restoring auto-restart) would
    # otherwise fail silently -- e.g. an unsuppressed failure action could respawn
    # the service mid-update, or a completed outcome could hide a lost start type.
    param([string[]]$Arguments)
    $output = & sc.exe @Arguments 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        $detail = "sc.exe " + ($Arguments -join ' ') + " exited " + $code + ": " + ($output -join ' ')
        Write-Log $detail
        throw $detail
    }
}

function Write-Outcome {
    param([string]$Status, [string]$Detail)
    @($CommandId, $Status, $Detail) | Set-Content -Path $outcomePath -Encoding UTF8
}

function Write-Startup {
    param([string]$Status)
    $startupTmp = "$StartupPath.tmp"
    Set-Content -Path $startupTmp -Value ("$StartupToken`:$Status") -Encoding ASCII
    Move-Item -Path $startupTmp -Destination $StartupPath -Force
}

function Restore-ServiceStartPolicy {
    # Restore auto-start and failure/restart actions after a stop. Deliberately does
    # NOT touch binPath: the MSI owns the service registration and the EXE path
    # replaces the binary in place, so rewriting binPath here can only point the
    # service at the wrong lineage or drop legitimate service arguments.
    param([string]$ServiceName)
    Invoke-Sc @('config', $ServiceName, 'start=', 'auto') | Out-Null
    Invoke-Sc @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/10000/restart/30000') | Out-Null
    Invoke-Sc @('failureflag', $ServiceName, '1') | Out-Null
}

function Stop-AgentService {
    param([string]$ServiceName)
    Write-Log "stopping service $ServiceName"
    # Capture the service's real PID and start time up front. Identity is keyed on
    # (pid, start time) so a reused pid is never force-killed as if it were the
    # agent. The image name is not assumed (installs may run eguard-agent.exe or
    # agent-core.exe); the force-kill targets the actual service process id.
    $targetPid = Get-ServiceProcessId -ServiceName $ServiceName
    $targetStart = $null
    if ($targetPid -gt 0) {
        $tp = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
        if ($tp) { $targetStart = $tp.StartTime }
    }

    # Suspend auto-restart so a force-killed service does not respawn mid-update.
    # The empty actions value must be the literal string '""' -- PowerShell drops a
    # bare empty-string native arg, which makes sc.exe reject the command (1639).
    Invoke-Sc @('failure', $ServiceName, 'reset=', '0', 'actions=', '""') | Out-Null
    Invoke-Sc @('failureflag', $ServiceName, '0') | Out-Null
    Invoke-Sc @('config', $ServiceName, 'start=', 'demand') | Out-Null

    $maxAttempts = 4
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue

        $waited = 0
        while ($waited -lt 15) {
            $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            $currentPid = Get-ServiceProcessId -ServiceName $ServiceName
            $stopped = (-not $service) -or ($service.Status -eq 'Stopped')
            if ($stopped -and $currentPid -le 0 -and -not (Test-TrackedProcessAlive -ProcessId $targetPid -StartTime $targetStart)) { break }
            Start-Sleep -Seconds 1
            $waited++
        }

        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $currentPid = Get-ServiceProcessId -ServiceName $ServiceName
        $stopped = (-not $service) -or ($service.Status -eq 'Stopped')
        if ($stopped -and $currentPid -le 0 -and -not (Test-TrackedProcessAlive -ProcessId $targetPid -StartTime $targetStart)) {
            Write-Log "service $ServiceName stopped on attempt $attempt"
            return
        }

        # Force-kill only pids proven to belong to this service right now: the PID
        # SCM currently reports, and the tracked start PID iff its start time still
        # matches. No /T: the update worker is a child of the agent and must survive.
        $killPids = New-Object System.Collections.Generic.List[int]
        if ($currentPid -gt 0) { [void]$killPids.Add($currentPid) }
        if (($targetPid -ne $currentPid) -and (Test-TrackedProcessAlive -ProcessId $targetPid -StartTime $targetStart)) { [void]$killPids.Add($targetPid) }
        foreach ($killPid in $killPids) {
            Write-Log "force killing agent pid $killPid (attempt $attempt)"
            & taskkill /F /PID $killPid 2>$null | Out-Null
        }
        Start-Sleep -Seconds 2
    }

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $currentPid = Get-ServiceProcessId -ServiceName $ServiceName
    $serviceState = if ($service) { [string]$service.Status } else { 'Absent' }
    if (($service -and $service.Status -ne 'Stopped') -or $currentPid -gt 0 -or (Test-TrackedProcessAlive -ProcessId $targetPid -StartTime $targetStart)) {
        throw "agent service did not stop after $maxAttempts attempts (service=$serviceState, targetPid=$targetPid, currentPid=$currentPid)"
    }
    Write-Log "service $ServiceName confirmed stopped (targetPid=$targetPid)"
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

function Normalize-Version {
    param([string]$Value)
    return ($Value.Trim() -replace '^[vV]', '')
}

function Verify-AgentVersion {
    param([string]$BinaryPath, [string]$ExpectedVersion)
    if (-not (Test-Path $BinaryPath)) {
        throw "agent binary missing after package install: $BinaryPath"
    }

    $hadVersionOverride = Test-Path Env:EGUARD_AGENT_VERSION
    $savedVersionOverride = $env:EGUARD_AGENT_VERSION
    Remove-Item Env:EGUARD_AGENT_VERSION -ErrorAction SilentlyContinue
    try {
        $output = & $BinaryPath --version 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        if ($hadVersionOverride) { $env:EGUARD_AGENT_VERSION = $savedVersionOverride }
    }
    if ($exitCode -ne 0) {
        throw "agent binary version check failed after package install (exit=$exitCode): $($output -join ' ')"
    }

    $actual = [string]($output | Select-Object -First 1)
    if ((Normalize-Version $actual) -ne (Normalize-Version $ExpectedVersion)) {
        throw "agent binary version mismatch after package install: expected $ExpectedVersion got $actual"
    }
    return $actual.Trim()
}

function Start-AgentServiceAndWait {
    param([string]$ServiceName)
    Start-Service -Name $ServiceName

    $startWait = 0
    while ($startWait -lt 30) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $serviceProcessId = Get-ServiceProcessId -ServiceName $ServiceName
        if ($service -and $service.Status -eq 'Running' -and $serviceProcessId -gt 0) {
            return $serviceProcessId
        }
        Start-Sleep -Seconds 1
        $startWait++
    }
    throw "agent service did not reach Running after package install"
}

function Start-AgentServiceAndVerifyVersion {
    param([string]$ServiceName, [string]$ExpectedVersion)
    Start-Service -Name $ServiceName

    $startWait = 0
    while ($startWait -lt 30) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $serviceProcessId = Get-ServiceProcessId -ServiceName $ServiceName
        if ($service -and $service.Status -eq 'Running' -and $serviceProcessId -gt 0) {
            $proc = Get-Process -Id $serviceProcessId -ErrorAction SilentlyContinue
            if ($proc -and $proc.Path) {
                $runningVersion = Verify-AgentVersion -BinaryPath $proc.Path -ExpectedVersion $ExpectedVersion
                return @($serviceProcessId, $runningVersion)
            }
        }
        Start-Sleep -Seconds 1
        $startWait++
    }

    throw "agent service did not reach Running on target version $ExpectedVersion after package install"
}

function Restore-AgentBinaryIfAbsent {
    param([string]$AgentPath, [string]$BackupPath, [string]$ScratchPath, [string]$StagedPath)
    # Idempotent, filesystem-state-driven recovery: if the live binary slot is
    # empty (a partial ReplaceFile can leave it so, even during a rollback), move
    # the best available source into it. Each move is a plain rename into an ABSENT
    # destination (no -Force, so a raced re-creation of the target is never
    # clobbered by a delete-then-move) and the target is re-checked after every
    # attempt, so this is safe to call repeatedly. Preference order, best first:
    # the pre-update backup (the last-known-good binary); then the rollback scratch
    # (which may hold the binary that just failed verification -- a signed,
    # hash-correct executable, promoted only as a last-resort availability
    # fallback); then the hash-verified staged binary. Restoring EDR availability
    # takes priority over restoring the exact prior version, and the update outcome
    # is still reported 'failed' regardless of which source is used.
    foreach ($src in @($BackupPath, $ScratchPath, $StagedPath)) {
        if (Test-Path $AgentPath) { return }
        if ($src -and (Test-Path $src)) {
            try {
                Move-Item -Path $src -Destination $AgentPath
                Write-Log "recovered agent binary into absent target from $src"
            }
            catch {
                Write-Log "recovery move from $src failed: $($_.Exception.Message)"
            }
        }
    }
}

New-Item -ItemType Directory -Path $WorkingDir -Force | Out-Null
$lockPath = Join-Path $WorkingDir 'agent-update.lock'
$lockStream = $null
try {
    $lockStream = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
}
catch [System.IO.IOException] {
    $detail = "another agent update is already in progress on this host; refusing to run concurrently"
    Write-Log $detail
    Write-Outcome -Status 'failed' -Detail $detail
    Write-Startup -Status 'busy'
    exit 1
}
Write-Startup -Status 'ready'

$pkgPath = $null
$tmpPath = $null
try {
    # Bound stale command-specific download artifacts after taking the lock.
    Get-ChildItem -Path $WorkingDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -lt (Get-Date).ToUniversalTime().AddDays(-1) -and $_.Name -match '^eguard-agent-.*\.(msi|exe)(\.download)?$' } |
        Remove-Item -Force -ErrorAction SilentlyContinue

    $ext = if ($PackageKind -eq 'msi') { 'msi' } else { 'exe' }
    $pkgPath = Join-Path $WorkingDir ("eguard-agent-$TargetVersion-$ArtifactId.$ext")
    $tmpPath = "$pkgPath.download"
    $serviceName = 'eGuardAgent'
    # Resolve the binary the service actually runs instead of assuming a fixed
    # location. Installs can land under Program Files or Program Files (x86) and
    # use different executable names; a hardcoded path silently verifies/updates
    # the wrong binary. Fall back to the historical default only when the service
    # is absent (e.g. a first-time install creating it).
    $defaultAgentPath = 'C:\Program Files\eGuard\eguard-agent.exe'
    $serviceBinaryPath = Get-ServiceBinaryPath -ServiceName $serviceName
    $agentPath = if ($serviceBinaryPath) { $serviceBinaryPath } else { $defaultAgentPath }
    Write-Log "resolved agent binary path: $agentPath"
    $agentDir = Split-Path -Parent $agentPath
    Get-ChildItem -Path $agentDir -Directory -Filter '.eguard-update-*' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -lt (Get-Date).ToUniversalTime().AddDays(-1) } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    $artifactDir = Join-Path $agentDir ('.eguard-update-' + $ArtifactId)
    New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
    $backupPath = Join-Path $artifactDir 'agent.backup'
    # Rollback tracking for the in-place EXE path: once we begin overwriting the
    # live binary, a failure must restore the backup before any restart attempt.
    $exeBackupCreated = $false
    $exeReplaced = $false
    $stagedPath = $null

    Write-Log "downloading update from $PackageUrl"
    Invoke-WebRequest -Uri $PackageUrl -OutFile $tmpPath -UseBasicParsing
    $downloadHash = Verify-FileHash -Path $tmpPath -ExpectedSha256 $ExpectedSha256
    Write-Log "download verified sha256=$downloadHash"

    Move-Item -Path $tmpPath -Destination $pkgPath -Force

    if ($PackageKind -eq 'msi') {
        Stop-AgentService -ServiceName $serviceName
        Write-Log "installing MSI package"
        $msiProcess = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $pkgPath, '/qn', '/norestart') -Wait -NoNewWindow -PassThru
        if ($msiProcess.ExitCode -ne 0 -and $msiProcess.ExitCode -ne 3010) {
            throw "msi package install failed with exit code $($msiProcess.ExitCode)"
        }
        # The MSI owns its install location and rewrites the service binPath, so
        # re-read it and verify against the binary the MSI actually registered. An
        # empty post-install path is fatal: never fall back to the pre-MSI lineage.
        $installedBinaryPath = Get-ServiceBinaryPath -ServiceName $serviceName
        if (-not $installedBinaryPath) { throw "service binary path empty after msi install" }
        Write-Log "post-install agent binary path: $installedBinaryPath"
        $installedVersion = Verify-AgentVersion -BinaryPath $installedBinaryPath -ExpectedVersion $TargetVersion
        Restore-ServiceStartPolicy -ServiceName $serviceName
        $running = Start-AgentServiceAndVerifyVersion -ServiceName $serviceName -ExpectedVersion $TargetVersion
        $servicePid = $running[0]
        $runningVersion = $running[1]
        Write-Log "MSI update finished (observed_version=$installedVersion, running_version=$runningVersion, pid=$servicePid, binary=$installedBinaryPath)"
        Write-Outcome -Status 'completed' -Detail ("agent update applied (version=" + $TargetVersion + ", kind=msi, observed_version=" + $installedVersion + ", running_version=" + $runningVersion + ", binary=" + $installedBinaryPath + ")")
        exit 0
    }

    # Stage the new binary beside the target and verify its hash BEFORE stopping
    # the service, so a corrupt package never takes the agent offline.
    $stagedPath = Join-Path $artifactDir 'agent.new'
    Copy-Item -Path $pkgPath -Destination $stagedPath -Force
    $stagedHash = Verify-FileHash -Path $stagedPath -ExpectedSha256 $ExpectedSha256
    Write-Log "staged EXE verified sha256=$stagedHash"

    Stop-AgentService -ServiceName $serviceName

    # Atomic replace via the Win32 ReplaceFile primitive ([IO.File]::Replace): it
    # swaps the staged binary into place and moves the previous binary to the
    # backup in a single atomic step, so a crash/power loss can never leave the
    # target absent or partial. (Move-Item -Force is NOT atomic -- PowerShell
    # implements forced overwrite as delete-then-move.) A first install has no
    # existing binary to replace/back up, so a plain move is correct there.
    $exeReplaced = $true
    if (Test-Path $agentPath) {
        [System.IO.File]::Replace($stagedPath, $agentPath, $backupPath, $true)
        $exeBackupCreated = $true
    }
    else {
        # First install: the target slot is absent, so a plain rename is atomic
        # (no -Force, so a raced creation is never clobbered by delete-then-move).
        Move-Item -Path $stagedPath -Destination $agentPath
    }
    $installedHash = Verify-FileHash -Path $agentPath -ExpectedSha256 $ExpectedSha256
    $installedVersion = Verify-AgentVersion -BinaryPath $agentPath -ExpectedVersion $TargetVersion
    Restore-ServiceStartPolicy -ServiceName $serviceName
    $running = Start-AgentServiceAndVerifyVersion -ServiceName $serviceName -ExpectedVersion $TargetVersion
    $servicePid = $running[0]
    $runningVersion = $running[1]
    $exeReplaced = $false
    if ($exeBackupCreated -and (Test-Path $backupPath)) {
        Remove-Item -Path $backupPath -Force -ErrorAction SilentlyContinue
    }
    Write-Log "EXE update finished (installed_sha256=$installedHash, observed_version=$installedVersion, running_version=$runningVersion, pid=$servicePid)"
    Write-Outcome -Status 'completed' -Detail ("agent update applied (version=" + $TargetVersion + ", kind=exe, sha256=" + $installedHash + ", observed_version=" + $installedVersion + ", running_version=" + $runningVersion + ")")
}
catch {
    $updateError = $_
    # Ensure a known-good agent binary is on disk BEFORE any restart. ReplaceFile
    # can fail with ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 (the original was already
    # moved to the backup but the staged replacement was not moved in), which
    # leaves the target absent -- so recovery must inspect the REAL filesystem
    # state rather than trust the in-memory flags. (MSI manages its own rollback.)
    $scratch = Join-Path $artifactDir 'agent.bad'
    if ($exeReplaced) {
        # Case 1: the replace fully succeeded but a later verification failed, so
        # the new (bad) binary is in place; atomically roll the known-good backup
        # back over it. This ReplaceFile can ITSELF fail partway (the current
        # target moved to $scratch but the backup not moved in), so it is only the
        # first attempt -- the filesystem-driven pass below is the real guarantee.
        if ((Test-Path $agentPath) -and $exeBackupCreated -and (Test-Path $backupPath)) {
            try {
                [System.IO.File]::Replace($backupPath, $agentPath, $scratch, $true)
                Write-Log "rolled back to pre-update binary after post-replace verification failure"
            }
            catch {
                Write-Log "rollback replace failed, deferring to filesystem recovery: $($_.Exception.Message)"
            }
        }
        # Case 2 (the real guarantee): if the target slot is empty for ANY reason
        # -- a partial forward replace or a partial rollback replace -- restore a
        # binary into it, preferring the known-good backup and falling back to the
        # rollback scratch or staged file only to keep the EDR service runnable.
        Restore-AgentBinaryIfAbsent -AgentPath $agentPath -BackupPath $backupPath -ScratchPath $scratch -StagedPath $stagedPath
    }
    # Discard the rollback scratch copy (the displaced bad binary) now that the
    # target is settled; never touch it while the target might still need it.
    if ((Test-Path $agentPath) -and (Test-Path $scratch)) {
        Remove-Item -Path $scratch -Force -ErrorAction SilentlyContinue
    }
    # Clean up any leftover staged binary ONLY when the target actually exists, so
    # cleanup can never discard the sole remaining valid binary if recovery failed.
    if ((Test-Path $agentPath) -and $stagedPath -and (Test-Path $stagedPath)) {
        Remove-Item -Path $stagedPath -Force -ErrorAction SilentlyContinue
    }
    # Restore start policy and bring the service back up as INDEPENDENT best-effort
    # steps: a failure in one must not prevent the other. Restarting the EDR agent
    # takes priority so a failed update never leaves the endpoint unprotected.
    try { Restore-ServiceStartPolicy -ServiceName $serviceName }
    catch { Write-Log "failed to restore service start policy after error: $($_.Exception.Message)" }
    try {
        $recoveredPid = Start-AgentServiceAndWait -ServiceName $serviceName
        Write-Log "service recovered after failed update (pid=$recoveredPid)"
    }
    catch {
        Write-Log "service restart after failed update did not complete: $($_.Exception.Message)"
    }
    $detail = "update failed: $($updateError.Exception.Message)"
    Write-Log $detail
    Write-Outcome -Status 'failed' -Detail $detail
    exit 1
}
finally {
    if ($tmpPath -and (Test-Path $tmpPath)) { Remove-Item -Path $tmpPath -Force -ErrorAction SilentlyContinue }
    if ($pkgPath -and (Test-Path $pkgPath)) { Remove-Item -Path $pkgPath -Force -ErrorAction SilentlyContinue }
    if ($artifactDir -and (Test-Path $agentPath) -and (Test-Path $artifactDir)) { Remove-Item -Path $artifactDir -Recurse -Force -ErrorAction SilentlyContinue }
    if ($lockStream) { $lockStream.Dispose() }
}
"#;

    // Write-then-rename onto a UNIQUE per-invocation temp so a later update
    // command rewriting this script cannot truncate or torn-activate it while an
    // earlier worker's PowerShell may still be reading the previous script. A
    // shared temp could be reopened/truncated by a second writer in the window
    // between this writer's write and its rename; a private (pid + atomic seq)
    // temp cannot be touched by another writer, and fs::rename is atomic (Windows
    // MoveFileEx replace-existing) once the complete temp exists, leaving the old
    // file intact for a worker still reading it.
    static SCRIPT_TMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp_path = path.with_extension(format!(
        "ps1.tmp.{}.{}",
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
#[cfg(target_os = "windows")]
mod tests {
    use super::*;

    fn spawn_lock_probe(lock_path: &Path, startup_path: &Path, token: &str) -> std::process::Child {
        let probe = r#"
param([string]$LockPath, [string]$StartupPath, [string]$Token)
try {
  $lock = [System.IO.File]::Open($LockPath, 'OpenOrCreate', 'ReadWrite', 'None')
} catch [System.IO.IOException] {
  Set-Content -Path $StartupPath -Value ("$Token`:busy") -Encoding ASCII
  exit 1
}
Set-Content -Path $StartupPath -Value ("$Token`:ready") -Encoding ASCII
Start-Sleep -Seconds 30
$lock.Dispose()
"#;
        Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", probe])
            .arg(lock_path)
            .arg(startup_path)
            .arg(token)
            .spawn()
            .expect("spawn lock probe")
    }

    #[test]
    fn second_worker_reports_busy_through_startup_handshake() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join("agent-update.lock");
        let first_token = durable_artifact_id().expect("first token");
        let first_startup = dir.path().join(format!("startup-{first_token}"));
        let first = spawn_lock_probe(&lock_path, &first_startup, &first_token);
        let mut first = wait_for_worker_startup(first, &first_startup, &first_token)
            .expect("first worker acquires lock");

        let second_token = durable_artifact_id().expect("second token");
        let second_startup = dir.path().join(format!("startup-{second_token}"));
        let second = spawn_lock_probe(&lock_path, &second_startup, &second_token);
        let err = wait_for_worker_startup(second, &second_startup, &second_token)
            .expect_err("second worker must report busy");
        assert_eq!(
            err,
            "another agent update is already in progress on this host; refusing to run concurrently"
        );
        first.kill().expect("stop first probe");
        first.wait().expect("reap first probe");
    }

    #[test]
    fn artifact_ids_are_unique_per_invocation() {
        let first = durable_artifact_id().expect("first random token");
        let second = durable_artifact_id().expect("second random token");
        assert_ne!(first, second);
        assert_ne!(
            Path::new("C:\\update").join(format!("eguard-agent-1.2.3-{}.exe", first)),
            Path::new("C:\\update").join(format!("eguard-agent-1.2.3-{}.exe", second))
        );
        assert_ne!(
            Path::new("C:\\Program Files\\eGuard").join(format!(".eguard-update-{}", first)),
            Path::new("C:\\Program Files\\eGuard").join(format!(".eguard-update-{}", second))
        );
    }
}
