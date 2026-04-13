param(
    [Parameter(Mandatory = $true)]
    [string]$ServerUrl,

    [Parameter(Mandatory = $true)]
    [string]$EnrollmentToken,

    [string]$MsiPath = "$env:TEMP\eguard-agent-latest.msi",

    [string]$ExpectedHash = "",

    [switch]$AllowInsecureHttp,

    [switch]$AllowUnsignedMsi,

    [switch]$KeepBootstrap
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host "[eGuard-install] $Message"
}

function Get-TrayPath {
    return Join-Path ${env:ProgramFiles} 'eGuard\eguard-tray.exe'
}

function Prepare-AgentServiceForUpgrade {
    $serviceName = 'eGuardAgent'
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Step "No existing $serviceName service detected before MSI install"
        return
    }

    Write-Step "Temporarily disabling $serviceName recovery actions for MSI upgrade"
    & sc.exe failure $serviceName reset= 0 actions= ""/0 2>$null | Out-Null
    & sc.exe failureflag $serviceName 0 2>$null | Out-Null
    & sc.exe config $serviceName start= demand 2>$null | Out-Null

    if ($service.Status -ne 'Stopped') {
        Write-Step "Stopping existing $serviceName service before MSI install"
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        $waited = 0
        while ($waited -lt 30) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if (-not $service -or $service.Status -eq 'Stopped') {
                break
            }
            Start-Sleep -Seconds 1
            $waited++
        }
    }

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        Write-Step "Service still running, force-terminating eguard-agent.exe before MSI install"
        taskkill /F /IM eguard-agent.exe /T 2>$null | Out-Null
        Start-Sleep -Seconds 3
    }
}

function Restore-AgentServiceAfterUpgrade {
    $serviceName = 'eGuardAgent'
    Write-Step "Restoring $serviceName startup and recovery policy"
    & sc.exe config $serviceName start= auto 2>$null | Out-Null
    & sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>$null | Out-Null
    & sc.exe failureflag $serviceName 1 2>$null | Out-Null
}

function Register-TrayProtocolAndStartup {
    $trayPath = Get-TrayPath
    if (-not (Test-Path $trayPath)) {
        Write-Step "Bundled tray executable not found at $trayPath; skipping tray registration"
        return
    }

    Write-Step "Registering bundled ZTNA tray protocol handler"
    try {
        & $trayPath register-protocol | Out-Null
    } catch {
        Write-Step "WARNING: tray protocol registration failed: $($_.Exception.Message)"
    }

    $runKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $trayCommand = '"' + $trayPath + '" tray'
    Write-Step "Configuring bundled tray startup entry for current user"
    try {
        New-Item -Path $runKeyPath -Force | Out-Null
        Set-ItemProperty -Path $runKeyPath -Name 'eGuardTray' -Value $trayCommand -Type String
    } catch {
        Write-Step "WARNING: tray startup registration failed: $($_.Exception.Message)"
    }

    Write-Step "Starting bundled tray for the current session if needed"
    try {
        Start-Process -FilePath $trayPath -ArgumentList 'tray' -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Step "WARNING: tray start attempt failed: $($_.Exception.Message)"
    }
}

# W6: Input validation
if ($ServerUrl -match '[\x00-\x1f]') {
    throw "ServerUrl contains control characters"
}
if ($EnrollmentToken -match '[\x00-\x1f]') {
    throw "EnrollmentToken contains control characters"
}
if ($ServerUrl -match '^https://') {
    # secure default
} elseif ($AllowInsecureHttp.IsPresent -and $ServerUrl -match '^http://') {
    Write-Step "WARNING: allowing insecure http:// server URL due to -AllowInsecureHttp"
} else {
    throw "ServerUrl must begin with https:// (or use -AllowInsecureHttp with http://)"
}
if ($EnrollmentToken.Length -lt 8) {
    throw "EnrollmentToken must be at least 8 characters"
}

$normalizedServerUrl = $ServerUrl.TrimEnd('/')
$installEndpoint = "$normalizedServerUrl/api/v1/agent-install/windows"
$programDataRoot = 'C:\ProgramData\eGuard'
$bootstrapPath = Join-Path $programDataRoot 'bootstrap.conf'

Write-Step "Ensuring ProgramData layout exists"
New-Item -Path $programDataRoot -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $programDataRoot 'logs') -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $programDataRoot 'certs') -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $programDataRoot 'rules-staging') -ItemType Directory -Force | Out-Null

# Ensure Visual C++ Redistributable is installed (required for agent binary)
if (-not (Test-Path "$env:SystemRoot\System32\vcruntime140.dll") -or
    -not (Test-Path "$env:SystemRoot\System32\msvcp140.dll")) {
    Write-Step "Installing Visual C++ Redistributable (required dependency)"
    $vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
    $vcRedistPath = Join-Path $env:TEMP "vc_redist.x64.exe"
    Invoke-WebRequest -Uri $vcRedistUrl -OutFile $vcRedistPath -UseBasicParsing
    $vcProc = Start-Process -FilePath $vcRedistPath -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru
    if ($vcProc.ExitCode -notin @(0, 1638, 3010)) {
        throw "Visual C++ Redistributable installation failed (exit code: $($vcProc.ExitCode))"
    }
    Remove-Item -Path $vcRedistPath -Force -ErrorAction SilentlyContinue
    Write-Step "Visual C++ Redistributable installed"
} else {
    Write-Step "Visual C++ Redistributable already present"
}

$headers = @{
    'X-Enrollment-Token' = $EnrollmentToken
}

# W4: fail-closed MSI integrity policy
if ([string]::IsNullOrWhiteSpace($ExpectedHash)) {
    $hashEndpoint = "$normalizedServerUrl/api/v1/agent-install/windows/sha256"
    Write-Step "ExpectedHash not provided; fetching SHA-256 from $hashEndpoint"
    try {
        $hashResponse = Invoke-WebRequest -Uri $hashEndpoint -Headers $headers -UseBasicParsing
        $hashJson = $hashResponse.Content | ConvertFrom-Json
        $ExpectedHash = [string]$hashJson.sha256
    } catch {
        throw "ExpectedHash not provided and failed to fetch hash metadata from $hashEndpoint: $($_.Exception.Message)"
    }
}

if ($ExpectedHash -notmatch '^[A-Fa-f0-9]{64}$') {
    throw "ExpectedHash must be a 64-character hex SHA-256 hash"
}
$ExpectedHash = $ExpectedHash.ToUpper()

Write-Step "Downloading MSI from $installEndpoint"
Invoke-WebRequest -Uri $installEndpoint -Headers $headers -OutFile $MsiPath -UseBasicParsing

Write-Step "Verifying MSI hash"
$actualHash = (Get-FileHash -Path $MsiPath -Algorithm SHA256).Hash.ToUpper()
if ($actualHash -ne $ExpectedHash) {
    Remove-Item -Path $MsiPath -Force -ErrorAction SilentlyContinue
    throw "MSI hash mismatch: expected $ExpectedHash, got $actualHash"
}

$sig = Get-AuthenticodeSignature -FilePath $MsiPath
if ($sig.Status -ne 'Valid') {
    if (-not $AllowUnsignedMsi.IsPresent) {
        Remove-Item -Path $MsiPath -Force -ErrorAction SilentlyContinue
        throw "MSI Authenticode signature status is '$($sig.Status)' (set -AllowUnsignedMsi to override)"
    }
    Write-Step "WARNING: MSI Authenticode signature status is '$($sig.Status)' (override accepted)"
}

Write-Step "Writing bootstrap configuration"
$bootstrap = @{
    server_url = $normalizedServerUrl
    enrollment_token = $EnrollmentToken
    written_at_utc = (Get-Date).ToUniversalTime().ToString('o')
}
$bootstrap | ConvertTo-Json -Depth 5 | Set-Content -Path $bootstrapPath -Encoding UTF8

# W5: Restrict bootstrap.conf ACL to SYSTEM and Administrators
Write-Step "Hardening bootstrap.conf permissions"
& icacls $bootstrapPath /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null

# W8: Do not pass enrollment token on MSI command line (bootstrap.conf already has it)
Write-Step "Installing MSI silently"
Prepare-AgentServiceForUpgrade
$msiArgs = @(
    '/i', "`"$MsiPath`"",
    '/qn',
    '/norestart',
    "SERVER_URL=$normalizedServerUrl"
)
$process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
if ($process.ExitCode -ne 0) {
    throw "msiexec failed with exit code $($process.ExitCode)"
}

Restore-AgentServiceAfterUpgrade

Write-Step "Starting eGuardAgent service"
Start-Service -Name 'eGuardAgent' -ErrorAction SilentlyContinue
$service = Get-Service -Name 'eGuardAgent' -ErrorAction Stop
if ($service.Status -ne 'Running') {
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}

Register-TrayProtocolAndStartup

if (-not $KeepBootstrap.IsPresent) {
    Write-Step "Enrollment bootstrap succeeded, removing bootstrap.conf"
    Remove-Item -Path $bootstrapPath -Force -ErrorAction SilentlyContinue
}

Write-Step "Windows agent installation completed"
Write-Host "MSI Path: $MsiPath"
Write-Host "Service: eGuardAgent ($((Get-Service -Name 'eGuardAgent').Status))"
Write-Host "Tray: $(if (Test-Path (Get-TrayPath)) { 'installed' } else { 'missing' })"
