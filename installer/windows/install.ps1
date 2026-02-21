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

Write-Step "Starting eGuardAgent service"
Start-Service -Name 'eGuardAgent' -ErrorAction SilentlyContinue
$service = Get-Service -Name 'eGuardAgent' -ErrorAction Stop
if ($service.Status -ne 'Running') {
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}

if (-not $KeepBootstrap.IsPresent) {
    Write-Step "Enrollment bootstrap succeeded, removing bootstrap.conf"
    Remove-Item -Path $bootstrapPath -Force -ErrorAction SilentlyContinue
}

Write-Step "Windows agent installation completed"
Write-Host "MSI Path: $MsiPath"
Write-Host "Service: eGuardAgent ($((Get-Service -Name 'eGuardAgent').Status))"
