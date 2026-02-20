param(
    [Parameter(Mandatory = $true)]
    [string]$ServerUrl,

    [Parameter(Mandatory = $true)]
    [string]$EnrollmentToken,

    [string]$MsiPath = "$env:TEMP\eguard-agent-latest.msi",

    [switch]$KeepBootstrap
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host "[eGuard-install] $Message"
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

Write-Step "Downloading MSI from $installEndpoint"
$headers = @{
    'X-Enrollment-Token' = $EnrollmentToken
}
Invoke-WebRequest -Uri $installEndpoint -Headers $headers -OutFile $MsiPath

Write-Step "Writing bootstrap configuration"
$bootstrap = @{
    server_url = $normalizedServerUrl
    enrollment_token = $EnrollmentToken
    written_at_utc = (Get-Date).ToUniversalTime().ToString('o')
}
$bootstrap | ConvertTo-Json -Depth 5 | Set-Content -Path $bootstrapPath -Encoding UTF8

Write-Step "Installing MSI silently"
$msiArgs = @(
    '/i', "`"$MsiPath`"",
    '/qn',
    '/norestart',
    "ENROLLMENT_TOKEN=$EnrollmentToken",
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
