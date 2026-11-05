# Read-only Windows VM preflight. Never executes an artifact or changes system configuration.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ReportPath,
    [Parameter(Mandatory=$true)][string]$ManifestPath,
    [Parameter(Mandatory=$true)][string]$CasesPath,
    [switch]$DisposableVmOperatorOptIn
)
$ErrorActionPreference = 'Stop'
$checks = @()
function Add-Check($id, $ok, $reference) {
    $evidence = @()
    if ($reference) { $evidence = @(@{ kind = 'observation'; reference = [string]$reference }) }
    $script:checks += @{ id = $id; status = $(if ($ok) { 'PASS' } else { 'FAIL' }); evidence = $evidence }
}
# Output path is the only write; refuse clobber. No installation or system writes.
if ([IO.File]::Exists($ReportPath)) { throw 'Report already exists; choose a new path' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$cases = Get-Content -LiteralPath $CasesPath -Raw | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $cases.schema_version -ne 1) { throw 'Unsupported schema' }
# Win32_OperatingSystem is available in Windows PowerShell 5.1; do not rely on
# RuntimeInformation (not present on every full-framework PowerShell host).
$isWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$osInfo = if ($isWindows) { Get-CimInstance -ClassName Win32_OperatingSystem } else { $null }
$os = if ($osInfo) { [version]$osInfo.Version } else { [version]'0.0' }
$arch = if ($osInfo) { [string]$osInfo.OSArchitecture } else { 'unknown' }
$workstation = $osInfo -and $osInfo.ProductType -eq 1
$x64 = $arch -match '^(64-bit|64 bit|x64)$'
$osClass = 'UNSUPPORTED_OR_UNKNOWN'
if ($isWindows -and $workstation -and $x64 -and $os.Major -eq 10) {
    if ($os.Build -ge 22000) { $osClass = 'WINDOWS11_CANDIDATE' }
    elseif ($os.Build -ge 10240) { $osClass = 'WINDOWS10_OBSERVED_NOT_MVP' }
}
Add-Check 'platform' ($osClass -eq 'WINDOWS11_CANDIDATE') "classification=$osClass; version=$os; arch=$arch; workstation=$workstation; target=Windows 11 x64"
$elevated = $false
if ($isWindows) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
Add-Check 'elevation' $elevated "elevated=$elevated; identity=redacted"
# Opt-in records intent only. There is intentionally no mutating code path in this harness.
Add-Check 'operator_gate' ([bool]$DisposableVmOperatorOptIn) "disposable_vm_operator_opt_in=$([bool]$DisposableVmOperatorOptIn); mutating_tests_available=false"
$artifactOK = $true
$signatureOK = $true
$artifactNotes = @()
$signatureNotes = @()
# Match the Python validator's dist/ and non-empty Windows-safe components.
$artifactComponentPattern = '^[A-Za-z0-9._-]+$'
$reservedNames = @('CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9')
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string]$artifact.path
    $digest = [string]$artifact.sha256
    $parts = $relative.Split('/')
    $safePath = $relative -cmatch '^dist/' -and $parts.Count -ge 2
    foreach ($part in @($parts | Select-Object -Skip 1)) {
        if ($part -cnotmatch $artifactComponentPattern -or $part -eq '.' -or $part -eq '..' -or
            $part.EndsWith('.') -or $reservedNames -ccontains $part.Split('.')[0].ToUpperInvariant()) {
            $safePath = $false
        }
    }
    if (-not $safePath -or $digest -cnotmatch '^[0-9a-f]{64}$') {
        $artifactOK = $false; $signatureOK = $false; $artifactNotes += 'invalid manifest entry'; continue
    }
    $file = [IO.Path]::GetFullPath((Join-Path $root ($relative -replace '/', [IO.Path]::DirectorySeparatorChar)))
    $dist = [IO.Path]::GetFullPath((Join-Path $root 'dist')) + [IO.Path]::DirectorySeparatorChar
    if (-not $file.StartsWith($dist, [StringComparison]::OrdinalIgnoreCase) -or -not [IO.File]::Exists($file)) {
        $artifactOK = $false; $signatureOK = $false; $artifactNotes += "$relative missing/unsafe"; continue
    }
    $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    $match = $actual -ceq $digest
    if (-not $match) { $artifactOK = $false }
    $artifactNotes += "$relative sha256_match=$match"
    $sig = Get-AuthenticodeSignature -LiteralPath $file
    $expected = [string]$artifact.signature_class
    $valid = if ($expected -eq 'TEST-UNSIGNED') { $sig.Status -eq 'NotSigned' } elseif ($expected -eq 'SIGNED') { $sig.Status -eq 'Valid' } else { $false }
    if (-not $valid) { $signatureOK = $false }
    $signatureNotes += "$relative class=$expected status=$($sig.Status) match=$valid"
}
if (@($manifest.artifacts).Count -eq 0) { $artifactOK = $false; $signatureOK = $false }
Add-Check 'artifacts' $artifactOK ($artifactNotes -join '; ')
Add-Check 'authenticode' $signatureOK ($signatureNotes -join '; ')
$preStatus = if (@($checks | Where-Object { $_.status -ne 'PASS' }).Count -eq 0) { 'PASS' } else { 'FAIL' }
$runtime = @($cases.cases | ForEach-Object { @{ id = [string]$_.id; status = 'NOT RUN'; evidence = @() } })
$report = @{ schema_version = 1; os_acceptance = $osClass; preflight = @{ status = $preStatus; checks = $checks }; runtime_acceptance = $runtime }
$json = ConvertTo-Json -InputObject $report -Depth 12
# CreateNew prevents overwriting concurrent or existing report; no sensitive identity is emitted.
$target = [IO.Path]::GetFullPath($ReportPath)
$stream = New-Object IO.FileStream($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($false))); try { $writer.Write($json); $writer.Flush() } finally { $writer.Dispose() } } finally { $stream.Dispose() }
Write-Output "Preflight $preStatus; runtime acceptance NOT RUN; report=$target"
