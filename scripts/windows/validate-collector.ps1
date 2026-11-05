# Run ONLY on explicitly authorized disposable Windows 11 VM snapshot. No admin needed.
# No network/device writes or SCM installation. PowerShell invokes only fixed local Go tests and inspector.
$ErrorActionPreference = 'Stop'
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$env:GOTMPDIR = Join-Path $env:TEMP ('nac-go-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $env:GOTMPDIR | Out-Null
try {
  Push-Location $root
  try {
    & go test -count=1 -v ./collector ./core ./boundary
    if ($LASTEXITCODE -ne 0) { throw "Windows Go tests failed ($LASTEXITCODE)" }
    $inspection = Join-Path $root 'dist\eguard-nac-inspect-TEST-UNSIGNED.exe'
    if (-not (Test-Path $inspection)) { throw 'Missing unsigned inspection payload; build with scripts/build-local.sh first' }
    $output = Join-Path $env:GOTMPDIR 'posture-sensitive.json'
    & $inspection > $output
    if ($LASTEXITCODE -ne 0) { throw "Native collector failed ($LASTEXITCODE)" }
    $p = Get-Content -Raw -Path $output | ConvertFrom-Json
    if ($p.agent_type -ne 'nac' -or $p.domain.match -ne 'unknown') { throw 'Unexpected asserted identity/domain match' }
    if ($p.os -notmatch '^windows-[0-9]+\.[0-9]+\.[0-9]+/amd64$') { throw 'Windows build unavailable or malformed' }
    foreach ($profile in @('domain', 'private', 'public')) { if (@('yes','no','unknown') -notcontains $p.firewall.$profile.value) { throw "Invalid firewall profile evidence: $profile" } }
    foreach ($adapter in $p.adapters) { if ($adapter.route_status -eq 'yes' -and $adapter.route_source -notmatch '^GetIpForwardTable2') { throw 'Route lacks native source' } }
    $routes = @($p.adapters | Where-Object { $_.route_status -eq 'yes' }).Count
    $unknown = @($p.adapters | Where-Object { $_.route_status -eq 'unknown' }).Count
    Write-Output "Native collector: OS build=$($p.os); adapters=$($p.adapters.Count), route-present=$routes, route-unknown=$unknown; domain-join=$($p.domain.part_of_domain), domain-match=unknown; AV installed/running/updated=$($p.av.installed)/$($p.av.running)/$($p.av.updated); firewall domain/private/public=$($p.firewall.domain.value)/$($p.firewall.private.value)/$($p.firewall.public.value); errors=$($p.errors.Count). Sensitive output deleted."
    $service = Join-Path $root 'dist\eguard-nac-service-TEST-UNSIGNED.exe'
    if (Test-Path $service) {
      $begin = [Diagnostics.Stopwatch]::StartNew()
      $process = Start-Process -FilePath $service -ArgumentList '--nac-fixed-collect' -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $env:GOTMPDIR 'service-sensitive.json')
      try { if (-not $process.WaitForExit(15000)) { $process.Kill(); throw 'Fixed collector timeout exceeded' }; if ($process.ExitCode -eq 0) { throw 'Ungated fixed collector unexpectedly succeeded' } } finally { $begin.Stop(); if (-not $process.HasExited) { $process.Kill() }; $process.Dispose() }
      Write-Output "Ungated service collector rejected in $($begin.ElapsedMilliseconds) ms. SCM Stop timing NOT RUN (no installation authorized)."
    }
  } finally { Pop-Location }
} finally {
  Remove-Item -Path $env:GOTMPDIR -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item Env:\GOTMPDIR -ErrorAction SilentlyContinue
  Remove-Item Env:\GOPROXY -ErrorAction SilentlyContinue
  Remove-Item Env:\GOSUMDB -ErrorAction SilentlyContinue
}
