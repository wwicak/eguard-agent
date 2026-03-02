param(
    [string]$DateTag = $env:EGUARD_PERF_DATE,
    [string]$OutRoot = $env:EGUARD_PERF_OUT_DIR,
    [int]$RunsPerMode = $(if ($env:EGUARD_PERF_RUNS_PER_MODE) { [int]$env:EGUARD_PERF_RUNS_PER_MODE } else { 10 }),
    [int]$WarmupRuns = $(if ($env:EGUARD_PERF_WARMUP_RUNS) { [int]$env:EGUARD_PERF_WARMUP_RUNS } else { 2 }),
    [string]$OrderPattern = $(if ($env:EGUARD_PERF_ORDER_PATTERN) { $env:EGUARD_PERF_ORDER_PATTERN } else { 'OFF,ON,ON,OFF' }),
    [string]$ScenariosCsv = $(if ($env:EGUARD_PERF_SCENARIOS) { $env:EGUARD_PERF_SCENARIOS } else { 'idle,office,build,ransomware,command-latency' }),
    [string]$AgentService = $(if ($env:EGUARD_AGENT_SERVICE) { $env:EGUARD_AGENT_SERVICE } else { 'eGuardAgent' }),
    [string]$AgentProcessName = $(if ($env:EGUARD_AGENT_PROCESS_NAME) { $env:EGUARD_AGENT_PROCESS_NAME } else { 'eguard-agent' }),
    [int]$AgentSettleSeconds = $(if ($env:EGUARD_AGENT_SETTLE_SECONDS) { [int]$env:EGUARD_AGENT_SETTLE_SECONDS } else { 2 })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = (Resolve-Path (Join-Path $scriptDir '..\..')).Path

if ([string]::IsNullOrWhiteSpace($DateTag)) {
    $DateTag = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
}
if ([string]::IsNullOrWhiteSpace($OutRoot)) {
    $OutRoot = Join-Path $rootDir ("artifacts/perf/{0}/windows" -f $DateTag)
}
$skipServiceControl = ("$env:EGUARD_PERF_SKIP_SERVICE_CONTROL" -eq '1')

function Write-Log([string]$Message) {
    Write-Host "[windows_phase3] $Message"
}

function Split-Csv([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    return $Value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
}

function Normalize-Mode([string]$Mode) {
    $m = $Mode.Trim().ToUpperInvariant()
    if ($m -ne 'ON' -and $m -ne 'OFF') {
        throw "Invalid mode '$Mode' in ORDER_PATTERN"
    }
    return $m
}

function Build-WarmupSequence([int]$Count, [string]$PatternCsv) {
    $pattern = @(Split-Csv $PatternCsv | ForEach-Object { Normalize-Mode $_ })
    if ($pattern.Count -eq 0) { throw 'ORDER_PATTERN must not be empty' }

    $result = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $Count; $i++) {
        $result.Add($pattern[$i % $pattern.Count])
    }
    return $result
}

function Build-MeasuredSequence([int]$PerMode, [string]$PatternCsv) {
    $pattern = @(Split-Csv $PatternCsv | ForEach-Object { Normalize-Mode $_ })
    if ($pattern.Count -eq 0) { throw 'ORDER_PATTERN must not be empty' }

    $onCount = 0
    $offCount = 0
    $result = New-Object System.Collections.Generic.List[string]

    while ($onCount -lt $PerMode -or $offCount -lt $PerMode) {
        foreach ($mode in $pattern) {
            if ($mode -eq 'ON' -and $onCount -lt $PerMode) {
                $result.Add('ON')
                $onCount++
            }
            elseif ($mode -eq 'OFF' -and $offCount -lt $PerMode) {
                $result.Add('OFF')
                $offCount++
            }

            if ($onCount -ge $PerMode -and $offCount -ge $PerMode) {
                break
            }
        }
    }

    return $result
}

function Set-AgentMode([string]$Mode) {
    if ($skipServiceControl) {
        return
    }
    if ($Mode -eq 'ON') {
        Start-Service -Name $AgentService -ErrorAction SilentlyContinue
    }
    else {
        Stop-Service -Name $AgentService -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds $AgentSettleSeconds
}

function Get-AgentProcessObject {
    return Get-Process -Name $AgentProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Get-AgentCpuSeconds {
    $p = Get-AgentProcessObject
    if ($null -eq $p) { return $null }
    return [double]$p.CPU
}

function Get-AgentWorkingSetKB {
    $p = Get-AgentProcessObject
    if ($null -eq $p) { return $null }
    return [int]([math]::Round($p.WorkingSet64 / 1KB))
}

function Get-DiskCounterSnapshot {
    try {
        $sample = Get-Counter -Counter @(
            '\PhysicalDisk(_Total)\Avg. Disk sec/Transfer',
            '\PhysicalDisk(_Total)\Disk Read Bytes/sec',
            '\PhysicalDisk(_Total)\Disk Write Bytes/sec'
        ) -SampleInterval 1 -MaxSamples 1

        $map = @{}
        foreach ($counter in $sample.CounterSamples) {
            $path = $counter.Path
            $value = [double]$counter.CookedValue
            if ($path -like '*Avg. Disk sec/Transfer') {
                $map['disk_await_ms'] = $value * 1000.0
            }
            elseif ($path -like '*Disk Read Bytes/sec') {
                $map['disk_read_bytes_per_sec'] = $value
            }
            elseif ($path -like '*Disk Write Bytes/sec') {
                $map['disk_write_bytes_per_sec'] = $value
            }
        }
        return $map
    }
    catch {
        return @{}
    }
}

function Invoke-CommandLatencyWorkload {
    $base = ("$env:EGUARD_PERF_COMMAND_LATENCY_BASE_URL").Trim().TrimEnd('/')
    $agentId = ("$env:EGUARD_PERF_COMMAND_LATENCY_AGENT_ID").Trim()
    $token = ("$env:EGUARD_PERF_COMMAND_LATENCY_BEARER").Trim()
    $timeoutS = if ($env:EGUARD_PERF_COMMAND_LATENCY_TIMEOUT_S) { [double]$env:EGUARD_PERF_COMMAND_LATENCY_TIMEOUT_S } else { 30.0 }
    $pollS = if ($env:EGUARD_PERF_COMMAND_LATENCY_POLL_S) { [double]$env:EGUARD_PERF_COMMAND_LATENCY_POLL_S } else { 1.5 }

    if ([string]::IsNullOrWhiteSpace($base) -or [string]::IsNullOrWhiteSpace($agentId)) {
        Start-Sleep -Milliseconds 250
        return
    }

    $headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($token)) {
        $headers['Authorization'] = "Bearer $token"
    }

    $payload = @{
        agent_id = $agentId
        command_type = 'scan'
        command_data = @{
            quick  = $true
            reason = 'phase3-command-latency'
        }
    }

    $body = $payload | ConvertTo-Json -Depth 8
    $enqueueUrl = "$base/api/v1/endpoint-command/enqueue"

    try {
        $resp = Invoke-RestMethod -Method POST -Uri $enqueueUrl -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec ([int][math]::Ceiling($timeoutS))
    }
    catch {
        Start-Sleep -Milliseconds 250
        return
    }

    $commandId = $resp.command_id
    if ([string]::IsNullOrWhiteSpace($commandId)) {
        if ($resp.id) { $commandId = [string]$resp.id }
    }

    if ([string]::IsNullOrWhiteSpace($commandId)) {
        Start-Sleep -Milliseconds 250
        return
    }

    $deadline = (Get-Date).AddSeconds($timeoutS)
    while ((Get-Date) -lt $deadline) {
        try {
            $statusUrl = "$base/api/v1/endpoint/commands?agent_id=$([uri]::EscapeDataString($agentId))&limit=100"
            $statusPayload = Invoke-RestMethod -Method GET -Uri $statusUrl -Headers $headers -TimeoutSec ([int][math]::Ceiling($timeoutS))

            $rows = @()
            if ($statusPayload.commands) {
                $rows = @($statusPayload.commands)
            }
            elseif ($statusPayload.items) {
                $rows = @($statusPayload.items)
            }

            foreach ($row in $rows) {
                if ($null -eq $row) { continue }
                if ([string]$row.command_id -ne $commandId) { continue }
                $status = ([string]$row.status).ToLowerInvariant()
                if (@('completed', 'failed', 'timeout') -contains $status) {
                    return
                }
            }
        }
        catch {
            # continue polling
        }
        Start-Sleep -Seconds $pollS
    }
}

function New-RandomText([int]$Length, [char]$Char) {
    return -join ((1..$Length) | ForEach-Object { $Char })
}

function Invoke-OfficeWorkload {
    $count = if ($env:EGUARD_PERF_OFFICE_FILES) { [int]$env:EGUARD_PERF_OFFICE_FILES } else { 1500 }
    $size = if ($env:EGUARD_PERF_FILE_SIZE_BYTES) { [int]$env:EGUARD_PERF_FILE_SIZE_BYTES } else { 4096 }

    $root = Join-Path $env:TEMP 'eguard-perf-office'
    if (Test-Path $root) { Remove-Item -Path $root -Recurse -Force }
    New-Item -Path $root -ItemType Directory -Force | Out-Null

    $payload = New-RandomText -Length $size -Char 'A'

    for ($i = 0; $i -lt $count; $i++) {
        $path = Join-Path $root ("doc-{0:d5}.txt" -f $i)
        [System.IO.File]::WriteAllText($path, $payload)
    }

    for ($i = 0; $i -lt $count; $i += 3) {
        $path = Join-Path $root ("doc-{0:d5}.txt" -f $i)
        [void][System.IO.File]::ReadAllText($path)
    }

    for ($i = 0; $i -lt $count; $i += 2) {
        $path = Join-Path $root ("doc-{0:d5}.txt" -f $i)
        [System.IO.File]::WriteAllText($path, "$payload`nrev=2")
    }

    for ($i = 0; $i -lt $count; $i += 10) {
        $path = Join-Path $root ("doc-{0:d5}.txt" -f $i)
        $tmp = Join-Path $root ("doc-{0:d5}.bak" -f $i)
        Rename-Item -Path $path -NewName ([System.IO.Path]::GetFileName($tmp))
        Rename-Item -Path $tmp -NewName ([System.IO.Path]::GetFileName($path))
    }

    Remove-Item -Path $root -Recurse -Force
}

function Invoke-BuildWorkload {
    $count = if ($env:EGUARD_PERF_BUILD_FILES) { [int]$env:EGUARD_PERF_BUILD_FILES } else { 2500 }
    $size = if ($env:EGUARD_PERF_FILE_SIZE_BYTES) { [int]$env:EGUARD_PERF_FILE_SIZE_BYTES } else { 4096 }

    $root = Join-Path $env:TEMP 'eguard-perf-build'
    $srcRoot = Join-Path $root 'src'
    $outRoot = Join-Path $root 'out'

    if (Test-Path $root) { Remove-Item -Path $root -Recurse -Force }
    New-Item -Path $srcRoot -ItemType Directory -Force | Out-Null
    New-Item -Path $outRoot -ItemType Directory -Force | Out-Null

    $payload = New-RandomText -Length $size -Char 'B'

    for ($i = 0; $i -lt $count; $i++) {
        $moduleDir = Join-Path $srcRoot ("mod-{0:d2}" -f ($i % 64))
        if (-not (Test-Path $moduleDir)) {
            New-Item -Path $moduleDir -ItemType Directory -Force | Out-Null
        }
        $path = Join-Path $moduleDir ("unit-{0:d5}.c" -f $i)
        [System.IO.File]::WriteAllText($path, $payload)
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        Get-ChildItem -Path $srcRoot -Filter '*.c' -Recurse | ForEach-Object {
            $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
            $hash = $sha.ComputeHash($bytes)
            $hex = -join ($hash | ForEach-Object { $_.ToString('x2') })
            $relative = $_.FullName.Substring($srcRoot.Length).TrimStart('\\')
            $outPath = Join-Path $outRoot ($relative + '.o')
            $outDir = Split-Path -Parent $outPath
            if (-not (Test-Path $outDir)) {
                New-Item -Path $outDir -ItemType Directory -Force | Out-Null
            }
            [System.IO.File]::WriteAllText($outPath, $hex)
        }
    }
    finally {
        $sha.Dispose()
    }

    Remove-Item -Path $root -Recurse -Force
}

function Invoke-RansomwareWorkload {
    $count = if ($env:EGUARD_PERF_RANSOMWARE_FILES) { [int]$env:EGUARD_PERF_RANSOMWARE_FILES } else { 3500 }
    $size = if ($env:EGUARD_PERF_FILE_SIZE_BYTES) { [int]$env:EGUARD_PERF_FILE_SIZE_BYTES } else { 4096 }

    $root = Join-Path $env:TEMP 'eguard-perf-ransomware'
    if (Test-Path $root) { Remove-Item -Path $root -Recurse -Force }
    New-Item -Path $root -ItemType Directory -Force | Out-Null

    $seed = New-RandomText -Length $size -Char 'C'
    $rewrite = New-RandomText -Length $size -Char 'X'

    for ($i = 0; $i -lt $count; $i++) {
        $path = Join-Path $root ("victim-{0:d5}.dat" -f $i)
        [System.IO.File]::WriteAllText($path, $seed)
    }

    for ($i = 0; $i -lt $count; $i++) {
        $src = Join-Path $root ("victim-{0:d5}.dat" -f $i)
        $dst = Join-Path $root ("victim-{0:d5}.locked" -f $i)
        [System.IO.File]::WriteAllText($src, $rewrite)
        Rename-Item -Path $src -NewName ([System.IO.Path]::GetFileName($dst))
    }

    Remove-Item -Path $root -Recurse -Force
}

function Invoke-Workload([string]$Scenario) {
    $scenarioUpper = $Scenario.ToUpperInvariant().Replace('-', '_')
    $customVar = "EGUARD_PERF_SCENARIO_${scenarioUpper}_CMD"
    $customCmd = [Environment]::GetEnvironmentVariable($customVar)

    if (-not [string]::IsNullOrWhiteSpace($customCmd)) {
        & powershell.exe -NoProfile -Command $customCmd | Out-Null
        return
    }

    switch ($Scenario) {
        'idle' {
            $seconds = if ($env:EGUARD_PERF_IDLE_SECONDS) { [int]$env:EGUARD_PERF_IDLE_SECONDS } else { 300 }
            Start-Sleep -Seconds $seconds
        }
        'office' { Invoke-OfficeWorkload }
        'build' { Invoke-BuildWorkload }
        'ransomware' { Invoke-RansomwareWorkload }
        'command-latency' { Invoke-CommandLatencyWorkload }
        default { throw "Unknown scenario '$Scenario'" }
    }
}

New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null
$scenarios = @(Split-Csv $ScenariosCsv)
if ($scenarios.Count -eq 0) {
    throw 'No scenarios resolved from EGUARD_PERF_SCENARIOS'
}

Write-Log "date_tag=$DateTag out_root=$OutRoot runs_per_mode=$RunsPerMode warmup_runs=$WarmupRuns"

foreach ($scenario in $scenarios) {
    $scenarioDir = Join-Path $OutRoot $scenario
    New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null

    $warmupSeq = @(Build-WarmupSequence -Count $WarmupRuns -PatternCsv $OrderPattern)
    $measuredSeq = @(Build-MeasuredSequence -PerMode $RunsPerMode -PatternCsv $OrderPattern)
    $sequence = @()
    $sequence += $warmupSeq
    $sequence += $measuredSeq

    $results = New-Object System.Collections.Generic.List[object]
    $measuredOnIndex = 0
    $measuredOffIndex = 0

    for ($runNumber = 0; $runNumber -lt $sequence.Count; $runNumber++) {
        $mode = $sequence[$runNumber]
        $warmup = $runNumber -lt $WarmupRuns
        $phase = if ($warmup) { 'warmup' } else { 'measured' }

        Set-AgentMode -Mode $mode

        $beforeCpu = if ($mode -eq 'ON') { Get-AgentCpuSeconds } else { $null }

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Invoke-Workload -Scenario $scenario
        $sw.Stop()

        $afterCpu = if ($mode -eq 'ON') { Get-AgentCpuSeconds } else { $null }
        $rssKb = if ($mode -eq 'ON') { Get-AgentWorkingSetKB } else { $null }
        $disk = Get-DiskCounterSnapshot

        $agentCpuDelta = $null
        if ($null -ne $beforeCpu -and $null -ne $afterCpu -and $afterCpu -ge $beforeCpu) {
            $agentCpuDelta = [double]($afterCpu - $beforeCpu)
        }

        $modeRunIndex = $null
        if (-not $warmup) {
            if ($mode -eq 'ON') {
                $measuredOnIndex++
                $modeRunIndex = $measuredOnIndex
            }
            else {
                $measuredOffIndex++
                $modeRunIndex = $measuredOffIndex
            }
        }

        $obj = [ordered]@{
            platform = 'windows'
            scenario = $scenario
            mode = $mode
            phase = $phase
            warmup = $warmup
            run_number = $runNumber
            mode_run_index = $modeRunIndex
            elapsed_s = [double]$sw.Elapsed.TotalSeconds
            agent_cpu_s = $agentCpuDelta
            agent_rss_kb = $rssKb
            cpu_iowait_pct = $null
            disk_await_ms = if ($disk.ContainsKey('disk_await_ms')) { [double]$disk['disk_await_ms'] } else { $null }
            disk_read_bytes_per_sec = if ($disk.ContainsKey('disk_read_bytes_per_sec')) { [double]$disk['disk_read_bytes_per_sec'] } else { $null }
            disk_write_bytes_per_sec = if ($disk.ContainsKey('disk_write_bytes_per_sec')) { [double]$disk['disk_write_bytes_per_sec'] } else { $null }
        }
        $results.Add([pscustomobject]$obj)
    }

    $rawJsonPath = Join-Path $scenarioDir 'raw.json'
    $rows = @($results.ToArray())
    $rawPayload = ($rows | ConvertTo-Json -Depth 8)
    [System.IO.File]::WriteAllText($rawJsonPath, $rawPayload + "`n", (New-Object System.Text.UTF8Encoding($false)))

    $metadata = [ordered]@{
        scenario = $scenario
        runs_per_mode = $RunsPerMode
        warmup_runs = $WarmupRuns
        order_pattern = $OrderPattern
        agent_service = $AgentService
        agent_process_name = $AgentProcessName
    }
    $metaPath = Join-Path $scenarioDir 'metadata.json'
    $metaPayload = ($metadata | ConvertTo-Json -Depth 5)
    [System.IO.File]::WriteAllText($metaPath, $metaPayload + "`n", (New-Object System.Text.UTF8Encoding($false)))

    Write-Log "scenario=$scenario wrote $rawJsonPath"
}

Write-Log 'done'
