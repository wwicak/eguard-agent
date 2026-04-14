param(
    [switch]$KeepData,
    [switch]$KeepProgramFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$serviceName = 'eGuardAgent'
$displayName = 'eGuard Endpoint Security Agent'
$publisher = 'eGuard'
$programDataRoot = 'C:\ProgramData\eGuard'
$installRoot = 'C:\Program Files\eGuard'
$trayProcessName = 'eguard-tray'
$trayRunKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$trayProtocolKeyPath = 'HKCU:\Software\Classes\eguard-ztna'

function Write-Step([string]$Message) {
    Write-Host "[eGuard-uninstall] $Message"
}

function Remove-PathIfExists([string]$Path, [string]$Description) {
    if (Test-Path -LiteralPath $Path) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            Write-Step "Removed ${Description}: ${Path}"
        } catch {
            Write-Step "Failed to remove ${Description}: $($_.Exception.Message)"
        }
    } else {
        Write-Step "Already absent: ${Path}"
    }
}

function Remove-RegistryValueIfExists([string]$Path, [string]$Name, [string]$Description) {
    if (Test-Path -LiteralPath $Path) {
        try {
            $existing = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $existing) {
                Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
                Write-Step "Removed ${Description}: ${Path}\\${Name}"
                return
            }
        } catch {
            Write-Step "Failed to remove ${Description}: $($_.Exception.Message)"
            return
        }
    }
    Write-Step "Already absent: ${Path}\\${Name}"
}

function Get-AgentUninstallEntry {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $entries = foreach ($root in $roots) {
        Get-ItemProperty -Path $root -ErrorAction SilentlyContinue
    }

    $entries |
        Where-Object {
            $displayProp = $_.PSObject.Properties['DisplayName']
            $publisherProp = $_.PSObject.Properties['Publisher']
            $installLocationProp = $_.PSObject.Properties['InstallLocation']

            $entryDisplayName = if ($null -ne $displayProp) { [string]$displayProp.Value } else { '' }
            $entryPublisher = if ($null -ne $publisherProp) { [string]$publisherProp.Value } else { '' }
            $entryInstallLocation = if ($null -ne $installLocationProp) { [string]$installLocationProp.Value } else { '' }

            $entryDisplayName -eq $displayName -or
            ($entryPublisher -eq $publisher -and $entryInstallLocation -like "$installRoot*")
        } |
        Select-Object -First 1
}

function Get-MsiProductCode([object]$Entry) {
    if ($null -eq $Entry) {
        return $null
    }

    if ($Entry.PSChildName -match '^\{[0-9A-Fa-f\-]+\}$') {
        return $Entry.PSChildName
    }

    $uninstallString = [string]$Entry.UninstallString
    if ($uninstallString -match '\{[0-9A-Fa-f\-]+\}') {
        return $matches[0]
    }

    return $null
}

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required to uninstall eGuard Agent.'
}

Write-Step 'Discovering installed eGuard Agent package'
$uninstallEntry = Get-AgentUninstallEntry
$productCode = Get-MsiProductCode -Entry $uninstallEntry

if ($null -ne $uninstallEntry -and -not [string]::IsNullOrWhiteSpace($productCode)) {
    Write-Step "Running MSI uninstall for product $productCode"
    $msiArgs = @('/x', $productCode, '/qn', '/norestart')
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "msiexec uninstall failed with exit code $($process.ExitCode)"
    }
    Write-Step 'MSI uninstall completed'
} elseif ($null -ne $uninstallEntry -and -not [string]::IsNullOrWhiteSpace([string]$uninstallEntry.QuietUninstallString)) {
    Write-Step 'Running quiet uninstall command from registry metadata'
    $process = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ([string]$uninstallEntry.QuietUninstallString) -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Quiet uninstall command failed with exit code $($process.ExitCode)"
    }
    Write-Step 'Quiet uninstall completed'
} else {
    Write-Step 'No installed MSI entry found; proceeding with leftover cleanup only'
}

Write-Step 'Stopping and removing any leftover Windows service state'
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        try {
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        } catch {
            Write-Step "Service stop timed out; force-terminating eguard-agent.exe and continuing cleanup"
            Get-Process -Name 'eguard-agent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }

    $deleteProcess = Start-Process -FilePath 'sc.exe' -ArgumentList 'delete', $serviceName -Wait -PassThru -NoNewWindow
    if ($deleteProcess.ExitCode -eq 0) {
        Write-Step "Deleted leftover service: $serviceName"
    } else {
        Write-Step "Service delete returned exit code $($deleteProcess.ExitCode); continuing"
    }
} else {
    Write-Step "Already absent: service $serviceName"
}

Write-Step 'Stopping any bundled tray process'
$trayProcesses = Get-Process -Name $trayProcessName -ErrorAction SilentlyContinue
if ($trayProcesses) {
    $trayProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Step "Stopped tray process: $trayProcessName"
} else {
    Write-Step "Already absent: process $trayProcessName"
}

Write-Step 'Removing bundled tray startup and protocol registration'
Remove-RegistryValueIfExists -Path $trayRunKeyPath -Name 'eGuardTray' -Description 'tray startup entry'
Remove-PathIfExists -Path $trayProtocolKeyPath -Description 'tray protocol registration'

if (-not $KeepProgramFiles.IsPresent) {
    Remove-PathIfExists -Path $installRoot -Description 'program files directory'
} else {
    Write-Step "Keeping program files directory: $installRoot"
}

if (-not $KeepData.IsPresent) {
    Remove-PathIfExists -Path $programDataRoot -Description 'program data directory'
} else {
    Write-Step "Keeping program data directory: $programDataRoot"
}

Write-Step 'Windows agent uninstall completed'
