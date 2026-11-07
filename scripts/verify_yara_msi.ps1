param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference = 'Stop'
# Read the MSI File table only. Never install it or invoke the service.
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase((Resolve-Path $Path).Path, 0)
$view = $database.OpenView('SELECT `FileName` FROM `File`')
$view.Execute()
$names = @()
while ($record = $view.Fetch()) { $names += $record.StringData(1).Split('|')[-1] }
$manifest = Get-Content "$PSScriptRoot/../threat-intel/yara-v1.json" -Raw | ConvertFrom-Json
$required = @('default.yar', 'THIRD-PARTY-NOTICES.txt', 'provenance.json')
$required += @($manifest.rules | ForEach-Object { "$($_.id).yar" })
foreach ($name in $required) { if ($names -notcontains $name) { throw "MSI missing $name" } }
$ruleFiles = @($names | Where-Object { $_ -match '\.yar(a)?$' })
if ($ruleFiles.Count -ne 10) { throw "MSI YARA count is $($ruleFiles.Count), expected exactly10" }
$names | Sort-Object
$view.Close()
Write-Output 'MSI exact10-rule pack, provenance and third-party notices: passed'
