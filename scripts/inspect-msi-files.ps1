param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Pattern = ''
)

$ErrorActionPreference = 'Stop'

$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
$view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database, @('SELECT FileName FROM File'))
$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null

while ($true) {
    $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
    if (-not $record) {
        break
    }
    $name = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1)
    if ([string]::IsNullOrWhiteSpace($Pattern) -or $name -match $Pattern) {
        Write-Output $name
    }
}
