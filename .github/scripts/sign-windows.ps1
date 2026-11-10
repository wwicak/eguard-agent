param([Parameter(Mandatory)][string[]]$Path)
$ErrorActionPreference = 'Stop'
$thumbprint = 'E57B64FE5904651C3CD10FF8E3CBCCADF0317CDF'
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw 'Windows SDK signtool.exe not found' }

function Invoke-SignTool([string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new($signtool.FullName)
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(120000)) {
        $process.Kill($true)
        throw 'signtool timed out; possible card PIN prompt. Stop and investigate; never guess a PIN.'
    }
    $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
    Write-Host $output
    # Exit code 2 is only a warning to signtool, but unacceptable for release signing.
    if ($process.ExitCode -ne 0) { throw "signtool failed (exit $($process.ExitCode))" }
    return $output
}

foreach ($file in $Path) {
    $resolved = (Resolve-Path -LiteralPath $file).Path
    $null = Invoke-SignTool @('sign', '/sha1', $thumbprint, '/fd', 'sha256', '/tr',
        'http://time.certum.pl', '/td', 'sha256', '/d', 'eGuard Agent', $resolved)
    $verification = Invoke-SignTool @('verify', '/pa', '/all', '/v', $resolved)
    $signature = Get-AuthenticodeSignature -LiteralPath $resolved
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $thumbprint -or
        -not $signature.TimeStamperCertificate -or $verification -notmatch '(?im)^\s*The signature is timestamped:') {
        throw 'Signature identity, trust, or required timestamp verification failed'
    }
    Write-Host "Verified signed and timestamped: $file"
}
