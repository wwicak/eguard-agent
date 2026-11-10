param([switch]$ValidateOnly)
$ErrorActionPreference = 'Stop'
Set-PSDebug -Off

function Mask-Value([string]$Value) {
    if ($Value) {
        $escaped = $Value.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
        Write-Host "::add-mask::$escaped"
    }
}

# Only static diagnostics may escape this script: parser/UI exceptions can contain credentials.
try {
    $raw = $env:SIMPLYSIGN_CODE
    Mask-Value $raw
    $raw = $raw.Trim()
    Mask-Value $raw
    $seed = $raw
    $format = 'base32'
    if ($raw.StartsWith('otpauth://', [StringComparison]::OrdinalIgnoreCase)) {
        $uri = [uri]$raw
        if ($uri.Scheme -ne 'otpauth' -or $uri.Host -ne 'totp') { throw 'format' }
        $query = [System.Web.HttpUtility]::ParseQueryString($uri.Query)
        if (($query['algorithm'] -and $query['algorithm'] -ne 'SHA1') -or
            ($query['digits'] -and $query['digits'] -ne '6') -or
            ($query['period'] -and $query['period'] -ne '30')) { throw 'format' }
        $seed = $query['secret']
        $format = 'otpauth'
    }
    Mask-Value $seed
    if ($seed -notmatch '^[A-Za-z2-7]{16,}={0,6}$') { throw 'format' }
    $seed = $seed.TrimEnd('=').ToUpperInvariant()
    Mask-Value $seed
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    $key = [System.Collections.Generic.List[byte]]::new()
    $buffer = 0
    $bits = 0
    foreach ($c in $seed.ToCharArray()) {
        $buffer = ($buffer -shl 5) -bor $alphabet.IndexOf($c)
        $bits += 5
        if ($bits -ge 8) {
            $bits -= 8
            $key.Add([byte](($buffer -shr $bits) -band 255))
            $buffer = $buffer -band ((1 -shl $bits) - 1)
        }
    }
    if ($buffer -ne 0 -or $key.Count -lt 10 -or $bits -ge 5) { throw 'format' }
} catch {
    Write-Host '::error::SIMPLYSIGN_CODE is not a TOTP seed (looks like a one-time activation code)'
    exit 1
}
Write-Host "SIMPLYSIGN_CODE format: $format (SHA1/6 digits/30 seconds)"
if ($ValidateOnly) { exit 0 }

function New-Token([byte[]]$KeyBytes, [long]$Seconds) {
    $counter = [BitConverter]::GetBytes([long][Math]::Floor($Seconds / 30))
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($counter) }
    $hmac = [Security.Cryptography.HMACSHA1]::new($KeyBytes)
    try { $hash = $hmac.ComputeHash($counter) } finally { $hmac.Dispose() }
    $offset = $hash[19] -band 15
    $value = (([int]$hash[$offset] -band 127) -shl 24) -bor ([int]$hash[$offset + 1] -shl 16) -bor
        ([int]$hash[$offset + 2] -shl 8) -bor [int]$hash[$offset + 3]
    return ($value % 1000000).ToString('D6')
}

$stage = 'TOTP self-check'
try {
    # RFC 6238 public test vector; never emit tokens, even test tokens.
    $testKey = [Text.Encoding]::ASCII.GetBytes('12345678901234567890')
    if ((New-Token $testKey 59) -ne '287082' -or (New-Token $testKey 1111111109) -ne '081804') {
        throw 'self-check'
    }
    $stage = 'official installer download and publisher validation'
    $installer = Join-Path $env:RUNNER_TEMP 'SimplySignDesktop.msi'
    Invoke-WebRequest -Uri 'https://files.certum.eu/software/SimplySignDesktop/Windows/9.4.4.92/SimplySignDesktop-9.4.4.92-64-bit-en.msi' -OutFile $installer -TimeoutSec 180
    if ((Get-FileHash $installer -Algorithm SHA256).Hash -ne '8EC420FC27798B86078B7BD02FE7152097E1B3005BAB51820EACA8E57DF84DA3') { throw 'hash' }
    $signature = Get-AuthenticodeSignature $installer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?i)(Asseco Data Systems|Certum)') { throw 'publisher' }
    Write-Host "Installer signature: $($signature.Status); publisher: $($signature.SignerCertificate.Subject)"
    $stage = 'SimplySign Desktop silent installation'
    $install = Start-Process msiexec.exe -ArgumentList @('/i', "`"$installer`"", '/qn', '/norestart') -PassThru
    if (-not $install.WaitForExit(180000)) { $install.Kill(); throw 'timeout' }
    if ($install.ExitCode -notin @(0, 3010)) { throw 'install' }
    $stage = 'SimplySign Desktop login'
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    $exe = Get-ChildItem 'C:\Program Files\Certum', 'C:\Program Files\Asseco*' -Filter SimplySignDesktop.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $exe) {
        $exe = Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' -Filter SimplySignDesktop.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (-not $exe) { throw 'executable' }
    $shell = New-Object -ComObject WScript.Shell
    $thumbprint = 'E57B64FE5904651C3CD10FF8E3CBCCADF0317CDF'
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        $process = Start-Process $exe.FullName -PassThru
        $window = $null
        $until = [DateTime]::UtcNow.AddSeconds(30)
        while ([DateTime]::UtcNow -lt $until -and -not $window) {
            $windows = [Windows.Automation.AutomationElement]::RootElement.FindAll(
                [Windows.Automation.TreeScope]::Children, [Windows.Automation.Condition]::TrueCondition)
            foreach ($candidate in $windows) {
                if ($candidate.Current.Name -like '*SimplySign*') { $window = $candidate; break }
            }
            if (-not $window) { Start-Sleep -Milliseconds 500 }
        }
        if (-not $window) { throw 'window' }
        $edits = $window.FindAll([Windows.Automation.TreeScope]::Descendants,
            [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ControlTypeProperty,
                [Windows.Automation.ControlType]::Edit))
        Write-Host "SimplySign login attempt $($attempt + 1): editable controls=$($edits.Count)"
        if ($edits.Count -ne 2) { throw 'unexpected login controls' }
        # Wait away from the expiry boundary, then mask the token before any UI calls.
        $seconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if (($seconds % 30) -gt 24) { Start-Sleep -Seconds (31 - ($seconds % 30)) }
        $token = New-Token $key.ToArray() ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
        Mask-Value $token
        $userPattern = $edits[0].GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)
        $userPattern.SetValue($env:SIMPLYSIGN_EMAIL)
        # Password controls may not expose ValuePattern; focus the token field explicitly.
        if (-not $shell.AppActivate($window.Current.ProcessId)) { throw 'focus' }
        $edits[1].SetFocus()
        $shell.SendKeys('^a')
        $shell.SendKeys($token)
        $shell.SendKeys('{ENTER}')
        $token = $null
        $until = [DateTime]::UtcNow.AddSeconds(120)
        while ([DateTime]::UtcNow -lt $until) {
            $certificate = Get-Item "Cert:\CurrentUser\My\$thumbprint" -ErrorAction SilentlyContinue
            if ($certificate -and $certificate.HasPrivateKey) {
                Write-Host "SimplySign certificate ready: $thumbprint"
                exit 0
            }
            Start-Sleep -Seconds 2
        }
    }
    throw 'certificate readiness timeout'
} catch {
    Write-Host "::error::SimplySign failed at stage: $stage. No credentials or UI values logged."
    exit 1
} finally {
    $token = $null
    $seed = $null
    $raw = $null
    if ($key) { $key.Clear() }
}
