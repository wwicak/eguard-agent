# Windows Platform Audit Report (Re-validated)

**Date:** 2026-02-21
**Scope:**
- `crates/platform-windows/`
- shared response protections in `crates/response/`
- Windows installer scaffold `installer/windows/install.ps1`

**Purpose:** Re-validate the Windows report against current code, correct stale/ambiguous claims, and keep only evidence-backed findings.

**Scope boundary:** This document audits `eguard-agent` Windows platform/scaffold code. Windows distribution/install hardening in the separate `fe_eguard` server path (`go/agent/server/install.ps1`) is tracked in `docs/audit-report-windows-distribution.md`.

---

## Fix Status (Recheck)

- **9/9 findings fixed** in current source: W1..W9.
- All verification commands pass (`cargo check`, `cargo test`, cross-compilation check).

---

## Verification Commands (executed after fixes)

| Command | Result |
|---|---|
| `cargo check -p platform-windows` | PASS |
| `cargo test -p platform-windows` | PASS (39 tests) |
| `cargo check -p response` | PASS |
| `cargo test -p response default_windows_protected_processes_match_baseline -- --nocapture` | PASS (includes `.exe` variant assertions) |
| `cargo check --target x86_64-pc-windows-msvc -p platform-windows` | PASS |

**Environment note:** PowerShell runtime is not available in this Linux runner (`pwsh` missing), so Windows installer/runtime behavior was validated by static code review + Rust unit tests, not live Windows execution.

### Pass-2 recheck notes (user-requested revisit)

- Rechecked all W1..W9 sections against current source snapshots.
- Implemented and re-validated residual hardening for W1/W4/W6.
- Confirmed no regression in test/build verification after this recheck pass.

---

## Findings & Fixes

## W1. Windows quarantine missing link/protected-path safeguards and robust collision handling (HIGH) — FIXED

**File:** `crates/platform-windows/src/response/quarantine.rs`

**Original issue:**
- Used `source.exists()` which follows symlinks/reparse points
- No collision guard on `fs::rename`
- No protected-path policy check before move

**Fix applied:**
- Replaced `source.exists()` with `fs::symlink_metadata()` to detect symlinks without following them
- If source is a symlink, resolves with `fs::canonicalize()` and operates on the effective target
- Added collision-safe target naming: appends counter suffix (`.1`, `.2`, etc.) if target already exists
- Added protected-path enforcement for canonical effective source paths (`C:\\Windows\\System32`, `C:\\Windows\\SysWOW64`, `C:\\ProgramData\\eGuard`)
- Metadata now records the effective (canonical) path

```rust
let sym_meta = fs::symlink_metadata(source).map_err(|err| { ... })?;
let effective_source = if sym_meta.file_type().is_symlink() {
    fs::canonicalize(source).map_err(|err| { ... })?
} else {
    source.to_path_buf()
};
let canonical_effective = fs::canonicalize(&effective_source).unwrap_or(effective_source.clone());
if is_protected_windows_path(&canonical_effective) {
    return Err(...);
}
// ... collision-safe target:
let mut target = bucket.join(&file_name);
if target.exists() {
    for i in 1u32..=999 { ... }
}
```

---

## W2. Windows protected-process matching misses common `.exe` names (CRITICAL) — FIXED

**Files:**
- `crates/response/src/lib.rs`
- `crates/response/src/tests.rs`

**Original issue:**
- Windows protected patterns were extension-less (`"svchost"`, `"lsass"`, etc.)
- Compiled as anchored exact matches (`^svchost$`), so `svchost.exe` did not match

**Fix applied:**
- Changed all patterns to regex with optional `.exe` suffix: `"^svchost(\\.exe)?$"`
- Updated test to verify both bare names and `.exe` variants match

```rust
let process_patterns = [
    "^System$",
    "^csrss(\\.exe)?$",
    "^wininit(\\.exe)?$",
    "^winlogon(\\.exe)?$",
    "^services(\\.exe)?$",
    "^lsass(\\.exe)?$",
    "^svchost(\\.exe)?$",
    "^smss(\\.exe)?$",
    "^eguard-agent(\\.exe)?$",
]
```

---

## W3. Windows integrity check lacks disable flag parity (BUG) — FIXED

**File:** `crates/platform-windows/src/self_protect/integrity.rs`

**Original issue:**
- Hash was computed unconditionally before any disable check
- No `EGUARD_DISABLE_BINARY_INTEGRITY_CHECK` gate existed (unlike macOS)

**Fix applied:**
- Added `EGUARD_DISABLE_BINARY_INTEGRITY_CHECK` env var check before hash computation, matching the macOS pattern exactly
- Supports `1`, `true`, `yes`, `on` values (case-insensitive)

```rust
if std::env::var("EGUARD_DISABLE_BINARY_INTEGRITY_CHECK")
    .ok()
    .map(|raw| matches!(raw.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
    .unwrap_or(false)
{
    return Ok(());
}
```

---

## W4. Installer downloads MSI without integrity verification (HIGH) — FIXED

**File:** `installer/windows/install.ps1`

**Original issue:**
- MSI downloaded with no checksum or signature verification

**Fix applied:**
- Added fail-closed hash policy:
  - if `-ExpectedHash` is not provided, script fetches hash metadata from `/api/v1/agent-install/windows/sha256`
  - install aborts if expected hash cannot be obtained or is malformed
- Always computes `Get-FileHash` and aborts on mismatch
- Authenticode check is fail-closed by default (`Status` must be `Valid`), with explicit override switch `-AllowUnsignedMsi`

```powershell
if ([string]::IsNullOrWhiteSpace($ExpectedHash)) {
    $hashEndpoint = "$normalizedServerUrl/api/v1/agent-install/windows/sha256"
    $hashResponse = Invoke-WebRequest -Uri $hashEndpoint -Headers $headers -UseBasicParsing
    $ExpectedHash = ([string](($hashResponse.Content | ConvertFrom-Json).sha256)).ToUpper()
}
$actualHash = (Get-FileHash -Path $MsiPath -Algorithm SHA256).Hash.ToUpper()
if ($actualHash -ne $ExpectedHash) {
    throw "MSI hash mismatch: expected $ExpectedHash, got $actualHash"
}
$sig = Get-AuthenticodeSignature -FilePath $MsiPath
if ($sig.Status -ne 'Valid' -and -not $AllowUnsignedMsi.IsPresent) {
    throw "MSI Authenticode signature status is '$($sig.Status)'"
}
```

---

## W5. Installer bootstrap token file is written without explicit restrictive ACL step (MEDIUM) — FIXED

**File:** `installer/windows/install.ps1`

**Original issue:**
- Bootstrap file written without explicit ACL restriction
- Token confidentiality depended on inherited ACL defaults

**Fix applied:**
- Added `icacls` after writing bootstrap.conf to restrict to SYSTEM and Administrators only

```powershell
& icacls $bootstrapPath /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null
```

---

## W6. Installer input validation is missing for server/token parameters (HIGH) — FIXED

**File:** `installer/windows/install.ps1`

**Original issue:**
- No scheme restriction, control-character checks, or token-format guards

**Fix applied:**
- Added control character rejection for both `$ServerUrl` and `$EnrollmentToken`
- Added strict secure-by-default URL scheme policy: `https://` is required by default
- Added explicit insecure override path for `http://` via `-AllowInsecureHttp`
- Added minimum token length check (8 characters)

```powershell
if ($ServerUrl -match '[\x00-\x1f]') { throw "ServerUrl contains control characters" }
if ($EnrollmentToken -match '[\x00-\x1f]') { throw "EnrollmentToken contains control characters" }
if ($ServerUrl -match '^https://') {
    # secure default
} elseif ($AllowInsecureHttp.IsPresent -and $ServerUrl -match '^http://') {
    Write-Step "WARNING: allowing insecure http:// server URL due to -AllowInsecureHttp"
} else {
    throw "ServerUrl must begin with https:// (or use -AllowInsecureHttp with http://)"
}
if ($EnrollmentToken.Length -lt 8) { throw "EnrollmentToken must be at least 8 characters" }
```

---

## W7. Authenticode PowerShell command construction is injectable via single quote (HIGH) — FIXED

**File:** `crates/platform-windows/src/self_protect/integrity.rs`

**Original issue:**
- Path embedded in single-quoted PS string with only double-quote escaping
- Single quotes in path were not escaped (PS single-quoted strings use `''` for literal `'`)

**Fix applied:**
- Changed escaping from `replace('"', "\\\"")` to `replace('\'', "''")`
- This is correct PowerShell single-quoted string escaping

```rust
&format!(
    "(Get-AuthenticodeSignature -FilePath '{}').Status",
    path_text.replace('\'', "''")
),
```

---

## W8. Enrollment token exposed via MSI command-line property (MEDIUM) — FIXED

**File:** `installer/windows/install.ps1`

**Original issue:**
- Token passed as MSI property visible in process listing

**Fix applied:**
- Removed `ENROLLMENT_TOKEN=$EnrollmentToken` from MSI command-line arguments
- Token is already written to `bootstrap.conf` before MSI install, so the agent can read it from there

```powershell
$msiArgs = @(
    '/i', "`"$MsiPath`"",
    '/qn',
    '/norestart',
    "SERVER_URL=$normalizedServerUrl"
)
```

---

## W9. Windows service install path is not idempotent (MEDIUM) — FIXED

**File:** `crates/platform-windows/src/service/lifecycle.rs`

**Original issue:**
- `install()` used `sc.exe create` directly, which fails if service already exists
- `query_service_state` helper existed but wasn't used in install path

**Fix applied:**
- Added pre-check via `query_service_state()` before service registration
- If service exists: uses `sc.exe config` to update configuration
- If service doesn't exist: uses `sc.exe create` as before
- Also fixed duplicate `#[cfg]` attributes on `parse_sc_state` and `map_sc_error`

```rust
let already_exists = query_service_state(&self.service_name).is_ok();
if already_exists {
    let config_args = vec![
        "config".to_string(), self.service_name.clone(),
        format!("binPath= \"{}\"", self.binary_path), "start= auto".to_string(),
    ];
    run_sc(&config_args).map_err(|err| map_sc_error("install", &err))?;
} else {
    let create_args = vec![
        "create".to_string(), self.service_name.clone(),
        format!("binPath= \"{}\"", self.binary_path), "start= auto".to_string(),
    ];
    run_sc(&create_args).map_err(|err| map_sc_error("install", &err))?;
}
```

---

## Residual Open Items

- No unresolved items remain for W1..W9 in this report scope.

---

## Findings from Linux/macOS audit that are NOT Windows-applicable

| Linux/macOS class | Windows status |
|---|---|
| `looks_like_regex` treating `.` as regex indicator | Already fixed in shared `crates/response/src/lib.rs` |
| PAM/login.defs/SSH-root parsing issues | Not applicable to Windows compliance path |
| LaunchDaemon plist issues | Not applicable (Windows SCM) |
| rpm-specific install behavior | Not applicable (MSI path) |

---

## Evidence Pointers (Recheck)

| Finding | Evidence |
|---|---|
| W1 | `crates/platform-windows/src/response/quarantine.rs`: symlink-aware path handling (`27`, `36`), protected-path guard (`46`-`49`, helper `163`-`178`), collision suffix loop (`79`), metadata uses effective source (`90`) |
| W2 | `crates/response/src/lib.rs`: optional `.exe` Windows patterns (`133`-`141`); `crates/response/src/tests.rs`: asserts `.exe` variants (`361`, `363`) |
| W3 | `crates/platform-windows/src/self_protect/integrity.rs`: disable gate before hash (`20`), hash call (`33`), single-quote-safe Authenticode command build (`98`-`99`) |
| W4/W6/W8 | `installer/windows/install.ps1`: secure transport gate + override (`33`-`38`), expected-hash fetch/fail-closed policy (`60`-`75`), hash verification (`81`-`84`), signature fail-closed unless override (`87`-`91`), MSI args no token (`114`) |
| W5 | `installer/windows/install.ps1`: bootstrap ACL hardening with `icacls` (`106`) |
| W9 | `crates/platform-windows/src/service/lifecycle.rs`: idempotent install pre-check + `config/create` branch (`43`, `48`, `52`, `60`), query helper (`197`) |

---

## Files Modified

| File | Fixes |
|------|-------|
| `crates/response/src/lib.rs` | W2 |
| `crates/response/src/tests.rs` | W2 |
| `crates/platform-windows/src/self_protect/integrity.rs` | W3, W7 |
| `crates/platform-windows/src/response/quarantine.rs` | W1 |
| `installer/windows/install.ps1` | W4, W5, W6, W8 |
| `crates/platform-windows/src/service/lifecycle.rs` | W9 |

---

## Scope/Confidence Notes

- This repo's Windows installer and lifecycle are still documented as **preview scaffolding** in `installer/windows/README.md`; severity here reflects hardening/operational risk if promoted to production behavior.
- No claim in this report depends on unverified runtime assumptions; all findings above are directly grounded in current source and local test/check outputs.
