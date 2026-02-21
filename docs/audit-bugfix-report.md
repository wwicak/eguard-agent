# Codebase Audit: Bug Fix Report

**Date:** 2026-02-21
**Scope:** 16 confirmed bugs across shell scripts, response crate, compliance crate, macOS platform, and macOS installer
**Approach:** 4 parallel agents, each handling a group of related fixes, followed by lead verification

---

## Re-validation Verdict (2026-02-21)

- ✅ **16/16 fixes are present in source** at the paths cited below.
- ✅ **All reported verification commands re-ran successfully** in this workspace.
- ✅ **Test counts match report claims** (`response`: 45 passed, `compliance`: 24 passed).
- 🔧 **Wording correction applied:** Fix #1 is a config/control-character injection risk; this report no longer overstates it as direct command execution.

## Verification Summary (Re-run)

| Check | Result |
|-------|--------|
| `bash -n scripts/install-eguard-agent.sh` | PASS |
| `bash -n scripts/apply-agent-update.sh` | PASS |
| `cargo check -p response` | PASS |
| `cargo check -p compliance` | PASS |
| `cargo check -p platform-macos` | PASS |
| `cargo test -p response` (45 tests) | PASS |
| `cargo test -p compliance` (24 tests) | PASS |

---

## Fix 1 — Shell/Config Injection in `install-eguard-agent.sh` (CRITICAL)

**File:** `scripts/install-eguard-agent.sh`
**Bug:** Unquoted heredoc `<<EOF` interpolated `${SERVER}` and `${TOKEN}`, allowing crafted values (especially newline/control characters) to inject unintended bootstrap config lines.

**Changes:**
- Added `contains_unsafe_chars()` validation function (matching the macOS installer pattern) — rejects `\n` and `\r` in `--server` and `--token` values
- Replaced unquoted `cat > ... <<EOF` with controlled `printf` writes inside a `(umask 077; ...)` subshell
- Bootstrap content now stays on canonical `[server]` fields (`address`, `grpc_port`, `enrollment_token`) without heredoc expansion behavior
- Changed directory permissions from `0755` to `0700`
- Added explicit `chmod 0600` on `bootstrap.conf`

```diff
-  install -d -m 0755 /etc/eguard-agent
-  cat > /etc/eguard-agent/bootstrap.conf <<EOF
-[server]
-address = ${SERVER}
-enrollment_token = ${TOKEN}
-EOF
+  install -d -m 0700 /etc/eguard-agent
+  (umask 077; {
+    printf '[server]\n'
+    printf 'address = %s\n' "${SERVER}"
+    printf 'grpc_port = 50052\n'
+    printf 'enrollment_token = %s\n' "${TOKEN}"
+  } > /etc/eguard-agent/bootstrap.conf)
+  chmod 0600 /etc/eguard-agent/bootstrap.conf
```

---

## Fix 2 — Missing Input Validation in `apply-agent-update.sh` (CRITICAL)

**File:** `scripts/apply-agent-update.sh`
**Bug:** `VERSION` was used in file paths without validation (path traversal via `../../etc/cron.d/evil`). `CHECKSUM` was not validated for hex format.

**Changes:**
- Added semver regex validation: `^[0-9]+\.[0-9]+\.[0-9]+$`
- Added SHA-256 hex validation: `^[0-9a-fA-F]{64}$`
- Added cleanup trap: `trap 'rm -f "${pkg_path}"' EXIT` to remove failed/corrupt downloads

```diff
+if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
+  echo "error: --version must be valid semver (X.Y.Z)" >&2
+  exit 1
+fi
+
+if [[ ! "${CHECKSUM}" =~ ^[0-9a-fA-F]{64}$ ]]; then
+  echo "error: --checksum must be a 64-character hex SHA-256 hash" >&2
+  exit 1
+fi
```

---

## Fix 3 — `rpm -i` Should Be `rpm -Uvh` (BUG)

**File:** `scripts/install-eguard-agent.sh`
**Bug:** `rpm -i` fails on reinstall/upgrade. The update script already uses `rpm -Uvh`.

**Change:** `INSTALL_CMD=(rpm -i)` → `INSTALL_CMD=(rpm -Uvh)`

---

## Fix 4 — Quarantine Path Traversal via Unsanitized `sha256` (HIGH)

**File:** `crates/response/src/quarantine.rs`
**Bug:** `quarantine_dir.join(sha256)` used `sha256` directly as a filename with no validation. Values containing `../` could escape the quarantine directory.

**Changes:**
- Added `is_valid_quarantine_id()` function: requires non-empty, max 128 chars, hex digits and colons only
- Replaced the empty-string check with the new validation
- Updated test to use a valid hex quarantine ID

```rust
fn is_valid_quarantine_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}
```

---

## Fix 5 — Quarantine Symlink Following Without Canonicalization (HIGH)

**File:** `crates/response/src/quarantine.rs`
**Bug:** `fs::metadata(path)` follows symlinks. A symlink `/tmp/evil -> /etc/passwd` would bypass the `is_protected_path()` check on the link path, then operations would affect the target.

**Changes:**
- Use `fs::symlink_metadata()` to detect symlinks
- If symlink detected: resolve with `fs::canonicalize()`, re-apply `is_protected_path()` on the canonical target
- All subsequent operations (copy, permissions, remove) use the resolved `effective_path`

```rust
let sym_meta = fs::symlink_metadata(path)?;
if sym_meta.file_type().is_symlink() {
    let canonical = fs::canonicalize(path)?;
    if protected.is_protected_path(&canonical) {
        return Err(ResponseError::ProtectedPath(canonical));
    }
    metadata = fs::metadata(&canonical)?;
    effective_path = canonical;
} else {
    metadata = fs::metadata(path)?;
    effective_path = path.to_path_buf();
}
```

---

## Fix 6 — `verify_binary_integrity` Hashes Before Checking Disable Flag (BUG)

**File:** `crates/platform-macos/src/self_protect/integrity.rs`
**Bug:** The function computed SHA-256 hash (expensive I/O) before checking `EGUARD_DISABLE_BINARY_INTEGRITY_CHECK`. If the check was disabled, the hash was wasted.

**Change:** Moved the env var check to immediately after resolving the executable path, before the hash computation. Original `if let Some(expected_hash)` logic preserved unchanged.

---

## Fix 7 — `restore_file` Not Re-exported from `response/mod.rs` (BUG)

**File:** `crates/platform-macos/src/response/mod.rs`
**Bug:** `quarantine_file` was re-exported but `restore_file` was not, making it inaccessible to external callers.

**Change:** Added `pub use quarantine::restore_file;`

---

## Fix 8 — `postinstall` Fails on Reinstall (BUG)

**File:** `installer/macos/scripts/postinstall`
**Bug:** `launchctl bootstrap` fails with EALREADY (exit 36) if the service is already registered. With `set -e`, this aborts the entire postinstall.

**Change:** Added `launchctl bootout system/com.eguard.agent 2>/dev/null || true` before `bootstrap` to ensure clean state. Also added proper directory permission hardening (`chmod 700`).

---

## Fix 9 — `preinstall` Missing `set -euo pipefail` (BUG)

**File:** `installer/macos/scripts/preinstall`
**Bug:** Inconsistent with `postinstall` which has strict error handling.

**Change:** Added `set -euo pipefail` after the shebang.

---

## Fix 10 — LaunchDaemon `ProcessType = Interactive` (BUG)

**File:** `installer/macos/com.eguard.agent.plist`
**Bug:** `Interactive` is for GUI apps requiring window server access. A security daemon should use `Background`.

**Change:** `<string>Interactive</string>` → `<string>Background</string>`

---

## Fix 11 — LaunchDaemon `AbandonProcessGroup = true` (BUG)

**File:** `installer/macos/com.eguard.agent.plist`
**Bug:** Prevents launchd from sending SIGTERM to child processes on stop, creating orphan monitoring gaps.

**Change:** Removed the `<key>AbandonProcessGroup</key>` and `<true/>` lines entirely. Default `false` is the correct behavior.

---

## Fix 12 — `looks_like_regex` Treats `.` as Regex Indicator (BUG)

**File:** `crates/response/src/lib.rs`
**Bug:** Process names containing dots (e.g., `svchost.exe`, `com.apple.loginwindow`) were incorrectly treated as regex patterns, causing `.` to match any character and widening protection checks.

**Change:** Removed `.` from the regex indicator character set. All other regex indicators (`^$*+?[](){}|`) retained.

```diff
-            '^' | '$' | '.' | '*' | '+' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|'
+            '^' | '$' | '*' | '+' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|'
```

---

## Fix 13 — Recursive `collect_descendants` Without Depth Limit (BUG)

**File:** `crates/response/src/kill.rs`
**Bug:** Recursive function with no depth guard. A deeply nested process tree would cause stack overflow.

**Change:** Converted from recursive DFS to iterative BFS using `VecDeque`. Two existing tests updated for BFS traversal order (children now visited in breadth-first rather than depth-first order).

```rust
let mut queue = VecDeque::new();
queue.push_back(pid);
while let Some(current) = queue.pop_front() {
    for child in introspector.children_of(current) {
        if seen.insert(child) {
            out.push(child);
            queue.push_back(child);
        }
    }
}
```

---

## Fix 14 — Password Policy `?` Operator Causes Silent Early Return (BUG)

**File:** `crates/compliance/src/lib.rs`
**Bug:** `v.split_whitespace().next()?.parse::<u64>().ok()?` — the `?` inside the loop body caused the entire function to return `None` if `PASS_MAX_DAYS` had a non-numeric value (e.g., a comment or text). This reported "unknown" instead of "non_compliant".

**Change:** Replaced `?` chain with `if let` to skip unparseable lines:

```diff
-                let days = v.split_whitespace().next()?.parse::<u64>().ok()?;
-                max_days_ok = days <= 90;
+                if let Some(days) = v.split_whitespace().next().and_then(|s| s.parse::<u64>().ok()) {
+                    max_days_ok = days <= 90;
+                }
```

---

## Fix 15 — SSH Root Login Returns `Some(false)` When Directive Absent (BUG)

**File:** `crates/compliance/src/lib.rs`
**Bug:** When `PermitRootLogin` is not found in `sshd_config`, returned `Some(false)` (root login disabled). But OpenSSH defaults to `prohibit-password` (key-based root login IS allowed), not `no`. This falsely reported compliance.

**Change:** `Some(false)` → `None` (unknown). Updated corresponding test expectation.

---

## Fix 16 — PAM Password Policy Matches Commented-Out Lines (BUG)

**File:** `crates/compliance/src/lib.rs`
**Bug:** `lower.contains("pam_pwquality.so")` matched commented-out lines like `# password requisite pam_pwquality.so`, falsely reporting password quality enforcement was active.

**Change:** Replaced whole-string search with line-by-line iteration that skips lines starting with `#`:

```rust
for line in raw.lines() {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        continue;
    }
    let lower_line = trimmed.to_ascii_lowercase();
    if lower_line.contains("pam_pwquality.so") || lower_line.contains("pam_cracklib.so") {
        pam_quality_ok = true;
        break;
    }
}
```

---

## Evidence Pointers (Source Re-check)

| Fixes | Evidence |
|------|----------|
| 1, 3 | `scripts/install-eguard-agent.sh`: `contains_unsafe_chars` + validation (`8`, `50`, `55`), `INSTALL_CMD=(rpm -Uvh)` (`65`), hardened bootstrap write (`82`-`89`) |
| 2 | `scripts/apply-agent-update.sh`: semver guard (`63`), checksum guard (`68`), cleanup trap (`78`) |
| 4, 5 | `crates/response/src/quarantine.rs`: quarantine ID validation (`69`, `206`), `symlink_metadata` + `canonicalize` (`77`, `82`) |
| 6 | `crates/platform-macos/src/self_protect/integrity.rs`: disable gate before hashing (`25`, `38`) |
| 7 | `crates/platform-macos/src/response/mod.rs`: `pub use quarantine::restore_file` (`13`) |
| 8, 9, 10, 11 | `installer/macos/scripts/postinstall`: `bootout` before `bootstrap` + `chmod 700` (`14`-`16`, `24`-`25`); `installer/macos/scripts/preinstall`: strict shell mode (`2`); `installer/macos/com.eguard.agent.plist`: `ProcessType=Background` and no `AbandonProcessGroup` (`21`-`22`) |
| 12, 13 | `crates/response/src/lib.rs`: `looks_like_regex` no longer treats `.` as regex indicator (`229`-`234`); `crates/response/src/kill.rs`: iterative `VecDeque` traversal (`361`-`367`) |
| 14, 15, 16 | `crates/compliance/src/lib.rs`: safe PASS_MAX_DAYS parse (`1281`-`1282`), missing `PermitRootLogin` => `None` (`1205`-`1223`), PAM comment skipping (`1293`-`1298`); test expectation in `crates/compliance/src/tests.rs` (`279`-`282`) |

---

## Files Modified

> Line deltas below are from the original patch set that introduced these fixes.

| File | Lines Changed | Fixes |
|------|--------------|-------|
| `scripts/install-eguard-agent.sh` | +27 -7 | 1, 3 |
| `scripts/apply-agent-update.sh` | +12 -1 | 2 |
| `crates/response/src/quarantine.rs` | +31 -6 | 4, 5 |
| `crates/response/src/quarantine/tests.rs` | +1 -1 | 4 |
| `crates/response/src/lib.rs` | +1 -1 | 12 |
| `crates/response/src/kill.rs` | +10 -5 | 13 |
| `crates/response/src/kill/tests.rs` | +2 -2 | 13 |
| `crates/compliance/src/lib.rs` | +16 -4 | 14, 15, 16 |
| `crates/compliance/src/tests.rs` | +1 -1 | 15 |
| `crates/platform-macos/src/self_protect/integrity.rs` | +13 -0 | 6 |
| `crates/platform-macos/src/response/mod.rs` | +1 -0 | 7 |
| `installer/macos/scripts/postinstall` | +16 -5 | 8 |
| `installer/macos/scripts/preinstall` | +1 -0 | 9 |
| `installer/macos/com.eguard.agent.plist` | +1 -3 | 10, 11 |
