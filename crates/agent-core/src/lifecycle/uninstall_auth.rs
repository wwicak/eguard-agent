//! Phase-2 remote-uninstall authorization.
//!
//! Remote uninstall is a destructive, self-removal action (MITRE T1562.001).
//! Beyond the default-off `allow_remote_uninstall` flag and the server-side
//! four-eyes approval, the agent binds uninstall authorization to the
//! enrollment token it was provisioned with:
//!
//! * At enrollment we persist only `SHA-256(enrollment_token)` to a 0600 state
//!   file (never the raw bootstrap secret).
//! * At uninstall the operator must supply the matching enrollment token as
//!   `command_data.auth_token`. The agent constant-time compares
//!   `SHA-256(supplied)` to the stored hash before doing anything destructive.
//!
//! Validation is fail-closed: an agent without a provisioned hash, or a
//! missing/incorrect token, refuses the uninstall and honest-acks.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const HASH_FILE: &str = "uninstall_token.sha256";

/// Resolve the eGuard agent data directory. Mirrors the on-disk convention used
/// by the command pipeline and config subsystems so the enrollment writer and
/// the uninstall reader always agree on the path.
fn resolve_agent_data_dir() -> PathBuf {
    if let Ok(raw) = std::env::var("EGUARD_AGENT_DATA_DIR") {
        if !raw.trim().is_empty() {
            return PathBuf::from(raw.trim());
        }
    }

    #[cfg(target_os = "windows")]
    {
        return PathBuf::from(r"C:\ProgramData\eGuard");
    }

    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Library/Application Support/eGuard");
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        PathBuf::from("/var/lib/eguard-agent")
    }
}

/// Absolute path of the persisted uninstall-token hash file.
pub(crate) fn hash_path() -> PathBuf {
    resolve_agent_data_dir().join(HASH_FILE)
}

fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

/// Constant-time equality over two byte slices (length-independent early return
/// only on differing lengths, which are not secret here).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Write `SHA-256(raw_token)` (hex) to `path` with 0600 permissions.
fn write_hash_file(path: &Path, raw_token: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{}\n", sha256_hex(raw_token.as_bytes())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Persist `SHA-256(enrollment_token)` so remote uninstall can later validate
/// the operator-supplied auth token. The raw token is never written to disk.
/// No-op for an empty token. Best-effort: failures are logged, not fatal to
/// enrollment.
pub(crate) fn provision_from_enrollment_token(raw_token: &str) {
    let token = raw_token.trim();
    if token.is_empty() {
        return;
    }
    let path = hash_path();
    match write_hash_file(&path, token) {
        Ok(()) => tracing::info!(
            path = %path.display(),
            "provisioned enrollment-bound uninstall auth hash"
        ),
        Err(err) => tracing::warn!(
            path = %path.display(),
            error = %err,
            "failed to persist uninstall auth hash; remote uninstall will fail closed"
        ),
    }
}

/// Resolve the expected hash: env override first (ops/testing), then the
/// enrollment-provisioned state file.
fn expected_hash_hex() -> Option<String> {
    if let Ok(v) = std::env::var("EGUARD_RESPONSE_UNINSTALL_TOKEN_SHA256") {
        let v = v.trim().to_ascii_lowercase();
        if !v.is_empty() {
            return Some(v);
        }
    }
    std::fs::read_to_string(hash_path())
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
}

/// Extract `auth_token` from the command payload JSON.
fn parse_auth_token(payload_json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(payload_json)
        .ok()
        .and_then(|v| {
            v.get("auth_token")
                .and_then(|t| t.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default()
}

/// Validate a supplied auth token against a known expected hash (pure/testable).
fn verify_with_expected(payload_json: &str, expected_hex: Option<&str>) -> Result<(), String> {
    let expected = expected_hex.map(str::trim).filter(|v| !v.is_empty()).ok_or_else(|| {
        "remote uninstall rejected: no enrollment-bound uninstall token provisioned on this agent (re-enroll to provision one)".to_string()
    })?;

    let supplied = parse_auth_token(payload_json);
    let supplied = supplied.trim();
    if supplied.is_empty() {
        return Err("remote uninstall rejected: missing uninstall auth token".to_string());
    }

    let supplied_hex = sha256_hex(supplied.as_bytes());
    if constant_time_eq(
        supplied_hex.as_bytes(),
        expected.to_ascii_lowercase().as_bytes(),
    ) {
        Ok(())
    } else {
        Err("remote uninstall rejected: invalid uninstall auth token".to_string())
    }
}

/// Validate the supplied uninstall auth token against the enrollment-provisioned
/// secret (fail-closed). Returns `Ok(())` when authorized, or `Err(detail)` with
/// an honest failure reason suitable for the command ack.
pub(crate) fn verify(payload_json: &str) -> Result<(), String> {
    verify_with_expected(payload_json, expected_hash_hex().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!(
            "eguard-uninstall-auth-{tag}-{nanos}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn sha256_hex_known_vector() {
        // SHA-256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn constant_time_eq_matches_and_differs() {
        assert!(constant_time_eq(b"deadbeef", b"deadbeef"));
        assert!(!constant_time_eq(b"deadbeef", b"deadbeee"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn verify_fails_closed_without_expected_hash() {
        let err = verify_with_expected(r#"{"auth_token":"whatever"}"#, None).unwrap_err();
        assert!(err.contains("no enrollment-bound"), "got: {err}");
    }

    #[test]
    fn verify_rejects_missing_token() {
        let expected = sha256_hex(b"secret-token");
        let err = verify_with_expected("{}", Some(&expected)).unwrap_err();
        assert!(err.contains("missing uninstall auth token"), "got: {err}");
    }

    #[test]
    fn verify_rejects_wrong_token() {
        let expected = sha256_hex(b"secret-token");
        let err = verify_with_expected(r#"{"auth_token":"wrong"}"#, Some(&expected)).unwrap_err();
        assert!(err.contains("invalid uninstall auth token"), "got: {err}");
    }

    #[test]
    fn verify_accepts_correct_token() {
        let expected = sha256_hex(b"secret-token");
        assert!(verify_with_expected(r#"{"auth_token":"secret-token"}"#, Some(&expected)).is_ok());
        // Case-insensitive on the stored hex.
        assert!(verify_with_expected(
            r#"{"auth_token":"secret-token"}"#,
            Some(&expected.to_ascii_uppercase())
        )
        .is_ok());
    }

    #[test]
    fn provision_then_verify_roundtrip_via_file() {
        let path = unique_path("roundtrip");
        write_hash_file(&path, "enroll-XYZ").expect("write hash file");
        let stored = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(stored.trim(), sha256_hex(b"enroll-XYZ"));
        // The stored hash validates the matching token and rejects others.
        assert!(
            verify_with_expected(r#"{"auth_token":"enroll-XYZ"}"#, Some(stored.trim())).is_ok()
        );
        assert!(
            verify_with_expected(r#"{"auth_token":"enroll-xyz"}"#, Some(stored.trim())).is_err()
        );
        let _ = std::fs::remove_file(&path);
    }
}
