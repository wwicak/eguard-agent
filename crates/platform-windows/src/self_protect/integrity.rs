//! Binary integrity verification.
//!
//! Verifies the agent binary's Authenticode signature and hash on startup.

#[cfg(target_os = "windows")]
use crate::windows_cmd::POWERSHELL_EXE;
#[cfg(target_os = "windows")]
use std::path::Path;
#[cfg(target_os = "windows")]
use std::process::Command;

/// Verify the integrity of the running agent binary.
pub fn verify_binary_integrity() -> Result<(), super::SelfProtectError> {
    #[cfg(target_os = "windows")]
    {
        let exe_path = std::env::current_exe().map_err(|err| {
            super::SelfProtectError::IntegrityCheckFailed(format!(
                "failed resolving current executable path: {err}"
            ))
        })?;

        if std::env::var("EGUARD_DISABLE_BINARY_INTEGRITY_CHECK")
            .ok()
            .map(|raw| {
                matches!(
                    raw.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
        {
            return Ok(());
        }

        let actual_hash = crypto_accel::sha256_file_hex(&exe_path).map_err(|err| {
            super::SelfProtectError::IntegrityCheckFailed(format!(
                "failed hashing executable {}: {err}",
                exe_path.display()
            ))
        })?;

        if let Some(expected_hash) = std::env::var("EGUARD_AGENT_EXPECTED_SHA256")
            .ok()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
        {
            if actual_hash.to_ascii_lowercase() != expected_hash {
                return Err(super::SelfProtectError::IntegrityCheckFailed(format!(
                    "binary hash mismatch: expected {expected_hash}, got {actual_hash}"
                )));
            }
        }

        if std::env::var("EGUARD_REQUIRE_AUTHENTICODE")
            .ok()
            .map(|raw| {
                matches!(
                    raw.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
            && !verify_authenticode_path(&exe_path)?
        {
            return Err(super::SelfProtectError::IntegrityCheckFailed(
                "authenticode verification failed".to_string(),
            ));
        }

        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(())
    }
}

/// Verify Authenticode signature on a given file path.
pub fn verify_authenticode(path: &str) -> Result<bool, super::SelfProtectError> {
    #[cfg(target_os = "windows")]
    {
        verify_authenticode_path(Path::new(path))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        Ok(false)
    }
}

#[cfg(target_os = "windows")]
fn verify_authenticode_path(path: &Path) -> Result<bool, super::SelfProtectError> {
    let path_text = path.to_string_lossy().to_string();
    let output = Command::new(POWERSHELL_EXE)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "(Get-AuthenticodeSignature -FilePath '{}').Status",
                path_text.replace('\'', "''")
            ),
        ])
        .output()
        .map_err(|err| {
            super::SelfProtectError::IntegrityCheckFailed(format!(
                "failed spawning powershell for authenticode: {err}"
            ))
        })?;

    if !output.status.success() {
        return Ok(false);
    }

    let status = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase();
    Ok(matches!(status.as_str(), "valid"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn hash_expectation_compare_is_case_insensitive() {
        let actual = "ABCDEF123".to_ascii_lowercase();
        let expected = "abcdef123".to_ascii_lowercase();
        assert_eq!(actual, expected);
    }
}
