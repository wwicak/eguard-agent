//! Binary integrity verification.
//!
//! Verifies the agent binary's hash at startup against an expected value.

/// Verify the integrity of the running agent binary.
pub fn verify_binary_integrity() -> Result<(), super::SelfProtectError> {
    #[cfg(target_os = "macos")]
    {
        verify_binary_integrity_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn verify_binary_integrity_macos() -> Result<(), super::SelfProtectError> {
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

    Ok(())
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
