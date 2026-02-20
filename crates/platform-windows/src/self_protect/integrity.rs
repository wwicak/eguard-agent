//! Binary integrity verification.
//!
//! Verifies the agent binary's Authenticode signature and hash on startup.

/// Verify the integrity of the running agent binary.
pub fn verify_binary_integrity() -> Result<(), super::SelfProtectError> {
    #[cfg(target_os = "windows")]
    {
        // TODO: WinVerifyTrust for Authenticode signature validation
        // TODO: Compare SHA-256 hash against known-good value
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("verify_binary_integrity is a stub on non-Windows");
        Ok(())
    }
}

/// Verify Authenticode signature on a given file path.
pub fn verify_authenticode(path: &str) -> Result<bool, super::SelfProtectError> {
    #[cfg(target_os = "windows")]
    {
        // TODO: WinVerifyTrust(path)
        let _ = path;
        Ok(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        tracing::warn!("verify_authenticode is a stub on non-Windows");
        Ok(false)
    }
}
