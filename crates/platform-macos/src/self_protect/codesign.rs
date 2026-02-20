//! Code signing validation for macOS.
//!
//! Verifies the agent binary's code signature using codesign(1).

#[cfg(target_os = "macos")]
use std::process::Command;

/// Verify the code signature of the running agent binary.
pub fn verify_code_signature() -> Result<(), super::SelfProtectError> {
    #[cfg(target_os = "macos")]
    {
        verify_code_signature_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

/// Verify the code signature of an arbitrary binary path.
pub fn verify_path_signature(path: &str) -> Result<bool, super::SelfProtectError> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("codesign")
            .args(["--verify", "--deep", "--strict", path])
            .output()
            .map_err(|err| {
                super::SelfProtectError::CodeSignFailed(format!("failed spawning codesign: {err}"))
            })?;
        Ok(output.status.success())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Ok(false)
    }
}

#[cfg(target_os = "macos")]
fn verify_code_signature_macos() -> Result<(), super::SelfProtectError> {
    let exe_path = std::env::current_exe().map_err(|err| {
        super::SelfProtectError::CodeSignFailed(format!(
            "failed resolving current executable path: {err}"
        ))
    })?;

    // Only enforce code signature if explicitly required.
    if std::env::var("EGUARD_REQUIRE_CODESIGN")
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
    {
        let output = Command::new("codesign")
            .args([
                "--verify",
                "--deep",
                "--strict",
                &exe_path.to_string_lossy(),
            ])
            .output()
            .map_err(|err| {
                super::SelfProtectError::CodeSignFailed(format!("failed spawning codesign: {err}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(super::SelfProtectError::CodeSignFailed(format!(
                "code signature verification failed for {}: {}",
                exe_path.display(),
                stderr.trim()
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn codesign_stub_succeeds_on_non_macos() {
        #[cfg(not(target_os = "macos"))]
        {
            super::verify_code_signature().expect("codesign stub succeeds");
        }
    }
}
