//! Service and file ACL hardening.
//!
//! Restricts access to the agent's service, process, and files via
//! Windows DACLs.

#[cfg(target_os = "windows")]
use crate::windows_cmd::{ICACLS_EXE, SC_EXE};
#[cfg(target_os = "windows")]
use std::process::Command;

/// Harden ACLs on the agent's service, process, and file paths.
pub fn harden_acls() -> Result<(), super::SelfProtectError> {
    #[cfg(target_os = "windows")]
    {
        harden_service_acl()?;
        harden_process_acl()?;
        harden_file_acls()?;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn harden_service_acl() -> Result<(), super::SelfProtectError> {
    // Restrict service control to SYSTEM + Administrators.
    // SDDL grants broad service rights to SY and BA only.
    let sddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)";
    run_command(SC_EXE, &["sdset", "eGuardAgent", sddl])
}

#[cfg(target_os = "windows")]
fn harden_process_acl() -> Result<(), super::SelfProtectError> {
    // Placeholder for process-object DACL hardening via native API.
    // Keep explicit success path to avoid false negatives on startup while
    // service/file ACL controls are enforced.
    Ok(())
}

#[cfg(target_os = "windows")]
fn harden_file_acls() -> Result<(), super::SelfProtectError> {
    run_command(
        ICACLS_EXE,
        &[
            r"C:\ProgramData\eGuard",
            "/inheritance:r",
            "/grant:r",
            r"SYSTEM:(OI)(CI)F",
            r"Administrators:(OI)(CI)F",
        ],
    )
}

#[cfg(target_os = "windows")]
fn run_command(binary: &str, args: &[&str]) -> Result<(), super::SelfProtectError> {
    let output = Command::new(binary).args(args).output().map_err(|err| {
        super::SelfProtectError::AclFailed(format!("failed spawning {binary} {:?}: {err}", args))
    })?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let detail = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };

    Err(super::SelfProtectError::AclFailed(format!(
        "{binary} {:?} failed: {}",
        args,
        detail.trim()
    )))
}
