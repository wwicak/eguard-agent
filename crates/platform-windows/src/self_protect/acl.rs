//! Service and file ACL hardening.
//!
//! Restricts access to the agent's service, process, and files via
//! Windows DACLs.

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
        tracing::warn!("harden_acls is a stub on non-Windows");
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn harden_service_acl() -> Result<(), super::SelfProtectError> {
    // TODO: SetServiceObjectSecurity to restrict service control access
    Ok(())
}

#[cfg(target_os = "windows")]
fn harden_process_acl() -> Result<(), super::SelfProtectError> {
    // TODO: SetSecurityInfo on current process to deny PROCESS_TERMINATE etc.
    Ok(())
}

#[cfg(target_os = "windows")]
fn harden_file_acls() -> Result<(), super::SelfProtectError> {
    // TODO: SetNamedSecurityInfoW on agent installation directory
    Ok(())
}
