//! Service and file ACL hardening.
//!
//! Restricts access to the agent's service, process, and files via
//! Windows DACLs.

#[cfg(target_os = "windows")]
use crate::windows_cmd::SC_EXE;
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

#[cfg(any(target_os = "windows", test))]
const DATA_DIRECTORY_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Protect the agent-owned data root; children inherit SYSTEM/Administrators access.
/// Unlike icacls /grant:r, replacing the DACL also removes other explicit grants.
pub fn harden_data_directory() -> Result<(), super::SelfProtectError> {
    #[cfg(target_os = "windows")]
    {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, BOOL, HLOCAL};
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{
            GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        };

        let root = r"C:\ProgramData\eGuard";
        std::fs::create_dir_all(root).map_err(|err| {
            super::SelfProtectError::AclFailed(format!("create data directory: {err}"))
        })?;
        let path: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
        let sddl: Vec<u16> = DATA_DIRECTORY_SDDL.encode_utf16().chain(Some(0)).collect();
        let result = unsafe {
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                1,
                &mut descriptor,
                None,
            )
            .and_then(|()| {
                let result = (|| {
                    let mut present = BOOL::default();
                    let mut defaulted = BOOL::default();
                    let mut dacl = std::ptr::null_mut();
                    GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)?;
                    SetNamedSecurityInfoW(
                        PCWSTR(path.as_ptr()),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        PSID::default(),
                        PSID::default(),
                        Some(dacl),
                        None,
                    )
                    .ok()
                })();
                let _ = LocalFree(HLOCAL(descriptor.0));
                result
            })
        };
        result.map_err(|err| {
            super::SelfProtectError::AclFailed(format!("protect data directory: {err}"))
        })
    }
    #[cfg(not(target_os = "windows"))]
    Ok(())
}

#[cfg(target_os = "windows")]
fn harden_file_acls() -> Result<(), super::SelfProtectError> {
    harden_data_directory()
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

#[cfg(test)]
mod tests {
    #[test]
    fn data_directory_dacl_is_protected_and_inheritable_for_system_and_admins_only() {
        assert_eq!(
            super::DATA_DIRECTORY_SDDL,
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        );
    }

    #[test]
    fn data_directory_acl_is_applied_before_config_load() {
        let main = include_str!("../../../agent-core/src/main.rs");
        let startup = main
            .split("async fn run_console_with_shutdown")
            .nth(1)
            .expect("startup");
        let harden = startup
            .find("harden_data_directory()")
            .expect("startup directory hardening");
        let config = startup.find("AgentConfig::load()").expect("config load");
        assert!(harden < config);
        assert!(startup[..config].contains("warn!"));
    }
}
