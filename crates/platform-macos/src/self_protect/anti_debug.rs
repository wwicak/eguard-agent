//! Anti-debugging measures for macOS.
//!
//! Uses ptrace(PT_DENY_ATTACH) to prevent debugger attachment and
//! checks P_TRACED flag to detect existing debuggers.

/// Deny debugger attachment via ptrace(PT_DENY_ATTACH).
pub fn deny_attach() -> Result<(), super::SelfProtectError> {
    #[cfg(target_os = "macos")]
    {
        deny_attach_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

/// Check whether a debugger is attached to the current process.
pub fn detect_debugger() -> bool {
    #[cfg(target_os = "macos")]
    {
        detect_debugger_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
const PT_DENY_ATTACH: libc::c_int = 31;

#[cfg(target_os = "macos")]
fn deny_attach_macos() -> Result<(), super::SelfProtectError> {
    let ret = unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut::<libc::c_char>(), 0) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        // ENOTSUP (45) is returned if already set, which is fine.
        if errno.raw_os_error() != Some(45) {
            return Err(super::SelfProtectError::AntiDebugFailed(format!(
                "ptrace(PT_DENY_ATTACH) failed: {errno}"
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn detect_debugger_macos() -> bool {
    // Check P_TRACED flag via sysctl.
    let mut mib: [libc::c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        unsafe { libc::getpid() },
    ];
    let mut info = std::mem::MaybeUninit::<libc::kinfo_proc>::zeroed();
    let mut size = std::mem::size_of::<libc::kinfo_proc>();

    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            info.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };

    if ret != 0 {
        return false;
    }

    let info = unsafe { info.assume_init() };
    const P_TRACED: i32 = 0x00000800;
    (info.kp_proc.p_flag & P_TRACED) != 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn detect_debugger_returns_false_on_non_macos() {
        #[cfg(not(target_os = "macos"))]
        {
            assert!(!super::detect_debugger());
        }
    }

    #[test]
    fn deny_attach_succeeds_on_non_macos() {
        #[cfg(not(target_os = "macos"))]
        {
            super::deny_attach().expect("deny_attach stub succeeds");
        }
    }
}
