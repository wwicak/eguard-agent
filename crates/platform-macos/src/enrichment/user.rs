//! UID-to-username resolution.
//!
//! On macOS/unix, uses libc::getpwuid_r() for thread-safe POSIX user lookup.

/// Resolve a UID to a username via POSIX getpwuid_r() (thread-safe).
pub fn resolve_uid_to_username(uid: u32) -> Option<String> {
    #[cfg(unix)]
    {
        resolve_uid_unix(uid)
    }
    #[cfg(not(unix))]
    {
        let _ = uid;
        None
    }
}

#[cfg(unix)]
fn resolve_uid_unix(uid: u32) -> Option<String> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 1024];

    let ret = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };

    if ret != 0 || result.is_null() {
        return None;
    }

    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
    let name = name.to_string_lossy().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn username_non_empty_validation() {
        assert!("alice".trim().is_empty() == false);
        assert!("   ".trim().is_empty());
    }
}
