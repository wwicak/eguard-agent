//! File quarantine: move files to a secure quarantine vault and set
//! com.apple.quarantine extended attribute.

use std::path::Path;

#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "macos")]
use std::time::{SystemTime, UNIX_EPOCH};

/// Quarantine a file by moving it to the quarantine directory and setting
/// the com.apple.quarantine xattr.
///
/// Returns the quarantined file path.
pub fn quarantine_file(path: &str, quarantine_dir: &str) -> Result<String, super::ResponseError> {
    #[cfg(target_os = "macos")]
    {
        let source = Path::new(path);

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        let bucket = Path::new(quarantine_dir).join(stamp.to_string());
        fs::create_dir_all(&bucket).map_err(|err| {
            super::ResponseError::OperationFailed(format!(
                "failed creating quarantine dir {}: {err}",
                bucket.display()
            ))
        })?;

        let file_name = source
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .ok_or_else(|| {
                super::ResponseError::OperationFailed(format!(
                    "invalid source path {}",
                    source.display()
                ))
            })?;

        let target = bucket.join(&file_name);
        fs::rename(source, &target).map_err(|err| {
            super::ResponseError::OperationFailed(format!(
                "failed moving {} to {}: {err}",
                source.display(),
                target.display()
            ))
        })?;

        set_quarantine_xattr(&target)?;

        Ok(target.to_string_lossy().to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, quarantine_dir);
        tracing::warn!(path, "quarantine_file is a stub on non-macOS");
        let file_name = Path::new(path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        Ok(format!("{quarantine_dir}/{file_name}"))
    }
}

#[cfg(target_os = "macos")]
fn set_quarantine_xattr(path: &Path) -> Result<(), super::ResponseError> {
    const XATTR_NAME: &str = "com.apple.quarantine";
    const XATTR_VALUE: &str = "0083;eGuard;eGuard Agent;quarantined";

    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        super::ResponseError::OperationFailed(format!("invalid quarantine path {}", path.display()))
    })?;
    let c_name = CString::new(XATTR_NAME).expect("xattr name is valid");

    let ret = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            XATTR_VALUE.as_ptr() as *const libc::c_void,
            XATTR_VALUE.len(),
            0,
            0,
        )
    };
    if ret == 0 {
        return Ok(());
    }

    Err(super::ResponseError::OperationFailed(format!(
        "failed setting quarantine xattr on {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    )))
}

#[cfg(target_os = "macos")]
fn clear_quarantine_xattr(path: &Path) -> Result<(), super::ResponseError> {
    const XATTR_NAME: &str = "com.apple.quarantine";

    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        super::ResponseError::OperationFailed(format!("invalid restore path {}", path.display()))
    })?;
    let c_name = CString::new(XATTR_NAME).expect("xattr name is valid");

    let ret = unsafe { libc::removexattr(c_path.as_ptr(), c_name.as_ptr(), 0) };
    if ret == 0 {
        return Ok(());
    }

    let io_err = std::io::Error::last_os_error();
    if io_err.raw_os_error() == Some(libc::ENOATTR) {
        return Ok(());
    }

    Err(super::ResponseError::OperationFailed(format!(
        "failed clearing quarantine xattr on {}: {}",
        path.display(),
        io_err
    )))
}

/// Restore a file from quarantine to its original location.
pub fn restore_file(
    quarantine_path: &str,
    original_path: &str,
) -> Result<(), super::ResponseError> {
    #[cfg(target_os = "macos")]
    {
        let source = Path::new(quarantine_path);
        let target = Path::new(original_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                super::ResponseError::OperationFailed(format!(
                    "failed creating restore parent dir {}: {err}",
                    parent.display()
                ))
            })?;
        }

        fs::rename(source, target).map_err(|err| {
            super::ResponseError::OperationFailed(format!(
                "failed restoring {} to {}: {err}",
                source.display(),
                target.display()
            ))
        })?;

        clear_quarantine_xattr(target)?;

        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (quarantine_path, original_path);
        tracing::warn!("restore_file is a stub on non-macOS");
        Ok(())
    }
}
