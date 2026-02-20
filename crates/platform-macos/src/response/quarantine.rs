//! File quarantine: move files to a secure quarantine vault and set
//! com.apple.quarantine extended attribute.

use std::path::Path;

#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::time::{SystemTime, UNIX_EPOCH};

/// Default quarantine directory on macOS.
#[cfg(target_os = "macos")]
const DEFAULT_QUARANTINE_DIR: &str = "/Library/Application Support/eGuard/quarantine";

/// Quarantine a file by moving it to the quarantine directory and setting
/// the com.apple.quarantine xattr.
///
/// Returns the quarantined file path.
pub fn quarantine_file(path: &str, quarantine_dir: &str) -> Result<String, super::ResponseError> {
    #[cfg(target_os = "macos")]
    {
        let source = Path::new(path);
        if !source.exists() {
            return Err(super::ResponseError::OperationFailed(format!(
                "source path does not exist: {}",
                source.display()
            )));
        }

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

        // Set com.apple.quarantine xattr to prevent execution.
        let _ = Command::new("xattr")
            .args([
                "-w",
                "com.apple.quarantine",
                "0083;eGuard;eGuard Agent;quarantined",
                &target.to_string_lossy(),
            ])
            .output();

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

        // Remove quarantine xattr after restore.
        let _ = Command::new("xattr")
            .args(["-d", "com.apple.quarantine", &target.to_string_lossy()])
            .output();

        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (quarantine_path, original_path);
        tracing::warn!("restore_file is a stub on non-macOS");
        Ok(())
    }
}
