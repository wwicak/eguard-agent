//! File quarantine: move files to a secure quarantine vault.

use std::path::Path;

#[cfg(target_os = "windows")]
use std::fs;
#[cfg(target_os = "windows")]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "windows")]
use serde::{Deserialize, Serialize};

/// Quarantine a file by moving it to the quarantine directory.
///
/// Returns the quarantined file path.
pub fn quarantine_file(
    path: &str,
    quarantine_dir: &str,
) -> Result<String, super::process::ResponseError> {
    #[cfg(target_os = "windows")]
    {
        let source = Path::new(path);
        if !source.exists() {
            return Err(super::process::ResponseError::OperationFailed(format!(
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
            super::process::ResponseError::OperationFailed(format!(
                "failed creating quarantine dir {}: {err}",
                bucket.display()
            ))
        })?;

        let file_name = source
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .ok_or_else(|| {
                super::process::ResponseError::OperationFailed(format!(
                    "invalid source path {}",
                    source.display()
                ))
            })?;

        let target = bucket.join(file_name);
        fs::rename(source, &target).map_err(|err| {
            super::process::ResponseError::OperationFailed(format!(
                "failed moving {} to {}: {err}",
                source.display(),
                target.display()
            ))
        })?;

        let metadata = QuarantineMetadata {
            original_path: source.to_string_lossy().to_string(),
            quarantined_at_unix: stamp,
        };
        write_quarantine_metadata(&target, &metadata)?;

        Ok(target.to_string_lossy().to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (path, quarantine_dir);
        tracing::warn!(path, "quarantine_file is a stub on non-Windows");
        // Return the would-be quarantine path
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
) -> Result<(), super::process::ResponseError> {
    #[cfg(target_os = "windows")]
    {
        let source = Path::new(quarantine_path);
        let target = Path::new(original_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                super::process::ResponseError::OperationFailed(format!(
                    "failed creating restore parent dir {}: {err}",
                    parent.display()
                ))
            })?;
        }

        fs::rename(source, target).map_err(|err| {
            super::process::ResponseError::OperationFailed(format!(
                "failed restoring {} to {}: {err}",
                source.display(),
                target.display()
            ))
        })?;

        let _ = fs::remove_file(quarantine_metadata_path(source));
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (quarantine_path, original_path);
        tracing::warn!("restore_file is a stub on non-Windows");
        Ok(())
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuarantineMetadata {
    original_path: String,
    quarantined_at_unix: u64,
}

#[cfg(target_os = "windows")]
fn quarantine_metadata_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|file| file.to_string_lossy().to_string())
        .unwrap_or_else(|| "quarantined-file".to_string());
    name.push_str(".eguard-meta.json");
    path.with_file_name(name)
}

#[cfg(target_os = "windows")]
fn write_quarantine_metadata(
    quarantined_path: &Path,
    metadata: &QuarantineMetadata,
) -> Result<(), super::process::ResponseError> {
    let metadata_path = quarantine_metadata_path(quarantined_path);
    let content = serde_json::to_string_pretty(metadata).map_err(|err| {
        super::process::ResponseError::OperationFailed(format!(
            "failed serializing quarantine metadata for {}: {err}",
            quarantined_path.display()
        ))
    })?;

    fs::write(&metadata_path, content).map_err(|err| {
        super::process::ResponseError::OperationFailed(format!(
            "failed writing quarantine metadata {}: {err}",
            metadata_path.display()
        ))
    })
}
