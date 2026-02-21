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

        // Use symlink_metadata to detect reparse points/symlinks without following them
        let sym_meta = fs::symlink_metadata(source).map_err(|err| {
            super::process::ResponseError::OperationFailed(format!(
                "source path does not exist or is inaccessible: {}: {err}",
                source.display()
            ))
        })?;

        // If source is a symlink/reparse point, resolve and operate on the real target
        let effective_source = if sym_meta.file_type().is_symlink() {
            fs::canonicalize(source).map_err(|err| {
                super::process::ResponseError::OperationFailed(format!(
                    "failed resolving symlink {}: {err}",
                    source.display()
                ))
            })?
        } else {
            source.to_path_buf()
        };

        let canonical_effective = fs::canonicalize(&effective_source).unwrap_or(effective_source.clone());
        if is_protected_windows_path(&canonical_effective) {
            return Err(super::process::ResponseError::OperationFailed(format!(
                "refusing to quarantine protected path {}",
                canonical_effective.display()
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

        let file_name = effective_source
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .ok_or_else(|| {
                super::process::ResponseError::OperationFailed(format!(
                    "invalid source path {}",
                    effective_source.display()
                ))
            })?;

        // Collision-safe target: append counter suffix if name already exists
        let mut target = bucket.join(&file_name);
        if target.exists() {
            for i in 1u32..=999 {
                let suffixed = format!("{file_name}.{i}");
                let candidate = bucket.join(&suffixed);
                if !candidate.exists() {
                    target = candidate;
                    break;
                }
            }
        }

        fs::rename(&effective_source, &target).map_err(|err| {
            super::process::ResponseError::OperationFailed(format!(
                "failed moving {} to {}: {err}",
                effective_source.display(),
                target.display()
            ))
        })?;

        let metadata = QuarantineMetadata {
            original_path: effective_source.to_string_lossy().to_string(),
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

#[cfg(any(test, target_os = "windows"))]
fn normalize_windows_path_text(raw: &str) -> String {
    raw.replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

#[cfg(any(test, target_os = "windows"))]
fn is_protected_windows_path_text(raw: &str) -> bool {
    let normalized = normalize_windows_path_text(raw);
    const PROTECTED_PREFIXES: [&str; 3] = [
        r"c:\windows\system32",
        r"c:\windows\syswow64",
        r"c:\programdata\eguard",
    ];

    PROTECTED_PREFIXES.iter().any(|prefix| {
        normalized == *prefix || normalized.starts_with(&format!("{prefix}\\"))
    })
}

#[cfg(target_os = "windows")]
fn is_protected_windows_path(path: &Path) -> bool {
    is_protected_windows_path_text(path.to_string_lossy().as_ref())
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

#[cfg(test)]
mod tests {
    use super::is_protected_windows_path_text;

    #[test]
    fn protected_windows_prefix_matching_is_boundary_safe() {
        assert!(is_protected_windows_path_text(
            r"C:\Windows\System32\kernel32.dll"
        ));
        assert!(is_protected_windows_path_text(
            r"C:\ProgramData\eGuard\bootstrap.conf"
        ));
        assert!(!is_protected_windows_path_text(
            r"C:\Windows\System32evil\payload.exe"
        ));
        assert!(!is_protected_windows_path_text(
            r"C:\Users\Public\sample.exe"
        ));
    }
}
