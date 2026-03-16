//! File quarantine: move files to a secure quarantine vault.

use std::path::Path;

#[cfg(target_os = "windows")]
use std::fs;
#[cfg(target_os = "windows")]
use std::io::Read as _;
#[cfg(target_os = "windows")]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "windows")]
use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use sha2::{Digest, Sha256};

/// Result of a successful quarantine operation.
#[derive(Debug, Clone)]
pub struct QuarantineResult {
    pub quarantine_path: String,
    pub sha256: String,
    pub file_size: u64,
}

/// Quarantine a file by moving it to the quarantine directory.
///
/// Computes SHA256 before moving to ensure the hash is available for server
/// correlation and IOC matching (fixes cross-platform quarantine inconsistency).
pub fn quarantine_file(
    path: &str,
    quarantine_dir: &str,
) -> Result<QuarantineResult, super::process::ResponseError> {
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

        let canonical_effective =
            fs::canonicalize(&effective_source).unwrap_or(effective_source.clone());
        if is_protected_windows_path(&canonical_effective) {
            return Err(super::process::ResponseError::OperationFailed(format!(
                "refusing to quarantine protected path {}",
                canonical_effective.display()
            )));
        }

        // Compute SHA256 and file size BEFORE moving the file.
        let (sha256_hex, file_size) = compute_file_sha256(&effective_source)?;

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
            sha256: sha256_hex.clone(),
            file_size,
        };
        write_quarantine_metadata(&target, &metadata)?;

        Ok(QuarantineResult {
            quarantine_path: target.to_string_lossy().to_string(),
            sha256: sha256_hex,
            file_size,
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (path, quarantine_dir);
        tracing::warn!(path, "quarantine_file is a stub on non-Windows");
        let file_name = Path::new(path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        Ok(QuarantineResult {
            quarantine_path: format!("{quarantine_dir}/{file_name}"),
            sha256: String::new(),
            file_size: 0,
        })
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

    PROTECTED_PREFIXES
        .iter()
        .any(|prefix| normalized == *prefix || normalized.starts_with(&format!("{prefix}\\")))
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
    sha256: String,
    file_size: u64,
}

/// Compute SHA256 of a file. Returns (hex_string, file_size).
#[cfg(target_os = "windows")]
fn compute_file_sha256(path: &Path) -> Result<(String, u64), super::process::ResponseError> {
    let mut file = fs::File::open(path).map_err(|err| {
        super::process::ResponseError::OperationFailed(format!(
            "failed opening {} for SHA256: {err}",
            path.display()
        ))
    })?;
    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(|err| {
            super::process::ResponseError::OperationFailed(format!(
                "failed reading {} for SHA256: {err}",
                path.display()
            ))
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let digest = hasher.finalize();
    let hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok((hex, file_size))
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
