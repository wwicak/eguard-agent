use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use crate::errors::{ResponseError, ResponseResult};
use crate::ProtectedList;

const DEFAULT_QUARANTINE_DIR: &str = "/var/lib/eguard-agent/quarantine";

#[derive(Debug, Clone)]
pub struct QuarantineReport {
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub sha256: String,
    pub file_size: u64,
    pub original_mode: u32,
    pub owner_uid: u32,
    pub owner_gid: u32,
}

#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub restored_path: PathBuf,
    pub source_quarantine_path: PathBuf,
}

pub fn quarantine_file(
    path: &Path,
    sha256: &str,
    protected: &ProtectedList,
) -> ResponseResult<QuarantineReport> {
    let quarantine_dir = resolve_default_quarantine_dir();
    quarantine_file_with_dir(path, sha256, protected, &quarantine_dir)
}

fn resolve_default_quarantine_dir() -> PathBuf {
    #[cfg(test)]
    if let Some(dir) = std::env::var_os("EGUARD_TEST_QUARANTINE_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }

    PathBuf::from(DEFAULT_QUARANTINE_DIR)
}

pub fn quarantine_file_with_dir(
    path: &Path,
    sha256: &str,
    protected: &ProtectedList,
    quarantine_dir: &Path,
) -> ResponseResult<QuarantineReport> {
    if protected.is_protected_path(path) {
        return Err(ResponseError::ProtectedPath(path.to_path_buf()));
    }
    if sha256.trim().is_empty() {
        return Err(ResponseError::InvalidInput(
            "sha256 cannot be empty".to_string(),
        ));
    }

    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(ResponseError::InvalidInput(format!(
            "{} is not a regular file",
            path.display()
        )));
    }

    fs::create_dir_all(quarantine_dir)?;
    let quarantine_path = quarantine_dir.join(sha256);

    fs::copy(path, &quarantine_path)?;

    let mut original = OpenOptions::new().write(true).open(path)?;
    apply_restrictive_permissions(path)?;
    overwrite_file_prefix_with_zeros_file(&mut original, metadata.len())?;
    fs::remove_file(path)?;

    let (original_mode, owner_uid, owner_gid) = metadata_identity(&metadata);

    Ok(QuarantineReport {
        original_path: path.to_path_buf(),
        quarantine_path,
        sha256: sha256.to_string(),
        file_size: metadata.len(),
        original_mode,
        owner_uid,
        owner_gid,
    })
}

pub fn restore_quarantined(
    quarantine_path: &Path,
    restore_to: &Path,
    original_mode: u32,
) -> ResponseResult<RestoreReport> {
    if quarantine_path == restore_to {
        return Err(ResponseError::InvalidInput(
            "quarantine and restore paths must differ".to_string(),
        ));
    }

    if let Some(parent) = restore_to.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(quarantine_path, restore_to)?;
    restore_permissions(restore_to, original_mode)?;

    Ok(RestoreReport {
        restored_path: restore_to.to_path_buf(),
        source_quarantine_path: quarantine_path.to_path_buf(),
    })
}

#[cfg(test)]
fn overwrite_file_prefix_with_zeros(path: &Path, file_size: u64) -> ResponseResult<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    overwrite_file_prefix_with_zeros_file(&mut file, file_size)
}

fn overwrite_file_prefix_with_zeros_file(
    file: &mut std::fs::File,
    file_size: u64,
) -> ResponseResult<()> {
    let overwrite_len = file_size.min(4096) as usize;
    if overwrite_len == 0 {
        return Ok(());
    }

    let zeros = vec![0u8; overwrite_len];
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&zeros)?;
    file.flush()?;
    Ok(())
}

#[cfg(unix)]
fn apply_restrictive_permissions(path: &Path) -> ResponseResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o000))?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_restrictive_permissions(path: &Path) -> ResponseResult<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
fn metadata_identity(metadata: &fs::Metadata) -> (u32, u32, u32) {
    (metadata.mode(), metadata.uid(), metadata.gid())
}

#[cfg(not(unix))]
fn metadata_identity(_metadata: &fs::Metadata) -> (u32, u32, u32) {
    (0, 0, 0)
}

#[cfg(unix)]
fn restore_permissions(path: &Path, original_mode: u32) -> ResponseResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(original_mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn restore_permissions(path: &Path, _original_mode: u32) -> ResponseResult<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_readonly(false);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(test)]
mod tests;
