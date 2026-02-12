use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::errors::{ResponseError, ResponseResult};
use crate::ProtectedList;

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

    let quarantine_dir = Path::new("/var/lib/eguard-agent/quarantine");
    fs::create_dir_all(quarantine_dir)?;
    let quarantine_path = quarantine_dir.join(sha256);

    fs::copy(path, &quarantine_path)?;

    fs::set_permissions(path, fs::Permissions::from_mode(0o000))?;

    overwrite_file_prefix_with_zeros(path, metadata.len())?;
    fs::remove_file(path)?;

    Ok(QuarantineReport {
        original_path: path.to_path_buf(),
        quarantine_path,
        sha256: sha256.to_string(),
        file_size: metadata.len(),
        original_mode: metadata.mode(),
        owner_uid: metadata.uid(),
        owner_gid: metadata.gid(),
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
    fs::set_permissions(restore_to, fs::Permissions::from_mode(original_mode))?;

    Ok(RestoreReport {
        restored_path: restore_to.to_path_buf(),
        source_quarantine_path: quarantine_path.to_path_buf(),
    })
}

fn overwrite_file_prefix_with_zeros(path: &Path, file_size: u64) -> ResponseResult<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_quarantined_file_writes_destination() {
        let base = std::env::temp_dir().join(format!(
            "eguard-restore-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        fs::create_dir_all(&base).expect("create base");

        let src = base.join("quarantine.bin");
        let dst = base.join("restored.bin");
        fs::write(&src, b"payload").expect("write src");

        let report = restore_quarantined(&src, &dst, 0o600).expect("restore file");
        assert_eq!(report.restored_path, dst);
        assert_eq!(
            fs::read(&report.restored_path).expect("read restored"),
            b"payload"
        );

        let _ = fs::remove_file(src);
        let _ = fs::remove_file(report.restored_path);
        let _ = fs::remove_dir(base);
    }
}
