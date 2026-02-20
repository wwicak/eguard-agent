//! File quarantine: move files to a secure quarantine vault.

use std::path::Path;

/// Quarantine a file by moving it to the quarantine directory.
///
/// The original file is replaced with a zone-identifier marker.
pub fn quarantine_file(path: &str, quarantine_dir: &str) -> Result<String, super::process::ResponseError> {
    #[cfg(target_os = "windows")]
    {
        // TODO: MoveFileExW with MOVEFILE_REPLACE_EXISTING to quarantine_dir
        // TODO: set NTFS ADS zone identifier on original path
        let _ = (path, quarantine_dir);
        Ok(String::new())
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
pub fn restore_file(quarantine_path: &str, original_path: &str) -> Result<(), super::process::ResponseError> {
    #[cfg(target_os = "windows")]
    {
        // TODO: MoveFileExW back to original_path
        let _ = (quarantine_path, original_path);
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (quarantine_path, original_path);
        tracing::warn!("restore_file is a stub on non-Windows");
        Ok(())
    }
}
