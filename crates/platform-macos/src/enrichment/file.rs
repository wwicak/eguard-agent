//! File metadata and hashing for enrichment.

use std::path::Path;

/// Compute SHA-256 hex digest of a file.
pub fn compute_sha256(path: &str) -> std::io::Result<String> {
    crypto_accel::sha256_file_hex(Path::new(path)).map_err(std::io::Error::other)
}

/// Retrieve file metadata (size, timestamps) for enrichment.
pub fn file_metadata(path: &str) -> Option<FileMetadata> {
    let meta = std::fs::metadata(path).ok()?;
    Some(FileMetadata {
        size_bytes: meta.len(),
        readonly: meta.permissions().readonly(),
    })
}

/// Basic file metadata.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub size_bytes: u64,
    pub readonly: bool,
}
