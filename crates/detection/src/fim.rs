//! File Integrity Monitoring (FIM)
//!
//! Maintains SHA-256 checksums of critical system files and detects
//! unauthorized modifications. Required for PCI-DSS 11.5 and HIPAA
//! 164.312(c)(2) compliance.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Default monitored paths. Includes critical authentication, authorization,
/// network, and boot files per PCI-DSS 11.5 requirements.
/// Paths ending with `/` or `\` are treated as directories; paths containing
/// `*` are treated as glob prefixes.
#[cfg(target_os = "linux")]
pub const DEFAULT_FIM_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ld.so.conf",
    "/etc/pam.d/",
    "/usr/bin/sudo",
    "/usr/bin/ssh",
    "/usr/bin/passwd",
    "/usr/sbin/sshd",
    "/boot/vmlinuz*",
    "/boot/initrd*",
];

#[cfg(target_os = "windows")]
pub const DEFAULT_FIM_PATHS: &[&str] = &[
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SECURITY",
    "C:\\Windows\\System32\\config\\SYSTEM",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\System32\\GroupPolicy\\",
    "C:\\Windows\\System32\\Tasks\\",
    "C:\\ProgramData\\ssh\\sshd_config",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\system.ini",
];

#[cfg(target_os = "macos")]
pub const DEFAULT_FIM_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
    "/etc/pam.d/",
    "/Library/Preferences/com.apple.loginwindow.plist",
    "/Library/LaunchDaemons/",
    "/Library/LaunchAgents/",
    "/System/Library/LaunchDaemons/",
    "/usr/bin/sudo",
    "/usr/bin/ssh",
];

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub const DEFAULT_FIM_PATHS: &[&str] = &["/etc/passwd", "/etc/shadow"];

/// Default scan interval in seconds.
pub const DEFAULT_FIM_SCAN_INTERVAL_SECS: u64 = 300;

/// Buffer size for chunked SHA-256 computation (8 KB).
const HASH_BUF_SIZE: usize = 8192;

// ── Data Structures ──────────────────────────────────────────────────

/// Type of change detected between baseline and current state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FimChangeType {
    Modified,
    Created,
    Deleted,
    PermissionChanged,
    OwnerChanged,
}

impl std::fmt::Display for FimChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Modified => write!(f, "modified"),
            Self::Created => write!(f, "created"),
            Self::Deleted => write!(f, "deleted"),
            Self::PermissionChanged => write!(f, "permission_changed"),
            Self::OwnerChanged => write!(f, "owner_changed"),
        }
    }
}

/// Metadata snapshot of a single monitored file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimEntry {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub owner_uid: u32,
    pub baseline_time: i64,
}

/// A detected change between baseline and current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimChange {
    pub path: PathBuf,
    pub change_type: FimChangeType,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
    pub old_size: Option<u64>,
    pub new_size: Option<u64>,
    pub old_mtime: Option<i64>,
    pub new_mtime: Option<i64>,
}

impl std::fmt::Display for FimChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FIM {}: {}", self.change_type, self.path.display())
    }
}

/// The FIM baseline: a collection of file entry snapshots keyed by path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimBaseline {
    entries: HashMap<PathBuf, FimEntry>,
}

impl FimBaseline {
    /// Create an empty baseline.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Number of entries in the baseline.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the baseline has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Scan the given paths and return `FimEntry` snapshots. Paths ending with
    /// `/` are treated as directories (all regular files within are scanned).
    /// Paths containing `*` are treated as glob prefixes (matched against the
    /// parent directory). Inaccessible files are silently skipped.
    pub fn scan_paths(paths: &[PathBuf]) -> Vec<FimEntry> {
        let now = current_unix_timestamp();
        let mut entries = Vec::new();

        for path in paths {
            let path_str = path.to_string_lossy();

            if path_str.ends_with('/') || path_str.ends_with('\\') {
                // Directory: scan all regular files within.
                if let Ok(dir_entries) = fs::read_dir(path) {
                    for dir_entry in dir_entries.flatten() {
                        let entry_path = dir_entry.path();
                        if entry_path.is_file() {
                            if let Some(entry) = scan_single_file(&entry_path, now) {
                                entries.push(entry);
                            }
                        }
                    }
                }
            } else if path_str.contains('*') {
                // Glob pattern: match files in the parent directory.
                if let Some(parent) = path.parent() {
                    let prefix = path_str.split('*').next().unwrap_or("");
                    if let Ok(dir_entries) = fs::read_dir(parent) {
                        for dir_entry in dir_entries.flatten() {
                            let entry_path = dir_entry.path();
                            if entry_path.is_file()
                                && entry_path.to_string_lossy().starts_with(prefix)
                            {
                                if let Some(entry) = scan_single_file(&entry_path, now) {
                                    entries.push(entry);
                                }
                            }
                        }
                    }
                }
            } else {
                // Regular file path.
                if let Some(entry) = scan_single_file(path, now) {
                    entries.push(entry);
                }
            }
        }

        entries
    }

    /// Detect changes between this baseline and the current scan results.
    /// Returns a list of detected changes.
    pub fn detect_changes(&self, current: &[FimEntry]) -> Vec<FimChange> {
        let mut changes = Vec::new();
        let current_map: HashMap<&PathBuf, &FimEntry> =
            current.iter().map(|e| (&e.path, e)).collect();

        // Check for modifications and deletions.
        for (path, baseline_entry) in &self.entries {
            match current_map.get(path) {
                Some(current_entry) => {
                    // Check content modification (hash change).
                    if baseline_entry.sha256 != current_entry.sha256 {
                        changes.push(FimChange {
                            path: path.clone(),
                            change_type: FimChangeType::Modified,
                            old_hash: Some(baseline_entry.sha256.clone()),
                            new_hash: Some(current_entry.sha256.clone()),
                            old_size: Some(baseline_entry.size),
                            new_size: Some(current_entry.size),
                            old_mtime: Some(baseline_entry.mtime),
                            new_mtime: Some(current_entry.mtime),
                        });
                    } else if baseline_entry.mode != current_entry.mode {
                        // Permissions changed but content is the same.
                        changes.push(FimChange {
                            path: path.clone(),
                            change_type: FimChangeType::PermissionChanged,
                            old_hash: Some(baseline_entry.sha256.clone()),
                            new_hash: Some(current_entry.sha256.clone()),
                            old_size: Some(baseline_entry.size),
                            new_size: Some(current_entry.size),
                            old_mtime: Some(baseline_entry.mtime),
                            new_mtime: Some(current_entry.mtime),
                        });
                    } else if baseline_entry.owner_uid != current_entry.owner_uid {
                        // Owner changed but content and permissions are the same.
                        changes.push(FimChange {
                            path: path.clone(),
                            change_type: FimChangeType::OwnerChanged,
                            old_hash: Some(baseline_entry.sha256.clone()),
                            new_hash: Some(current_entry.sha256.clone()),
                            old_size: Some(baseline_entry.size),
                            new_size: Some(current_entry.size),
                            old_mtime: Some(baseline_entry.mtime),
                            new_mtime: Some(current_entry.mtime),
                        });
                    }
                }
                None => {
                    // File was in baseline but not in current scan -> deleted.
                    changes.push(FimChange {
                        path: path.clone(),
                        change_type: FimChangeType::Deleted,
                        old_hash: Some(baseline_entry.sha256.clone()),
                        new_hash: None,
                        old_size: Some(baseline_entry.size),
                        new_size: None,
                        old_mtime: Some(baseline_entry.mtime),
                        new_mtime: None,
                    });
                }
            }
        }

        // Check for newly created files (in current but not in baseline).
        for current_entry in current {
            if !self.entries.contains_key(&current_entry.path) {
                changes.push(FimChange {
                    path: current_entry.path.clone(),
                    change_type: FimChangeType::Created,
                    old_hash: None,
                    new_hash: Some(current_entry.sha256.clone()),
                    old_size: None,
                    new_size: Some(current_entry.size),
                    old_mtime: None,
                    new_mtime: Some(current_entry.mtime),
                });
            }
        }

        changes
    }

    /// Update the baseline with the given entries, replacing any existing entry
    /// for the same path.
    pub fn update(&mut self, entries: &[FimEntry]) {
        for entry in entries {
            self.entries.insert(entry.path.clone(), entry.clone());
        }
    }

    /// Remove a path from the baseline (e.g., after acknowledging a deletion).
    pub fn remove(&mut self, path: &Path) {
        self.entries.remove(path);
    }

    /// Load a baseline from a JSON file on disk.
    pub fn load(path: &Path) -> Result<Self, FimError> {
        let content = fs::read_to_string(path).map_err(|e| FimError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let baseline: FimBaseline =
            serde_json::from_str(&content).map_err(|e| FimError::Deserialize {
                path: path.to_path_buf(),
                source: e,
            })?;
        Ok(baseline)
    }

    /// Save the baseline to a JSON file on disk.
    pub fn save(&self, path: &Path) -> Result<(), FimError> {
        let content =
            serde_json::to_string_pretty(self).map_err(|e| FimError::Serialize { source: e })?;
        // Write atomically: write to a temp file then rename.
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, content.as_bytes()).map_err(|e| FimError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;
        fs::rename(&tmp_path, path).map_err(|e| FimError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }
}

impl Default for FimBaseline {
    fn default() -> Self {
        Self::new()
    }
}

// ── Error Type ───────────────────────────────────────────────────────

/// Errors that can occur during FIM operations.
#[derive(Debug)]
pub enum FimError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Deserialize {
        path: PathBuf,
        source: serde_json::Error,
    },
    Serialize {
        source: serde_json::Error,
    },
}

impl std::fmt::Display for FimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "FIM I/O error on {}: {}", path.display(), source)
            }
            Self::Deserialize { path, source } => {
                write!(
                    f,
                    "FIM deserialization error on {}: {}",
                    path.display(),
                    source
                )
            }
            Self::Serialize { source } => {
                write!(f, "FIM serialization error: {}", source)
            }
        }
    }
}

impl std::error::Error for FimError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Deserialize { source, .. } => Some(source),
            Self::Serialize { source } => Some(source),
        }
    }
}

// ── Internal Helpers ─────────────────────────────────────────────────

/// Compute SHA-256 hash of a file by reading in 8 KB chunks.
fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_BUF_SIZE];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(encode_hex(&hasher.finalize()))
}

/// Encode bytes as lowercase hex string.
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Read metadata for a single file and build a `FimEntry`.
fn scan_single_file(path: &Path, now: i64) -> Option<FimEntry> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }

    let sha256 = sha256_file(path).ok()?;
    let size = metadata.len();
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Platform-specific metadata extraction.
    #[cfg(unix)]
    let (mode, owner_uid) = {
        use std::os::unix::fs::MetadataExt;
        (metadata.mode(), metadata.uid())
    };
    #[cfg(not(unix))]
    let (mode, owner_uid) = (0u32, 0u32);

    Some(FimEntry {
        path: path.to_path_buf(),
        sha256,
        size,
        mode,
        mtime,
        owner_uid,
        baseline_time: now,
    })
}

/// Current UNIX timestamp in seconds.
fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Expand the default path strings into `PathBuf` values.
pub fn default_fim_paths() -> Vec<PathBuf> {
    DEFAULT_FIM_PATHS.iter().map(PathBuf::from).collect()
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    /// Helper: create a temp directory with known files for testing.
    fn setup_test_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("file_a.txt"), b"hello world").unwrap();
        fs::write(dir.path().join("file_b.txt"), b"secret data").unwrap();
        dir
    }

    #[test]
    fn scan_and_baseline_round_trip() {
        let dir = setup_test_dir();
        let paths = vec![dir.path().join("file_a.txt"), dir.path().join("file_b.txt")];

        let scanned = FimBaseline::scan_paths(&paths);
        assert_eq!(scanned.len(), 2);

        let mut baseline = FimBaseline::new();
        baseline.update(&scanned);
        assert_eq!(baseline.len(), 2);

        // No changes when re-scanning the same files.
        let current = FimBaseline::scan_paths(&paths);
        let changes = baseline.detect_changes(&current);
        assert!(changes.is_empty(), "expected no changes, got {:?}", changes);
    }

    #[test]
    fn detect_file_modification() {
        let dir = setup_test_dir();
        let paths = vec![dir.path().join("file_a.txt")];

        let scanned = FimBaseline::scan_paths(&paths);
        let mut baseline = FimBaseline::new();
        baseline.update(&scanned);

        // Modify the file.
        fs::write(dir.path().join("file_a.txt"), b"modified content").unwrap();

        let current = FimBaseline::scan_paths(&paths);
        let changes = baseline.detect_changes(&current);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, FimChangeType::Modified);
        assert_eq!(changes[0].path, dir.path().join("file_a.txt"));
        assert!(changes[0].old_hash.is_some());
        assert!(changes[0].new_hash.is_some());
        assert_ne!(changes[0].old_hash, changes[0].new_hash);
    }

    #[test]
    fn detect_file_deletion() {
        let dir = setup_test_dir();
        let path_a = dir.path().join("file_a.txt");
        let paths = vec![path_a.clone()];

        let scanned = FimBaseline::scan_paths(&paths);
        let mut baseline = FimBaseline::new();
        baseline.update(&scanned);

        // Delete the file.
        fs::remove_file(&path_a).unwrap();

        let current = FimBaseline::scan_paths(&paths);
        let changes = baseline.detect_changes(&current);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, FimChangeType::Deleted);
        assert_eq!(changes[0].path, path_a);
        assert!(changes[0].new_hash.is_none());
    }

    #[test]
    fn detect_new_file_creation() {
        let dir = setup_test_dir();
        let path_a = dir.path().join("file_a.txt");
        let path_new = dir.path().join("file_new.txt");

        // Baseline only knows about file_a.
        let initial_paths = vec![path_a.clone()];
        let scanned = FimBaseline::scan_paths(&initial_paths);
        let mut baseline = FimBaseline::new();
        baseline.update(&scanned);

        // Create a new file and scan both.
        fs::write(&path_new, b"new file content").unwrap();

        let current_paths = vec![path_a, path_new.clone()];
        let current = FimBaseline::scan_paths(&current_paths);
        let changes = baseline.detect_changes(&current);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, FimChangeType::Created);
        assert_eq!(changes[0].path, path_new);
        assert!(changes[0].old_hash.is_none());
        assert!(changes[0].new_hash.is_some());
    }

    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore = "chmod is unsupported under miri")]
    fn detect_permission_change() {
        use std::os::unix::fs::PermissionsExt;

        let dir = setup_test_dir();
        let path_a = dir.path().join("file_a.txt");
        let paths = vec![path_a.clone()];

        let scanned = FimBaseline::scan_paths(&paths);
        let mut baseline = FimBaseline::new();
        baseline.update(&scanned);

        // Change permissions without modifying content.
        let mut perms = fs::metadata(&path_a).unwrap().permissions();
        perms.set_mode(0o777);
        fs::set_permissions(&path_a, perms).unwrap();

        let current = FimBaseline::scan_paths(&paths);
        let changes = baseline.detect_changes(&current);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, FimChangeType::PermissionChanged);
    }

    #[test]
    fn directory_scanning() {
        let dir = setup_test_dir();
        // Append '/' to treat as directory scan.
        let dir_path = PathBuf::from(format!("{}/", dir.path().display()));
        let paths = vec![dir_path];

        let scanned = FimBaseline::scan_paths(&paths);
        assert_eq!(scanned.len(), 2, "should find both files in directory");
    }

    #[test]
    fn save_and_load_baseline() {
        let dir = setup_test_dir();
        let paths = vec![dir.path().join("file_a.txt"), dir.path().join("file_b.txt")];

        let scanned = FimBaseline::scan_paths(&paths);
        let mut baseline = FimBaseline::new();
        baseline.update(&scanned);

        let save_path = dir.path().join("baseline.json");
        baseline.save(&save_path).expect("save baseline");

        let loaded = FimBaseline::load(&save_path).expect("load baseline");
        assert_eq!(loaded.len(), baseline.len());

        // Verify loaded baseline detects no changes.
        let current = FimBaseline::scan_paths(&paths);
        let changes = loaded.detect_changes(&current);
        assert!(changes.is_empty());
    }

    #[test]
    fn update_acknowledges_changes() {
        let dir = setup_test_dir();
        let path_a = dir.path().join("file_a.txt");
        let paths = vec![path_a.clone()];

        let scanned = FimBaseline::scan_paths(&paths);
        let mut baseline = FimBaseline::new();
        baseline.update(&scanned);

        // Modify file.
        fs::write(&path_a, b"new content after change").unwrap();

        let current = FimBaseline::scan_paths(&paths);
        let changes = baseline.detect_changes(&current);
        assert_eq!(changes.len(), 1);

        // Acknowledge the change by updating baseline.
        baseline.update(&current);

        // No more changes detected.
        let current2 = FimBaseline::scan_paths(&paths);
        let changes2 = baseline.detect_changes(&current2);
        assert!(changes2.is_empty());
    }

    #[test]
    fn sha256_known_value() {
        // "hello world" SHA-256 = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        fs::write(&path, b"hello world").unwrap();

        let hash = sha256_file(&path).unwrap();
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn empty_file_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        fs::write(&path, b"").unwrap();

        let hash = sha256_file(&path).unwrap();
        // SHA-256 of empty input.
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn remove_entry_from_baseline() {
        let dir = setup_test_dir();
        let path_a = dir.path().join("file_a.txt");
        let paths = vec![path_a.clone()];

        let scanned = FimBaseline::scan_paths(&paths);
        let mut baseline = FimBaseline::new();
        baseline.update(&scanned);
        assert_eq!(baseline.len(), 1);

        baseline.remove(&path_a);
        assert!(baseline.is_empty());
    }

    #[test]
    fn scan_nonexistent_path_is_skipped() {
        let paths = vec![PathBuf::from(
            "/tmp/this_file_does_not_exist_fim_test_12345",
        )];
        let scanned = FimBaseline::scan_paths(&paths);
        assert!(scanned.is_empty());
    }

    #[test]
    fn large_file_chunked_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");

        // Create a file larger than the hash buffer (8KB) to exercise chunked reading.
        let mut file = fs::File::create(&path).unwrap();
        let chunk = [0xABu8; 4096];
        for _ in 0..4 {
            file.write_all(&chunk).unwrap();
        }
        drop(file);

        let hash = sha256_file(&path).unwrap();
        assert_eq!(hash.len(), 64, "SHA-256 hex string should be 64 chars");

        // Verify consistency: hashing the same file twice yields the same result.
        let hash2 = sha256_file(&path).unwrap();
        assert_eq!(hash, hash2);
    }
}
