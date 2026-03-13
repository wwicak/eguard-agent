use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{info, warn};

use super::prune_rules_staging_root;

const DEFAULT_QUARANTINE_MAX_BYTES: u64 = 1_024 * 1_024 * 1_024;
const DEFAULT_UPDATE_MAX_BYTES: u64 = 512 * 1_024 * 1_024;
const DEFAULT_LOG_DIR_MAX_BYTES: u64 = 256 * 1_024 * 1_024;
const DEFAULT_QUARANTINE_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_UPDATE_RETENTION_SECS: u64 = 14 * 24 * 60 * 60;
const DEFAULT_LOG_RETENTION_SECS: u64 = 14 * 24 * 60 * 60;
const DEFAULT_STALE_UPDATE_TEMP_RETENTION_SECS: u64 = 24 * 60 * 60;
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
const DEFAULT_ACTIVE_LOG_MAX_BYTES: u64 = 20 * 1_024 * 1_024;
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
const DEFAULT_ROTATED_LOG_KEEP_COUNT: usize = 5;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct StorageCleanupReport {
    pub deleted_entries: usize,
    pub reclaimed_bytes: u64,
}

impl StorageCleanupReport {
    fn merge(&mut self, other: StorageCleanupReport) {
        self.deleted_entries = self.deleted_entries.saturating_add(other.deleted_entries);
        self.reclaimed_bytes = self.reclaimed_bytes.saturating_add(other.reclaimed_bytes);
    }
}

#[derive(Debug)]
struct DirEntryInfo {
    path: PathBuf,
    name: String,
    modified: SystemTime,
    size_bytes: u64,
}

pub(crate) fn run_periodic_storage_hygiene() -> StorageCleanupReport {
    let mut report = StorageCleanupReport::default();
    let bundle_report = prune_rules_staging_root();
    report.deleted_entries = report
        .deleted_entries
        .saturating_add(bundle_report.deleted_entries);
    report.reclaimed_bytes = report
        .reclaimed_bytes
        .saturating_add(bundle_report.reclaimed_bytes);
    report.merge(prune_quarantine_dir());
    report.merge(prune_update_dir());
    report.merge(prune_logs_dir());

    if report.deleted_entries > 0 {
        info!(
            deleted_entries = report.deleted_entries,
            reclaimed_bytes = report.reclaimed_bytes,
            "completed storage hygiene pass"
        );
    }

    report
}

#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub(crate) fn prepare_managed_log_file(log_path: &Path) {
    let max_bytes = env_u64("EGUARD_ACTIVE_LOG_MAX_BYTES").unwrap_or(DEFAULT_ACTIVE_LOG_MAX_BYTES);
    let keep_count =
        env_usize("EGUARD_ROTATED_LOG_KEEP_COUNT").unwrap_or(DEFAULT_ROTATED_LOG_KEEP_COUNT);

    let metadata = match fs::metadata(log_path) {
        Ok(metadata) => metadata,
        Err(_) => {
            if let Some(parent) = log_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            return;
        }
    };

    if metadata.len() < max_bytes {
        return;
    }

    let Some(parent) = log_path.parent() else {
        return;
    };
    let stem = log_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("agent");
    let ext = log_path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("log");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let rotated = parent.join(format!("{}-{}.{}", stem, suffix, ext));

    if let Err(err) = fs::rename(log_path, &rotated) {
        warn!(error = %err, path = %log_path.display(), rotated = %rotated.display(), "failed rotating managed log file");
        return;
    }

    let _ = prune_named_files(parent, stem, ext, keep_count);
}

pub(crate) fn resolve_logs_dir() -> PathBuf {
    if let Ok(raw) = std::env::var("EGUARD_LOG_DIR") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    resolve_agent_data_dir().join("logs")
}

fn prune_quarantine_dir() -> StorageCleanupReport {
    let dir = resolve_quarantine_dir();
    prune_dir_with_policy(
        &dir,
        env_u64("EGUARD_QUARANTINE_MAX_BYTES").unwrap_or(DEFAULT_QUARANTINE_MAX_BYTES),
        env_u64("EGUARD_QUARANTINE_RETENTION_SECS").unwrap_or(DEFAULT_QUARANTINE_RETENTION_SECS),
        |_| false,
        |_| false,
    )
}

fn prune_update_dir() -> StorageCleanupReport {
    let dir = resolve_update_dir();
    let retention_secs =
        env_u64("EGUARD_UPDATE_RETENTION_SECS").unwrap_or(DEFAULT_UPDATE_RETENTION_SECS);
    let stale_temp_secs = env_u64("EGUARD_UPDATE_TEMP_RETENTION_SECS")
        .unwrap_or(DEFAULT_STALE_UPDATE_TEMP_RETENTION_SECS);
    prune_dir_with_policy(
        &dir,
        env_u64("EGUARD_UPDATE_MAX_BYTES").unwrap_or(DEFAULT_UPDATE_MAX_BYTES),
        retention_secs,
        |_| false,
        |entry| is_stale_update_temp(entry, stale_temp_secs),
    )
}

fn prune_logs_dir() -> StorageCleanupReport {
    let dir = resolve_logs_dir();
    let active_name = managed_log_file_name();
    prune_dir_with_policy(
        &dir,
        env_u64("EGUARD_LOG_DIR_MAX_BYTES").unwrap_or(DEFAULT_LOG_DIR_MAX_BYTES),
        env_u64("EGUARD_LOG_RETENTION_SECS").unwrap_or(DEFAULT_LOG_RETENTION_SECS),
        |entry| entry.name == active_name,
        |_| false,
    )
}

fn prune_dir_with_policy(
    dir: &Path,
    max_bytes: u64,
    retention_secs: u64,
    preserve: impl Fn(&DirEntryInfo) -> bool,
    force_delete: impl Fn(&DirEntryInfo) -> bool,
) -> StorageCleanupReport {
    let mut report = StorageCleanupReport::default();
    let now = SystemTime::now();

    let mut entries = collect_dir_entries(dir);
    entries.retain(|entry| !preserve(entry));

    for entry in &entries {
        let age = now.duration_since(entry.modified).unwrap_or_default();
        if force_delete(entry) || age >= Duration::from_secs(retention_secs) {
            delete_path(&entry.path, entry.size_bytes, &mut report);
        }
    }

    let mut survivors = collect_dir_entries(dir);
    survivors.retain(|entry| !preserve(entry));
    let mut total_bytes = survivors.iter().map(|entry| entry.size_bytes).sum::<u64>();
    if total_bytes <= max_bytes {
        return report;
    }

    survivors.sort_by_key(|entry| entry.modified);
    for entry in survivors {
        if total_bytes <= max_bytes {
            break;
        }
        delete_path(&entry.path, entry.size_bytes, &mut report);
        total_bytes = total_bytes.saturating_sub(entry.size_bytes);
    }

    report
}

fn collect_dir_entries(dir: &Path) -> Vec<DirEntryInfo> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
        let size_bytes = if metadata.is_dir() {
            dir_size_bytes(&path)
        } else {
            metadata.len()
        };
        out.push(DirEntryInfo {
            path,
            name: entry.file_name().to_string_lossy().into_owned(),
            modified,
            size_bytes,
        });
    }
    out
}

fn delete_path(path: &Path, size_bytes: u64, report: &mut StorageCleanupReport) {
    let result = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match result {
        Ok(()) => {
            report.deleted_entries = report.deleted_entries.saturating_add(1);
            report.reclaimed_bytes = report.reclaimed_bytes.saturating_add(size_bytes);
        }
        Err(err) => warn!(error = %err, path = %path.display(), "failed pruning storage path"),
    }
}

fn dir_size_bytes(path: &Path) -> u64 {
    let mut total = 0u64;
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return 0,
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        total = total.saturating_add(if metadata.is_dir() {
            dir_size_bytes(&entry_path)
        } else {
            metadata.len()
        });
    }
    total
}

fn is_stale_update_temp(entry: &DirEntryInfo, stale_temp_secs: u64) -> bool {
    let age = SystemTime::now()
        .duration_since(entry.modified)
        .unwrap_or_default();
    if age < Duration::from_secs(stale_temp_secs) {
        return false;
    }

    entry.name.ends_with(".download")
        || entry.name.starts_with("update-outcome-")
        || entry.name.starts_with("apply-agent-update-worker")
        || entry.name.contains(".backup-")
}

#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
fn prune_named_files(dir: &Path, stem: &str, ext: &str, keep_count: usize) -> StorageCleanupReport {
    let mut entries = collect_dir_entries(dir)
        .into_iter()
        .filter(|entry| {
            entry.name.starts_with(&format!("{}-", stem))
                && entry.name.ends_with(&format!(".{}", ext))
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| b.modified.cmp(&a.modified));

    let mut report = StorageCleanupReport::default();
    for entry in entries.into_iter().skip(keep_count) {
        delete_path(&entry.path, entry.size_bytes, &mut report);
    }
    report
}

fn managed_log_file_name() -> String {
    #[cfg(target_os = "windows")]
    {
        return "agent.log".to_string();
    }

    #[cfg(target_os = "macos")]
    {
        return "agent.log".to_string();
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        "agent.log".to_string()
    }
}

fn resolve_quarantine_dir() -> PathBuf {
    if let Ok(raw) = std::env::var("EGUARD_QUARANTINE_DIR") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    #[cfg(target_os = "windows")]
    {
        return resolve_agent_data_dir().join("quarantine");
    }

    #[cfg(target_os = "macos")]
    {
        return resolve_agent_data_dir().join("quarantine");
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        resolve_agent_data_dir().join("quarantine")
    }
}

fn resolve_update_dir() -> PathBuf {
    resolve_agent_data_dir().join("update")
}

fn resolve_agent_data_dir() -> PathBuf {
    if let Ok(raw) = std::env::var("EGUARD_AGENT_DATA_DIR") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    #[cfg(target_os = "windows")]
    {
        return PathBuf::from(r"C:\ProgramData\eGuard");
    }

    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Library/Application Support/eGuard");
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        PathBuf::from("/var/lib/eguard-agent")
    }
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
}

#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn unique_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "eguard-storage-hygiene-{}-{}",
            label,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("unix time")
                .as_nanos()
        ))
    }

    #[test]
    fn quarantine_pruning_enforces_size_cap() {
        let _guard = crate::test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = unique_dir("quarantine");
        let quarantine = root.join("quarantine");
        fs::create_dir_all(&quarantine).expect("create quarantine dir");
        std::env::set_var("EGUARD_QUARANTINE_DIR", &quarantine);
        std::env::set_var("EGUARD_QUARANTINE_MAX_BYTES", "10");
        std::env::set_var("EGUARD_QUARANTINE_RETENTION_SECS", "86400");

        fs::write(quarantine.join("old.bin"), b"123456").expect("write old file");
        std::thread::sleep(Duration::from_millis(5));
        fs::write(quarantine.join("new.bin"), b"123456").expect("write new file");

        let report = prune_quarantine_dir();
        assert_eq!(report.deleted_entries, 1);
        assert!(!quarantine.join("old.bin").exists());
        assert!(quarantine.join("new.bin").exists());

        std::env::remove_var("EGUARD_QUARANTINE_DIR");
        std::env::remove_var("EGUARD_QUARANTINE_MAX_BYTES");
        std::env::remove_var("EGUARD_QUARANTINE_RETENTION_SECS");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn update_pruning_removes_stale_temp_files() {
        let _guard = crate::test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = unique_dir("update");
        let update_dir = root.join("update");
        fs::create_dir_all(&update_dir).expect("create update dir");
        std::env::set_var("EGUARD_AGENT_DATA_DIR", &root);
        std::env::set_var("EGUARD_UPDATE_TEMP_RETENTION_SECS", "0");

        fs::write(update_dir.join("apply-agent-update-worker.log"), b"log")
            .expect("write worker log");
        fs::write(update_dir.join("package.download"), b"payload").expect("write download temp");

        let report = prune_update_dir();
        assert!(report.deleted_entries >= 2);
        assert!(!update_dir.join("apply-agent-update-worker.log").exists());
        assert!(!update_dir.join("package.download").exists());

        std::env::remove_var("EGUARD_AGENT_DATA_DIR");
        std::env::remove_var("EGUARD_UPDATE_TEMP_RETENTION_SECS");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn managed_log_file_rotates_when_too_large() {
        let _guard = crate::test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = unique_dir("logs");
        let log_dir = root.join("logs");
        fs::create_dir_all(&log_dir).expect("create log dir");
        let log_path = log_dir.join("agent.log");
        let mut file = fs::File::create(&log_path).expect("create log file");
        file.write_all(b"0123456789abcdef").expect("write log file");
        std::env::set_var("EGUARD_ACTIVE_LOG_MAX_BYTES", "8");
        std::env::set_var("EGUARD_ROTATED_LOG_KEEP_COUNT", "2");

        prepare_managed_log_file(&log_path);

        let entries = collect_dir_entries(&log_dir);
        assert!(entries
            .iter()
            .any(|entry| entry.name.starts_with("agent-") && entry.name.ends_with(".log")));
        assert!(!log_path.exists());

        std::env::remove_var("EGUARD_ACTIVE_LOG_MAX_BYTES");
        std::env::remove_var("EGUARD_ROTATED_LOG_KEEP_COUNT");
        let _ = fs::remove_dir_all(root);
    }
}
