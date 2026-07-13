use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
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
const DEFAULT_ROTATED_LOG_KEEP_COUNT: usize = 4;

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

pub(crate) struct ManagedLogWriter {
    path: PathBuf,
    file: Option<File>,
    written: u64,
    max_bytes: u64,
    keep_count: usize,
}

impl ManagedLogWriter {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let max_bytes = configured_active_log_max_bytes();
        let keep_count =
            env_usize("EGUARD_ROTATED_LOG_KEEP_COUNT").unwrap_or(DEFAULT_ROTATED_LOG_KEEP_COUNT);
        if let Ok((parent, stem, ext)) = managed_log_parts(path) {
            let _ = quiet_normalize_managed_archives(parent, stem, ext, keep_count, max_bytes);
        }
        let mut file = open_managed_log_file(path, false)?;
        let mut written = file.metadata()?.len();
        if written > max_bytes {
            drop(file);
            file = open_managed_log_file(path, true)?;
            written = 0;
        }
        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
            written,
            max_bytes,
            keep_count,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.take();
        let file = rotate_or_truncate(&self.path, self.keep_count)?;
        self.written = file.metadata()?.len();
        self.file = Some(file);
        Ok(())
    }
}

impl Write for ManagedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bounded = if buf.len() as u64 > self.max_bytes {
            &buf[..self.max_bytes as usize]
        } else {
            buf
        };
        if !bounded.is_empty()
            && self.written > 0
            && self.written.saturating_add(bounded.len() as u64) > self.max_bytes
        {
            self.rotate()?;
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "managed log is closed"))?;
        file.write_all(bounded)?;
        self.written = self.written.saturating_add(bounded.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "managed log is closed"))?
            .flush()
    }
}

fn configured_active_log_max_bytes() -> u64 {
    env_u64("EGUARD_ACTIVE_LOG_MAX_BYTES")
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_ACTIVE_LOG_MAX_BYTES)
}

fn open_managed_log_file(path: &Path, truncate: bool) -> io::Result<File> {
    #[cfg(unix)]
    let existed = path.exists();
    let mut options = OpenOptions::new();
    options.create(true).write(true);
    if truncate {
        options.truncate(true);
    } else {
        options.append(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let file = options.open(path)?;
        if !existed {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        return Ok(file);
    }
    #[cfg(not(unix))]
    options.open(path)
}

fn rotate_or_truncate(log_path: &Path, keep_count: usize) -> io::Result<File> {
    if keep_count > 0 {
        if let Ok((parent, stem, ext)) = managed_log_parts(log_path) {
            if quiet_prune_managed_archives(parent, stem, ext, keep_count - 1).is_ok() {
                let archive = parent.join(format!(
                    "{stem}-{}.{ext}",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|duration| duration.as_nanos())
                        .unwrap_or_default()
                ));
                if fs::rename(log_path, &archive).is_ok() {
                    match open_managed_log_file(log_path, false) {
                        Ok(file) => return Ok(file),
                        Err(open_err) => {
                            if fs::rename(&archive, log_path).is_ok() {
                                return open_managed_log_file(log_path, true);
                            }
                            return Err(open_err);
                        }
                    }
                }
            }
        }
    }
    open_managed_log_file(log_path, true)
}

fn managed_log_parts(log_path: &Path) -> io::Result<(&Path, &str, &str)> {
    let parent = log_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "log path has no parent"))?;
    let stem = log_path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "log path has no stem"))?;
    let ext = log_path
        .extension()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "log path has no extension"))?;
    Ok((parent, stem, ext))
}

fn quiet_normalize_managed_archives(
    dir: &Path,
    stem: &str,
    ext: &str,
    retain_count: usize,
    max_bytes: u64,
) -> io::Result<()> {
    let prefix = format!("{stem}-");
    let suffix = format!(".{ext}");
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix)
            && name.ends_with(&suffix)
            && entry.metadata()?.len() > max_bytes
        {
            fs::remove_file(entry.path())?;
        }
    }
    quiet_prune_managed_archives(dir, stem, ext, retain_count)
}

fn quiet_prune_managed_archives(
    dir: &Path,
    stem: &str,
    ext: &str,
    retain_count: usize,
) -> io::Result<()> {
    let prefix = format!("{stem}-");
    let suffix = format!(".{ext}");
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(&suffix) {
            entries.push((
                entry.metadata()?.modified().unwrap_or(UNIX_EPOCH),
                entry.path(),
            ));
        }
    }
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in entries.into_iter().skip(retain_count) {
        fs::remove_file(path)?;
    }
    Ok(())
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

    fn with_log_limits(max_bytes: &str, keep_count: &str) {
        std::env::set_var("EGUARD_ACTIVE_LOG_MAX_BYTES", max_bytes);
        std::env::set_var("EGUARD_ROTATED_LOG_KEEP_COUNT", keep_count);
    }

    fn clear_log_limits() {
        std::env::remove_var("EGUARD_ACTIVE_LOG_MAX_BYTES");
        std::env::remove_var("EGUARD_ROTATED_LOG_KEEP_COUNT");
    }

    #[test]
    fn managed_log_writer_open_normalizes_preexisting_oversized_logs() {
        let _guard = crate::test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = unique_dir("normalize-existing");
        fs::create_dir_all(&root).expect("create root");
        let log_path = root.join("agent.log");
        fs::write(&log_path, vec![b'A'; 40]).expect("multi-limit active log");
        fs::write(root.join("agent-1.log"), vec![b'B'; 24]).expect("oversized archive");
        for index in 2..=5 {
            fs::write(
                root.join(format!("agent-{index}.log")),
                vec![b'0' + index; 8],
            )
            .expect("bounded archive");
        }
        with_log_limits("8", "2");

        let writer = ManagedLogWriter::open(&log_path).expect("normalize existing logs");
        let logs = collect_dir_entries(&root)
            .into_iter()
            .filter(|entry| entry.name == "agent.log" || entry.name.starts_with("agent-"))
            .collect::<Vec<_>>();

        assert!(logs.len() <= 3, "active plus at most two archives");
        assert!(logs.iter().all(|entry| entry.size_bytes <= 8));
        assert!(logs.iter().map(|entry| entry.size_bytes).sum::<u64>() <= 24);
        assert_eq!(fs::metadata(&log_path).expect("active metadata").len(), 0);
        assert!(!root.join("agent-1.log").exists());

        drop(writer);
        clear_log_limits();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn managed_log_writer_repeated_rollover_enforces_aggregate_bound() {
        let _guard = crate::test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = unique_dir("bounded-writer");
        let log_path = root.join("agent.log");
        with_log_limits("8", "2");

        let mut writer = ManagedLogWriter::open(&log_path).expect("open managed writer");
        for value in 0..10 {
            writer
                .write_all(&[b'0' + value; 8])
                .expect("rollover write");
        }
        writer.flush().expect("flush");

        let logs = collect_dir_entries(&root)
            .into_iter()
            .filter(|entry| entry.name == "agent.log" || entry.name.starts_with("agent-"))
            .collect::<Vec<_>>();
        assert!(logs.len() <= 3, "active plus at most two archives");
        assert!(logs.iter().all(|entry| entry.size_bytes <= 8));
        assert!(logs.iter().map(|entry| entry.size_bytes).sum::<u64>() <= 24);

        clear_log_limits();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn managed_log_writer_zero_max_uses_default() {
        let _guard = crate::test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = unique_dir("zero-max");
        with_log_limits("0", "1");

        let writer = ManagedLogWriter::open(&root.join("agent.log")).expect("open managed writer");
        assert_eq!(writer.max_bytes, DEFAULT_ACTIVE_LOG_MAX_BYTES);

        clear_log_limits();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn managed_log_writer_zero_keep_truncates_without_archives() {
        let _guard = crate::test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = unique_dir("zero-keep");
        let log_path = root.join("agent.log");
        with_log_limits("8", "0");

        let mut writer = ManagedLogWriter::open(&log_path).expect("open managed writer");
        writer.write_all(b"12345678").expect("first write");
        writer.write_all(b"abcdefgh").expect("threshold write");
        writer.flush().expect("flush");

        assert_eq!(fs::read(&log_path).expect("active log"), b"abcdefgh");
        assert_eq!(collect_dir_entries(&root).len(), 1);

        clear_log_limits();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn managed_log_writer_bounds_oversized_record() {
        let _guard = crate::test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = unique_dir("oversized-record");
        let log_path = root.join("agent.log");
        with_log_limits("8", "2");

        let mut writer = ManagedLogWriter::open(&log_path).expect("open managed writer");
        writer
            .write_all(b"0123456789abcdef")
            .expect("oversized write");
        writer.flush().expect("flush");

        assert_eq!(fs::read(&log_path).expect("active log"), b"01234567");

        clear_log_limits();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn managed_log_writer_startup_prune_failure_falls_back_to_truncate() {
        let _guard = crate::test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = unique_dir("prune-failure");
        fs::create_dir_all(&root).expect("create root");
        let log_path = root.join("agent.log");
        fs::write(&log_path, b"0123456789abcdef").expect("oversized active log");
        fs::create_dir(root.join("agent-0.log")).expect("undeletable archive-shaped directory");
        with_log_limits("8", "1");

        let mut writer = ManagedLogWriter::open(&log_path).expect("fallback keeps file logging");
        writer.write_all(b"recovery").expect("write after fallback");
        writer.flush().expect("flush");

        assert_eq!(fs::read(&log_path).expect("active log"), b"recovery");
        assert!(root.join("agent-0.log").is_dir());

        clear_log_limits();
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn managed_log_writer_creates_files_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = crate::test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = unique_dir("permissions");
        let log_path = root.join("agent.log");
        with_log_limits("8", "1");

        let mut writer = ManagedLogWriter::open(&log_path).expect("open managed writer");
        assert_eq!(
            fs::metadata(&log_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        writer.write_all(b"12345678").expect("first write");
        writer.write_all(b"abcdefgh").expect("rotate write");
        writer.flush().expect("flush");
        assert_eq!(
            fs::metadata(&log_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        clear_log_limits();
        let _ = fs::remove_dir_all(root);
    }
}
