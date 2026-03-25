use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use serde::Deserialize;
use tracing::{info, warn};

use super::DEFAULT_RULES_STAGING_DIR;

const LAST_KNOWN_GOOD_STATE_FILE: &str = "threat-intel-last-known-good.v1.json";
const REPLAY_FLOOR_STATE_FILE: &str = "threat-intel-replay-floor.v1.json";
// Reduced from 6h to 10 minutes — extracted directories are only needed during
// the initial load.  The previous 6h retention caused multi-GB bloat on
// resource-constrained VMs (especially macOS KVM with 4–8GB RAM) because
// multiple copies accumulated before the window expired.
const EXTRACTED_BUNDLE_RETENTION: Duration = Duration::from_secs(10 * 60);
const IOC_EXACT_STORE_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const DOWNLOAD_BUNDLE_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const ACTIVE_BUNDLE_KEEP_COUNT: usize = 2;

pub(super) fn is_remote_bundle_reference(bundle_path: &str) -> bool {
    let bundle_path = bundle_path.trim();
    if bundle_path.is_empty() {
        return false;
    }

    bundle_path.starts_with("http://")
        || bundle_path.starts_with("https://")
        || bundle_path.starts_with("/api/")
        || bundle_path.starts_with("api/")
}

pub(super) fn staging_bundle_archive_path(version: &str, bundle_path: &str) -> Result<PathBuf> {
    let staging_root = resolve_rules_staging_root();
    fs::create_dir_all(&staging_root)
        .map_err(|err| anyhow!("create staging root {}: {}", staging_root.display(), err))?;

    let mut file_name = sanitize_bundle_component(version);
    if file_name.is_empty() {
        file_name = sanitize_bundle_component(bundle_path);
    }
    if file_name.is_empty() {
        file_name = "bundle".to_string();
    }

    Ok(staging_root.join(format!("{}.bundle.tar.zst", file_name)))
}

pub(super) fn resolve_rules_staging_root() -> PathBuf {
    std::env::var("EGUARD_RULES_STAGING_DIR")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_RULES_STAGING_DIR))
}

#[derive(Debug, Default)]
pub(super) struct StorageCleanupReport {
    pub deleted_entries: usize,
    pub reclaimed_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct LastKnownGoodState {
    bundle_path: String,
}

pub(super) fn prune_rules_staging_root() -> StorageCleanupReport {
    let staging_root = resolve_rules_staging_root();
    let entries = match fs::read_dir(&staging_root) {
        Ok(entries) => entries,
        Err(_) => return StorageCleanupReport::default(),
    };

    let now = SystemTime::now();
    let mut report = StorageCleanupReport::default();
    let mut preserved_archives = preserved_bundle_archive_names(&staging_root);
    let mut bundle_files = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let age = metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .unwrap_or_default();

        if metadata.is_dir() {
            if age >= EXTRACTED_BUNDLE_RETENTION {
                delete_path(&path, &mut report);
            }
            continue;
        }

        if name == LAST_KNOWN_GOOD_STATE_FILE || name == REPLAY_FLOOR_STATE_FILE {
            continue;
        }

        if name.starts_with("ioc-exact-store-") && name.ends_with(".sqlite") {
            if age >= IOC_EXACT_STORE_RETENTION {
                delete_path(&path, &mut report);
            }
            continue;
        }

        if name.ends_with(".bundle.tar.zst") {
            bundle_files.push((name, path, age, metadata.len()));
            continue;
        }

        if name.ends_with(".bundle.tar.zst.sig") {
            if !preserved_archives.contains(name.trim_end_matches(".sig"))
                && age >= DOWNLOAD_BUNDLE_RETENTION
            {
                delete_path(&path, &mut report);
            }
            continue;
        }
    }

    bundle_files.sort_by(|a, b| a.2.cmp(&b.2));
    for (idx, (name, path, age, _size)) in bundle_files.into_iter().enumerate() {
        if idx < ACTIVE_BUNDLE_KEEP_COUNT {
            preserved_archives.insert(name.clone());
            continue;
        }
        if preserved_archives.contains(&name) || age < DOWNLOAD_BUNDLE_RETENTION {
            continue;
        }
        delete_path(&path, &mut report);
        let sig_path = path.with_extension("zst.sig");
        if sig_path.exists() {
            delete_path(&sig_path, &mut report);
        }
    }

    if report.deleted_entries > 0 {
        info!(
            path = %staging_root.display(),
            deleted_entries = report.deleted_entries,
            reclaimed_bytes = report.reclaimed_bytes,
            "pruned rules staging storage"
        );
    }

    report
}

fn preserved_bundle_archive_names(staging_root: &std::path::Path) -> HashSet<String> {
    let mut preserved = HashSet::new();
    let state_path = staging_root.join(LAST_KNOWN_GOOD_STATE_FILE);
    let Ok(raw) = fs::read_to_string(&state_path) else {
        return preserved;
    };
    let Ok(state) = serde_json::from_str::<LastKnownGoodState>(&raw) else {
        return preserved;
    };
    let path = PathBuf::from(state.bundle_path.trim());
    if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
        preserved.insert(name.to_string());
    }
    preserved
}

fn delete_path(path: &std::path::Path, report: &mut StorageCleanupReport) {
    let bytes = path_size_bytes(path);
    let result = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match result {
        Ok(()) => {
            report.deleted_entries = report.deleted_entries.saturating_add(1);
            report.reclaimed_bytes = report.reclaimed_bytes.saturating_add(bytes);
        }
        Err(err) => warn!(error = %err, path = %path.display(), "failed pruning storage path"),
    }
}

fn path_size_bytes(path: &std::path::Path) -> u64 {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return 0,
    };
    if metadata.is_file() {
        return metadata.len();
    }
    if !metadata.is_dir() {
        return 0;
    }

    let mut total = 0u64;
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return 0,
    };
    for entry in entries.flatten() {
        total = total.saturating_add(path_size_bytes(&entry.path()));
    }
    total
}

pub(super) fn sanitize_bundle_component(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
}
