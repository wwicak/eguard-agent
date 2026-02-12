use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Result};

use super::DEFAULT_RULES_STAGING_DIR;

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
