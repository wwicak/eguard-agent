use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::types::{BookmarkRecord, BookmarkState};

pub fn read_bookmark_state(path: &Path) -> Result<BookmarkState> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading bookmark state {}", path.display()))?;
    let state = serde_json::from_str::<BookmarkState>(&raw)
        .with_context(|| format!("failed parsing bookmark state {}", path.display()))?;
    Ok(state)
}

pub fn write_bookmark_state(path: &Path, state: &BookmarkState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating bookmark state dir {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(state)?;
    fs::write(path, body)
        .with_context(|| format!("failed writing bookmark state {}", path.display()))?;
    Ok(())
}

pub fn default_bookmark_state_path() -> PathBuf {
    if let Ok(raw) = std::env::var("EGUARD_ZTNA_BOOKMARK_STATE") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    #[cfg(target_os = "linux")]
    {
        return PathBuf::from("/var/lib/eguard-agent/ztna-bookmarks.json");
    }
    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Library/Application Support/eGuard/ztna-bookmarks.json");
    }
    #[cfg(target_os = "windows")]
    {
        return PathBuf::from(r"C:\ProgramData\eGuard\ztna-bookmarks.json");
    }
    #[allow(unreachable_code)]
    PathBuf::from("ztna-bookmarks.json")
}

pub fn bookmark_by_app_id<'a>(
    state: &'a BookmarkState,
    app_id: &str,
) -> Option<&'a BookmarkRecord> {
    state
        .bookmarks
        .iter()
        .find(|bookmark| bookmark.app_id == app_id)
}

#[cfg(test)]
mod tests {
    use super::{bookmark_by_app_id, read_bookmark_state, write_bookmark_state};
    use crate::types::{BookmarkRecord, BookmarkState};

    #[test]
    fn roundtrip_bookmark_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bookmarks.json");
        let state = BookmarkState {
            version: "v1".to_string(),
            bookmarks: vec![BookmarkRecord {
                app_id: "app-1".to_string(),
                name: "SSH".to_string(),
                launch_uri: "eguard-ztna://launch?type=ssh".to_string(),
                ..BookmarkRecord::default()
            }],
        };
        write_bookmark_state(&path, &state).expect("write bookmarks");
        let loaded = read_bookmark_state(&path).expect("read bookmarks");
        assert_eq!(loaded.version, "v1");
        assert!(bookmark_by_app_id(&loaded, "app-1").is_some());
    }
}
