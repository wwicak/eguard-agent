use std::fs;
use std::path::{Component, Path, PathBuf};

use detection::DetectionEngine;
use tracing::warn;

use super::{resolve_rules_staging_root, verify_bundle_signature};

pub(super) fn load_bundle_rules(
    detection: &mut DetectionEngine,
    bundle_path: &str,
) -> (usize, usize) {
    let bundle_path = bundle_path.trim();
    if bundle_path.is_empty() {
        return (0, 0);
    }

    let path = Path::new(bundle_path);
    if !path.exists() {
        warn!(path = %path.display(), "threat-intel bundle path does not exist; skipping bundle load");
        return (0, 0);
    }

    if path.is_file() {
        if is_signed_bundle_archive(path) {
            return load_signed_bundle_archive_rules(detection, path);
        }
        return load_bundle_rules_from_file(detection, path);
    }

    load_bundle_rules_from_dir(detection, path)
}

pub(super) fn is_signed_bundle_archive(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            let lower = name.to_ascii_lowercase();
            lower.ends_with(".tar.zst") || lower.ends_with(".tzst")
        })
        .unwrap_or(false)
}

fn load_bundle_rules_from_file(detection: &mut DetectionEngine, path: &Path) -> (usize, usize) {
    let mut sigma_loaded = 0usize;
    let mut yara_loaded = 0usize;

    match path.extension().and_then(|ext| ext.to_str()) {
        Some("yml") | Some("yaml") => {
            match fs::read_to_string(path)
                .ok()
                .and_then(|source| detection.load_sigma_rule_yaml(&source).ok())
            {
                Some(_) => sigma_loaded += 1,
                None => warn!(path = %path.display(), "failed loading SIGMA bundle file"),
            }
        }
        Some("yar") | Some("yara") => {
            match fs::read_to_string(path)
                .ok()
                .and_then(|source| detection.load_yara_rules_str(&source).ok())
            {
                Some(count) => yara_loaded += count,
                None => warn!(path = %path.display(), "failed loading YARA bundle file"),
            }
        }
        _ => {
            warn!(path = %path.display(), "unsupported threat-intel bundle file extension");
        }
    }

    (sigma_loaded, yara_loaded)
}

fn load_bundle_rules_from_dir(detection: &mut DetectionEngine, path: &Path) -> (usize, usize) {
    let mut sigma_loaded = 0usize;
    let mut yara_loaded = 0usize;

    let mut sigma_dirs = Vec::new();
    push_unique_dir(&mut sigma_dirs, path.join("sigma"));
    push_unique_dir(&mut sigma_dirs, path.join("rules/sigma"));
    push_unique_dir(&mut sigma_dirs, path.join("detection/sigma"));

    let mut yara_dirs = Vec::new();
    push_unique_dir(&mut yara_dirs, path.join("yara"));
    push_unique_dir(&mut yara_dirs, path.join("rules/yara"));
    push_unique_dir(&mut yara_dirs, path.join("detection/yara"));

    for dir in sigma_dirs {
        if !dir.is_dir() {
            continue;
        }
        match detection.load_sigma_rules_from_dir(&dir) {
            Ok(count) => sigma_loaded += count,
            Err(err) => {
                warn!(error = %err, path = %dir.display(), "failed loading SIGMA bundle directory")
            }
        }
    }

    for dir in yara_dirs {
        if !dir.is_dir() {
            continue;
        }
        match detection.load_yara_rules_from_dir(&dir) {
            Ok(count) => yara_loaded += count,
            Err(err) => {
                warn!(error = %err, path = %dir.display(), "failed loading YARA bundle directory")
            }
        }
    }

    (sigma_loaded, yara_loaded)
}

fn load_signed_bundle_archive_rules(
    detection: &mut DetectionEngine,
    bundle_path: &Path,
) -> (usize, usize) {
    if !verify_bundle_signature(bundle_path) {
        warn!(path = %bundle_path.display(), "skipping rule bundle because signature verification failed");
        return (0, 0);
    }

    let extraction_dir = match prepare_bundle_extraction_dir(bundle_path) {
        Ok(path) => path,
        Err(err) => {
            warn!(error = %err, path = %bundle_path.display(), "failed preparing bundle extraction directory");
            return (0, 0);
        }
    };

    if let Err(err) = extract_bundle_archive(bundle_path, &extraction_dir) {
        warn!(error = %err, path = %bundle_path.display(), "failed extracting signed bundle archive");
        let _ = fs::remove_dir_all(&extraction_dir);
        return (0, 0);
    }

    let loaded = load_bundle_rules_from_dir(detection, &extraction_dir);
    if let Err(err) = fs::remove_dir_all(&extraction_dir) {
        warn!(error = %err, path = %extraction_dir.display(), "failed cleaning extracted bundle directory");
    }
    loaded
}

fn prepare_bundle_extraction_dir(bundle_path: &Path) -> std::result::Result<PathBuf, String> {
    let staging_root = resolve_rules_staging_root();

    fs::create_dir_all(&staging_root)
        .map_err(|err| format!("create staging root {}: {}", staging_root.display(), err))?;

    let bundle_name = bundle_path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("bundle")
        .to_ascii_lowercase();
    let sanitized_name = bundle_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();

    let extraction = staging_root.join(format!("{}-{}", sanitized_name, nonce));
    fs::create_dir_all(&extraction)
        .map_err(|err| format!("create extraction dir {}: {}", extraction.display(), err))?;
    Ok(extraction)
}

fn extract_bundle_archive(
    bundle_path: &Path,
    extraction_dir: &Path,
) -> std::result::Result<(), String> {
    let file = fs::File::open(bundle_path)
        .map_err(|err| format!("open archive {}: {}", bundle_path.display(), err))?;
    let decoder = zstd::stream::read::Decoder::new(file)
        .map_err(|err| format!("create zstd decoder for {}: {}", bundle_path.display(), err))?;
    let mut archive = tar::Archive::new(decoder);

    let entries = archive
        .entries()
        .map_err(|err| format!("read tar entries for {}: {}", bundle_path.display(), err))?;
    for entry in entries {
        let mut entry =
            entry.map_err(|err| format!("read tar entry in {}: {}", bundle_path.display(), err))?;

        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            continue;
        }

        let entry_path = entry
            .path()
            .map_err(|err| format!("read entry path in {}: {}", bundle_path.display(), err))?
            .into_owned();

        let Some(safe_rel) = sanitize_archive_relative_path(&entry_path) else {
            warn!(entry = %entry_path.display(), archive = %bundle_path.display(), "skipping unsafe bundle archive path");
            continue;
        };

        let destination = extraction_dir.join(&safe_rel);
        if entry_type.is_dir() {
            fs::create_dir_all(&destination)
                .map_err(|err| format!("create dir {}: {}", destination.display(), err))?;
            continue;
        }

        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("create parent {}: {}", parent.display(), err))?;
        }

        entry
            .unpack(&destination)
            .map_err(|err| format!("unpack {}: {}", destination.display(), err))?;
    }

    Ok(())
}

pub(super) fn sanitize_archive_relative_path(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(seg) => out.push(seg),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

pub(super) fn push_unique_dir(out: &mut Vec<PathBuf>, path: PathBuf) {
    if !out.iter().any(|existing| existing == &path) {
        out.push(path);
    }
}
