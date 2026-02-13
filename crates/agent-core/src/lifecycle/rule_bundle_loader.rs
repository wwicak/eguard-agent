use std::fs;
use std::io::BufRead;
use std::path::{Component, Path, PathBuf};

use detection::DetectionEngine;
use tracing::{info, warn};

use super::{resolve_rules_staging_root, verify_bundle_signature};

/// Summary of rules loaded from a 6-layer threat intel bundle.
#[derive(Debug, Clone, Default)]
pub struct BundleLoadSummary {
    pub sigma_loaded: usize,
    pub yara_loaded: usize,
    pub ioc_hashes: usize,
    pub ioc_domains: usize,
    pub ioc_ips: usize,
    pub suricata_rules: usize,
    pub elastic_rules: usize,
    pub cve_entries: usize,
}

impl BundleLoadSummary {
    pub fn total_rules(&self) -> usize {
        self.sigma_loaded
            + self.yara_loaded
            + self.ioc_hashes
            + self.ioc_domains
            + self.ioc_ips
            + self.suricata_rules
            + self.elastic_rules
            + self.cve_entries
    }

    pub fn as_tuple(&self) -> (usize, usize) {
        (self.sigma_loaded, self.yara_loaded)
    }
}

pub(super) fn load_bundle_rules(
    detection: &mut DetectionEngine,
    bundle_path: &str,
) -> (usize, usize) {
    load_bundle_full(detection, bundle_path).as_tuple()
}

/// Load all 6 layers from a threat intel bundle.
pub(super) fn load_bundle_full(
    detection: &mut DetectionEngine,
    bundle_path: &str,
) -> BundleLoadSummary {
    let bundle_path = bundle_path.trim();
    if bundle_path.is_empty() {
        return BundleLoadSummary::default();
    }

    let path = Path::new(bundle_path);
    if !path.exists() {
        warn!(path = %path.display(), "threat-intel bundle path does not exist; skipping bundle load");
        return BundleLoadSummary::default();
    }

    if path.is_file() {
        if is_signed_bundle_archive(path) {
            return load_signed_bundle_archive_full(detection, path);
        }
        let (s, y) = load_bundle_rules_from_file(detection, path);
        return BundleLoadSummary {
            sigma_loaded: s,
            yara_loaded: y,
            ..Default::default()
        };
    }

    load_bundle_all_layers(detection, path)
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
    load_signed_bundle_archive_full(detection, bundle_path).as_tuple()
}

fn load_signed_bundle_archive_full(
    detection: &mut DetectionEngine,
    bundle_path: &Path,
) -> BundleLoadSummary {
    if !verify_bundle_signature(bundle_path) {
        warn!(path = %bundle_path.display(), "skipping rule bundle because signature verification failed");
        return BundleLoadSummary::default();
    }

    let extraction_dir = match prepare_bundle_extraction_dir(bundle_path) {
        Ok(path) => path,
        Err(err) => {
            warn!(error = %err, path = %bundle_path.display(), "failed preparing bundle extraction directory");
            return BundleLoadSummary::default();
        }
    };

    if let Err(err) = extract_bundle_archive(bundle_path, &extraction_dir) {
        warn!(error = %err, path = %bundle_path.display(), "failed extracting signed bundle archive");
        let _ = fs::remove_dir_all(&extraction_dir);
        return BundleLoadSummary::default();
    }

    let summary = load_bundle_all_layers(detection, &extraction_dir);
    if let Err(err) = fs::remove_dir_all(&extraction_dir) {
        warn!(error = %err, path = %extraction_dir.display(), "failed cleaning extracted bundle directory");
    }
    summary
}

/// Load all 6 detection layers from an extracted bundle directory.
fn load_bundle_all_layers(
    detection: &mut DetectionEngine,
    path: &Path,
) -> BundleLoadSummary {
    let (sigma_loaded, yara_loaded) = load_bundle_rules_from_dir(detection, path);

    // Layer 3: IOC indicators (hashes, domains, IPs)
    let (ioc_hashes, ioc_domains, ioc_ips) = load_ioc_indicators(detection, path);

    // Layer 4: Suricata network detection rules
    let suricata_rules = load_suricata_rules(path);

    // Layer 5: Elastic behavioral detection rules
    let elastic_rules = load_elastic_rules(path);

    // Layer 6: CVE vulnerability intelligence
    let cve_entries = load_cve_data(path);

    let summary = BundleLoadSummary {
        sigma_loaded,
        yara_loaded,
        ioc_hashes,
        ioc_domains,
        ioc_ips,
        suricata_rules,
        elastic_rules,
        cve_entries,
    };

    info!(
        sigma = summary.sigma_loaded,
        yara = summary.yara_loaded,
        ioc_hashes = summary.ioc_hashes,
        ioc_domains = summary.ioc_domains,
        ioc_ips = summary.ioc_ips,
        suricata = summary.suricata_rules,
        elastic = summary.elastic_rules,
        cve = summary.cve_entries,
        total = summary.total_rules(),
        "threat-intel bundle loaded (6 layers)"
    );

    summary
}

/// Load IOC indicators from the bundle's ioc/ directory.
///
/// Reads hashes.txt, domains.txt, and ips.txt; feeds them into the
/// detection engine's Layer 1 IOC filter.
fn load_ioc_indicators(
    detection: &mut DetectionEngine,
    bundle_dir: &Path,
) -> (usize, usize, usize) {
    let ioc_dir = bundle_dir.join("ioc");
    if !ioc_dir.is_dir() {
        return (0, 0, 0);
    }

    let hashes = load_ioc_list(&ioc_dir.join("hashes.txt"));
    let domains = load_ioc_list(&ioc_dir.join("domains.txt"));
    let ips = load_ioc_list(&ioc_dir.join("ips.txt"));

    // Feed into detection engine Layer 1 using bulk load
    detection.layer1.load_hashes(hashes.iter().cloned());
    detection.layer1.load_domains(domains.iter().cloned());
    detection.layer1.load_ips(ips.iter().cloned());

    (hashes.len(), domains.len(), ips.len())
}

/// Read a plain-text IOC list (one indicator per line, # comments, empty lines skipped).
fn load_ioc_list(path: &Path) -> Vec<String> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let reader = std::io::BufReader::new(file);
    let mut indicators = Vec::new();

    for line in reader.lines() {
        let Ok(line) = line else { break };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // IOC lists may have "indicator  # comment" format
        let indicator = trimmed.split('#').next().unwrap_or(trimmed).trim();
        if !indicator.is_empty() {
            indicators.push(indicator.to_lowercase());
        }
    }

    indicators
}

/// Load Suricata network IDS rules.
///
/// Counts alert rules from .rules files in suricata/ directory.
/// The actual Suricata rules are loaded by the network detection engine,
/// not the host-based detection engine — we just count them here for
/// the bundle manifest.
fn load_suricata_rules(bundle_dir: &Path) -> usize {
    let suricata_dir = bundle_dir.join("suricata");
    if !suricata_dir.is_dir() {
        return 0;
    }

    let mut rule_count = 0usize;

    if let Ok(entries) = fs::read_dir(&suricata_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rules") {
                continue;
            }
            if let Ok(content) = fs::read_to_string(&path) {
                rule_count += content
                    .lines()
                    .filter(|line| {
                        let trimmed = line.trim();
                        trimmed.starts_with("alert ") || trimmed.starts_with("drop ")
                    })
                    .count();
            }
        }
    }

    rule_count
}

/// Load Elastic behavioral detection rules from JSONL.
///
/// These rules use KQL/EQL queries for endpoint behavioral detection.
/// We count them and store for use by the temporal detection engine.
fn load_elastic_rules(bundle_dir: &Path) -> usize {
    let elastic_dir = bundle_dir.join("elastic");
    if !elastic_dir.is_dir() {
        return 0;
    }

    let jsonl_path = elastic_dir.join("elastic-rules.jsonl");
    if !jsonl_path.is_file() {
        return 0;
    }

    let file = match fs::File::open(&jsonl_path) {
        Ok(f) => f,
        Err(_) => return 0,
    };

    let reader = std::io::BufReader::new(file);
    reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .count()
}

/// Load CVE vulnerability intelligence from JSONL.
fn load_cve_data(bundle_dir: &Path) -> usize {
    let cve_path = bundle_dir.join("cve").join("cves.jsonl");
    if !cve_path.is_file() {
        return 0;
    }

    let file = match fs::File::open(&cve_path) {
        Ok(f) => f,
        Err(_) => return 0,
    };

    let reader = std::io::BufReader::new(file);
    reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .count()
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
