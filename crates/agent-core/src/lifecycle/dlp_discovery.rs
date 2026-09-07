use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use detection::dlp::{DlpMatch, DlpScanner};
use serde::{Deserialize, Serialize};

const DEFAULT_MAX_FILES: usize = 10_000;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_MAX_DURATION: Duration = Duration::from_secs(5 * 60);
const DEFAULT_MAX_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone)]
pub struct DlpDiscoveryLimits {
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_duration: Duration,
    pub max_buffer_bytes: usize,
}

impl Default for DlpDiscoveryLimits {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_FILES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_duration: DEFAULT_MAX_DURATION,
            max_buffer_bytes: DEFAULT_MAX_BUFFER_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DlpDiscoveryRequest {
    pub roots: Vec<PathBuf>,
    pub excluded_roots: Vec<PathBuf>,
    pub allowed_extensions: Vec<String>,
    pub limits: DlpDiscoveryLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DlpDiscoveryCheckpoint {
    pub scope: String,
    pub last_path: PathBuf,
}

impl DlpDiscoveryCheckpoint {
    pub fn scope_for(request: &DlpDiscoveryRequest) -> String {
        let mut parts = request
            .roots
            .iter()
            .chain(request.excluded_roots.iter())
            .map(|path| path_sort_key(path))
            .collect::<Vec<_>>();
        parts.extend(
            request
                .allowed_extensions
                .iter()
                .map(|extension| extension.to_ascii_lowercase()),
        );
        parts.sort();
        parts.join("|")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DlpDiscoverySummary {
    pub files_seen: usize,
    pub files_scanned: usize,
    pub files_matched: usize,
    pub bytes_scanned: u64,
    pub errors: usize,
    pub limit_reached: bool,
    pub last_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpDiscoveryFinding {
    pub classifier_ids: Vec<String>,
    pub severity: String,
    pub match_count: usize,
}

#[cfg(test)]
fn run_dlp_discovery(
    request: &DlpDiscoveryRequest,
    scanner: &DlpScanner,
    stop: impl Fn() -> bool,
) -> (DlpDiscoverySummary, Vec<DlpDiscoveryFinding>) {
    run_dlp_discovery_from(request, scanner, None, stop, |_| {})
}

pub fn run_dlp_discovery_from(
    request: &DlpDiscoveryRequest,
    scanner: &DlpScanner,
    last_path: Option<PathBuf>,
    stop: impl Fn() -> bool,
    mut checkpoint: impl FnMut(&Path),
) -> (DlpDiscoverySummary, Vec<DlpDiscoveryFinding>) {
    let mut summary = DlpDiscoverySummary::default();
    let mut findings = Vec::new();
    let mut queue = VecDeque::new();
    let started = Instant::now();
    let cursor_key = last_path.as_ref().map(|path| path_sort_key(path));

    for root in &request.roots {
        if allowed_path(root, &request.excluded_roots) {
            queue.push_back((root.clone(), 0));
        }
    }

    while let Some((path, depth)) = queue.pop_front() {
        if stop() || started.elapsed() >= request.limits.max_duration {
            summary.limit_reached = true;
            break;
        }
        if summary.files_seen >= request.limits.max_files
            || summary.bytes_scanned >= request.limits.max_total_bytes
        {
            summary.limit_reached = true;
            break;
        }

        let metadata = match fs::symlink_metadata(&path) {
            Ok(value) => value,
            Err(_) => {
                summary.errors += 1;
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !allowed_path(&path, &request.excluded_roots) {
            continue;
        }

        if metadata.is_dir() {
            if depth >= MAX_DEPTH {
                continue;
            }
            let mut entries = match fs::read_dir(&path) {
                Ok(value) => value
                    .flatten()
                    .map(|entry| entry.path())
                    .collect::<Vec<_>>(),
                Err(_) => {
                    summary.errors += 1;
                    continue;
                }
            };
            entries.sort();
            for entry in entries.into_iter().rev() {
                if allowed_path(&entry, &request.excluded_roots) {
                    queue.push_back((entry, depth + 1));
                }
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }

        if cursor_key
            .as_ref()
            .is_some_and(|cursor| path_sort_key(&path) <= *cursor)
        {
            continue;
        }
        summary.files_seen += 1;
        if !is_allowed_extension(&path, &request.allowed_extensions)
            || metadata.len() > request.limits.max_file_bytes
            || metadata.len() > request.limits.max_buffer_bytes as u64
            || summary.bytes_scanned.saturating_add(metadata.len()) > request.limits.max_total_bytes
        {
            summary.last_path = Some(path.clone());
            checkpoint(&path);
            continue;
        }

        let matches = match scanner.scan_file(&path, request.limits.max_file_bytes) {
            Ok(value) => value,
            Err(_) => {
                summary.errors += 1;
                summary.last_path = Some(path.clone());
                checkpoint(&path);
                continue;
            }
        };
        summary.files_scanned += 1;
        summary.bytes_scanned = summary.bytes_scanned.saturating_add(metadata.len());
        summary.last_path = Some(path.clone());
        checkpoint(&path);
        if matches.is_empty() {
            continue;
        }

        summary.files_matched += 1;
        findings.push(metadata_only_finding(&matches));
    }

    (summary, findings)
}

fn metadata_only_finding(matches: &[DlpMatch]) -> DlpDiscoveryFinding {
    let mut classifier_ids: Vec<String> = matches.iter().map(|item| item.rule_id.clone()).collect();
    classifier_ids.sort();
    classifier_ids.dedup();
    let severity = matches
        .iter()
        .map(|item| item.severity.clone())
        .max_by_key(|value| severity_rank(value))
        .unwrap_or_else(|| "info".to_string());
    DlpDiscoveryFinding {
        classifier_ids,
        severity,
        match_count: matches.len(),
    }
}

fn severity_rank(value: &str) -> u8 {
    match value.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn is_allowed_extension(path: &Path, allowed: &[String]) -> bool {
    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return false;
    };
    let extension = extension.to_ascii_lowercase();
    allowed.iter().any(|item| {
        item.trim_start_matches('.')
            .eq_ignore_ascii_case(&extension)
    })
}

fn path_sort_key(path: &Path) -> String {
    let normalized = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let key = normalized.to_string_lossy().replace('\\', "/");
    if cfg!(target_os = "windows") {
        key.to_ascii_lowercase()
    } else {
        key
    }
}

fn allowed_path(path: &Path, excluded: &[PathBuf]) -> bool {
    let normalized = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    !excluded.iter().any(|root| {
        let root = fs::canonicalize(root).unwrap_or_else(|_| root.clone());
        normalized == root || normalized.starts_with(&root)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use detection::dlp::{DlpRule, DlpRulePack};

    fn scanner() -> DlpScanner {
        DlpScanner::from_pack(DlpRulePack {
            schema_version: "1".to_string(),
            pack_id: "test".to_string(),
            version: "1".to_string(),
            rules: vec![DlpRule {
                id: "id.nik".to_string(),
                name: "NIK".to_string(),
                pattern: r"[0-9]{16}".to_string(),
                context: vec!["nik".to_string()],
                validator: "context_only".to_string(),
                severity: "high".to_string(),
                default_action: "audit".to_string(),
                regulations: vec!["UU PDP".to_string()],
                redaction: "partial".to_string(),
                max_matches: 3,
            }],
        })
        .expect("scanner")
    }

    fn temp_root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "eguard-dlp-discovery-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temp root");
        path
    }

    #[test]
    fn discovery_is_bounded_and_metadata_only() {
        let root = temp_root("bounds");
        fs::write(root.join("hit.txt"), "NIK 3174123456780001").expect("hit");
        fs::write(root.join("skip.bin"), "NIK 3174123456780001").expect("skip");
        fs::write(root.join("large.txt"), vec![b'x'; 32]).expect("large");
        let request = DlpDiscoveryRequest {
            roots: vec![root.clone()],
            excluded_roots: vec![],
            allowed_extensions: vec!["txt".to_string()],
            limits: DlpDiscoveryLimits {
                max_files: 10,
                max_total_bytes: 1024,
                max_file_bytes: 24,
                max_duration: Duration::from_secs(5),
                max_buffer_bytes: 24,
            },
        };
        let scanner = scanner();
        assert_eq!(scanner.scan("NIK 3174123456780001").len(), 1);
        let (summary, findings) = run_dlp_discovery(&request, &scanner, || false);
        assert_eq!(summary.files_matched, 1);
        assert_eq!(findings[0].classifier_ids, vec!["id.nik"]);
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[0].match_count, 1);
        assert!(!format!("{findings:?}").contains("3174123456780001"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discovery_excludes_root_and_rejects_symlink() {
        let root = temp_root("exclude");
        let excluded = root.join("excluded");
        fs::create_dir_all(&excluded).expect("excluded");
        fs::write(excluded.join("hidden.txt"), "NIK 3174123456780001").expect("hidden");
        fs::write(root.join("visible.txt"), "benign").expect("visible");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&excluded, root.join("link")).expect("symlink");
        let request = DlpDiscoveryRequest {
            roots: vec![root.clone()],
            excluded_roots: vec![excluded],
            allowed_extensions: vec!["txt".to_string()],
            limits: DlpDiscoveryLimits::default(),
        };
        let (summary, findings) = run_dlp_discovery(&request, &scanner(), || false);
        assert_eq!(summary.files_matched, 0);
        assert!(findings.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discovery_resumes_after_last_checkpointed_file() {
        let root = temp_root("resume");
        for name in ["a.txt", "b.txt", "c.txt"] {
            fs::write(root.join(name), "benign").expect("file");
        }
        let request = DlpDiscoveryRequest {
            roots: vec![root.clone()],
            excluded_roots: vec![],
            allowed_extensions: vec!["txt".to_string()],
            limits: DlpDiscoveryLimits::default(),
        };
        let (summary, _) = run_dlp_discovery_from(
            &request,
            &scanner(),
            Some(root.join("b.txt")),
            || false,
            |_| {},
        );
        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.last_path, Some(root.join("c.txt")));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discovery_stops_on_kill_switch_and_limits_files() {
        let root = temp_root("stop");
        for index in 0..5 {
            fs::write(root.join(format!("{index}.txt")), "benign").expect("file");
        }
        let request = DlpDiscoveryRequest {
            roots: vec![root.clone()],
            excluded_roots: vec![],
            allowed_extensions: vec!["txt".to_string()],
            limits: DlpDiscoveryLimits {
                max_files: 2,
                ..DlpDiscoveryLimits::default()
            },
        };
        let (summary, _) = run_dlp_discovery(&request, &scanner(), || true);
        assert!(summary.limit_reached);
        assert_eq!(summary.files_scanned, 0);
        let _ = fs::remove_dir_all(root);
    }
}
