//! DLP policy engine (Forcepoint-style).
//!
//! Evaluates server-provided DLP policies against file-write events. A policy
//! matches when: at least one classifier matches the file content, AND the
//! event's source (path/channel/process) matches, AND the destination
//! (channel/path/app) matches. The first matching policy by priority wins.
//!
//! Everything reuses the existing detection primitives: `DlpScanner` for
//! regex rules, `dlp_classification::classify` for structured/unstructured
//! fingerprints, and the platform channel mapper.

use serde::Deserialize;

use detection::dlp::DlpMatch;
use detection::dlp_classification::{
    self, ClassificationMatch, ClassificationPolicy, StructuredRecord,
};

fn debug_event_log_enabled_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

pub(super) fn debug_event_log_enabled() -> bool {
    debug_event_log_enabled_value(std::env::var("EGUARD_DEBUG_EVENT_LOG").ok().as_deref())
}

const MAX_CLASSIFIER_BYTES: u64 = 64 * 1024 * 1024;

fn read_classifier_text(path: &str, classifier: &str, limit: u64) -> Option<String> {
    let read = || -> std::io::Result<String> {
        use std::io::Read;
        let file = std::fs::File::open(path)?;
        if file.metadata()?.len() > limit {
            return Err(std::io::Error::other("file exceeds DLP classifier limit"));
        }
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(std::io::Error::other("file exceeds DLP classifier limit"));
        }
        String::from_utf8(bytes)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    };
    match read() {
        Ok(text) => Some(text),
        Err(err) => {
            if debug_event_log_enabled() {
                tracing::info!(
                    path,
                    classifier,
                    error = %err,
                    "DLP classifier could not read file"
                );
            }
            None
        }
    }
}

/// One content classifier reference in a policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DlpClassifierRef {
    #[serde(rename = "type")]
    pub classifier_type: String,
    #[serde(default)]
    pub r#ref: String,
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub validator: String,
    #[serde(default)]
    pub context: Vec<String>,
}

/// Source condition: where the file comes from.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DlpSourceCond {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub processes: Vec<String>,
}

/// Destination condition: where the file goes.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DlpDestCond {
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub apps: Vec<String>,
    #[serde(default)]
    pub app_categories: Vec<String>,
    #[serde(default)]
    pub domain_categories: Vec<String>,
}

/// Flat user target list. Empty users = applies to all users (backward
/// compatible: existing policies have no `targets` field at all).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DlpTargets {
    #[serde(default)]
    pub users: Vec<String>,
}

/// Wire shape of one DLP policy as rendered by the server into policy_json.
#[derive(Debug, Clone, Deserialize)]
pub struct DlpPolicyEnvelope {
    pub policy_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub priority: i64,
    #[serde(default)]
    pub classifiers: Vec<DlpClassifierRef>,
    #[serde(default = "default_match_mode")]
    pub match_mode: String,
    #[serde(default)]
    pub source: DlpSourceCond,
    #[serde(default)]
    pub destination: DlpDestCond,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_redaction")]
    pub redaction: String,
    #[serde(default)]
    pub regulations: Vec<String>,
    #[serde(default = "default_max_size")]
    pub max_file_size_mb: usize,
    #[serde(default)]
    pub targets: DlpTargets,
}

fn default_match_mode() -> String {
    "any".to_string()
}
fn default_severity() -> String {
    "high".to_string()
}
fn default_action() -> String {
    "alert".to_string()
}
fn default_redaction() -> String {
    "mask_middle".to_string()
}
fn default_max_size() -> usize {
    10
}

/// Context gathered from a file-write event for policy evaluation.
pub struct DlpEvalContext<'a> {
    pub file_path: &'a str,
    pub process: &'a str,
    pub channel: &'a str,
    pub dst_domain: Option<&'a str>,
    pub app_category: Option<&'a str>,
    pub domain_category: Option<&'a str>,
    /// Optional resolved user (Scenario 13 AD integration); None = not resolved.
    pub user: Option<&'a str>,
}

/// The DLP policy engine. Owned by `AgentRuntime`.
pub struct DlpPolicyEngine {
    policies: Vec<DlpPolicyEnvelope>,
    fingerprint_policy: Option<ClassificationPolicy>,
    fingerprint_key: Option<Vec<u8>>,
    regex_scanner: Option<detection::dlp::DlpScanner>,
}

impl DlpPolicyEngine {
    pub fn new(
        mut policies: Vec<DlpPolicyEnvelope>,
        fingerprint_policy: Option<ClassificationPolicy>,
        fingerprint_key: Option<Vec<u8>>,
        regex_scanner: Option<detection::dlp::DlpScanner>,
    ) -> Self {
        // First matching policy by priority wins; sort ascending defensively
        // even if the server already ordered the list.
        policies.sort_by_key(|p| p.priority);
        Self {
            policies,
            fingerprint_policy,
            fingerprint_key,
            regex_scanner,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Evaluate a file event against all policies; first match by priority wins.
    pub fn evaluate(&self, ctx: &DlpEvalContext<'_>) -> Option<DlpMatch> {
        for policy in &self.policies {
            if !match_targets(&policy.targets, ctx.user)
                || !match_source(&policy.source, ctx)
                || !match_dest(&policy.destination, ctx)
            {
                continue;
            }
            if !policy.classifiers.is_empty() {
                let Ok(metadata) = std::fs::metadata(ctx.file_path) else {
                    continue;
                };
                let size = metadata.len();
                if size > (policy.max_file_size_mb as u64).saturating_mul(1024 * 1024) {
                    continue;
                }
                if size > MAX_CLASSIFIER_BYTES {
                    let mut finding = self.build_match(policy);
                    finding.action = "audit".to_string();
                    return Some(finding);
                }
            }
            if self.match_classifiers(policy, ctx) {
                return Some(self.build_match(policy));
            }
        }
        None
    }

    fn match_classifiers(&self, policy: &DlpPolicyEnvelope, ctx: &DlpEvalContext<'_>) -> bool {
        if policy.classifiers.is_empty() {
            return true;
        }
        let mut matched = 0usize;
        for classifier in &policy.classifiers {
            if self.match_classifier(classifier, ctx, policy.max_file_size_mb) {
                matched += 1;
                if policy.match_mode == "any" {
                    return true;
                }
            }
        }
        policy.match_mode == "all" && matched == policy.classifiers.len()
    }

    fn match_classifier(
        &self,
        classifier: &DlpClassifierRef,
        ctx: &DlpEvalContext<'_>,
        max_mb: usize,
    ) -> bool {
        match classifier.classifier_type.as_str() {
            "regex_rule" => self.match_regex_rule(classifier, ctx, max_mb),
            "structured_fingerprint" => self.match_structured(classifier, ctx, max_mb),
            "unstructured_fingerprint" => self.match_unstructured(classifier, ctx, max_mb),
            "label" => false, // Scenario 01: trusted label verifier not yet available
            _ => false,       // unknown classifier type: skip (fail closed)
        }
    }

    fn match_regex_rule(
        &self,
        classifier: &DlpClassifierRef,
        ctx: &DlpEvalContext<'_>,
        max_mb: usize,
    ) -> bool {
        let custom_scanner = if !classifier.pattern.trim().is_empty() {
            detection::dlp::DlpScanner::from_pack(detection::dlp::DlpRulePack {
                schema_version: "1".to_string(),
                pack_id: "server-classifier".to_string(),
                version: "1".to_string(),
                rules: vec![detection::dlp::DlpRule {
                    id: classifier.r#ref.clone(),
                    name: classifier.r#ref.clone(),
                    pattern: classifier.pattern.clone(),
                    validator: if classifier.validator.trim().is_empty() {
                        "none".to_string()
                    } else {
                        classifier.validator.clone()
                    },
                    context: classifier.context.clone(),
                    severity: "high".to_string(),
                    default_action: "audit".to_string(),
                    regulations: vec![],
                    redaction: "full".to_string(),
                    max_matches: 10,
                }],
            })
            .ok()
        } else {
            None
        };
        let scanner = custom_scanner.as_ref().or(self.regex_scanner.as_ref());
        let Some(scanner) = scanner else {
            return false;
        };
        let Some(text) = read_classifier_text(
            ctx.file_path,
            "regex_rule",
            (max_mb as u64)
                .saturating_mul(1024 * 1024)
                .min(MAX_CLASSIFIER_BYTES),
        ) else {
            return false;
        };
        // Match by rule id when the policy pins a specific rule; otherwise any hit.
        if classifier.r#ref.is_empty() {
            return !scanner.scan(&text).is_empty();
        }
        let rule_id = match classifier.r#ref.as_str() {
            "nik_indonesia" => "id.nik",
            "npwp_indonesia" => "id.npwp",
            "phone_indonesia" => "id.phone",
            "credit_card" => "id.kartu_kredit",
            value => value,
        };
        scanner.scan(&text).iter().any(|m| m.rule_id == rule_id)
    }

    fn match_structured(
        &self,
        classifier: &DlpClassifierRef,
        ctx: &DlpEvalContext<'_>,
        max_mb: usize,
    ) -> bool {
        let (Some(policy), Some(key)) = (&self.fingerprint_policy, self.fingerprint_key.as_deref())
        else {
            return false;
        };
        let Some(text) = read_classifier_text(
            ctx.file_path,
            "structured_fingerprint",
            (max_mb as u64)
                .saturating_mul(1024 * 1024)
                .min(MAX_CLASSIFIER_BYTES),
        ) else {
            return false;
        };
        let object = match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&text)
        {
            Ok(object) => object,
            Err(err) => {
                if debug_event_log_enabled() {
                    tracing::info!(
                        path = ctx.file_path,
                        classifier = "structured_fingerprint",
                        error = %err,
                        "DLP classifier could not parse structured file"
                    );
                }
                return false;
            }
        };
        let fields = object
            .iter()
            .filter_map(|(name, value)| value.as_str().map(|value| (name.as_str(), value)))
            .collect();
        let record = StructuredRecord { fields };
        let matches = dlp_classification::classify(policy, None, Some((key, &record)), None);
        if classifier.r#ref.is_empty() {
            return matches
                .iter()
                .any(|m| matches!(m, ClassificationMatch::StructuredFingerprint));
        }
        matches.iter().any(|m| match m {
            ClassificationMatch::StructuredFingerprint => {
                // Policy pinned a specific key_id; the loaded pack key_id is the
                // only structured set we hold, so a fingerprint hit satisfies it.
                true
            }
            _ => false,
        })
    }

    fn match_unstructured(
        &self,
        _classifier: &DlpClassifierRef,
        ctx: &DlpEvalContext<'_>,
        max_mb: usize,
    ) -> bool {
        let (Some(policy), Some(key)) = (&self.fingerprint_policy, self.fingerprint_key.as_deref())
        else {
            return false;
        };
        let Some(text) = read_classifier_text(
            ctx.file_path,
            "unstructured_fingerprint",
            (max_mb as u64)
                .saturating_mul(1024 * 1024)
                .min(MAX_CLASSIFIER_BYTES),
        ) else {
            return false;
        };
        let matches = dlp_classification::classify(policy, None, None, Some((key, &text)));
        matches
            .iter()
            .any(|m| matches!(m, ClassificationMatch::UnstructuredFingerprint { .. }))
    }

    fn build_match(&self, policy: &DlpPolicyEnvelope) -> DlpMatch {
        DlpMatch {
            rule_id: policy.policy_id.clone(),
            severity: policy.severity.clone(),
            action: policy.action.clone(),
            start: 0,
            end: 0,
            redacted_evidence: "[REDACTED]".to_string(),
        }
    }
}

fn match_source(source: &DlpSourceCond, ctx: &DlpEvalContext<'_>) -> bool {
    let path = ctx.file_path;
    if !source.exclude_paths.is_empty()
        && source
            .exclude_paths
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
    {
        return false;
    }
    let path_ok = source.paths.is_empty()
        || source
            .paths
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()));
    let channel_ok = source.channels.is_empty()
        || source
            .channels
            .iter()
            .any(|c| c == "file_system" || c == ctx.channel);
    let process_ok = source.processes.is_empty()
        || source
            .processes
            .iter()
            .any(|p| ctx.process.contains(p.as_str()));
    let user_ok = source.users.is_empty()
        || ctx
            .user
            .map(|user| source.users.iter().any(|u| u == user))
            .unwrap_or(false);
    path_ok && channel_ok && process_ok && user_ok
}

fn match_targets(targets: &DlpTargets, user: Option<&str>) -> bool {
    if targets.users.is_empty() {
        return true;
    }
    let Some(user) = user.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    targets
        .users
        .iter()
        .any(|target| target.trim().eq_ignore_ascii_case(user))
}

fn match_dest(dest: &DlpDestCond, ctx: &DlpEvalContext<'_>) -> bool {
    if dest.channels.is_empty()
        && dest.paths.is_empty()
        && dest.apps.is_empty()
        && dest.app_categories.is_empty()
        && dest.domain_categories.is_empty()
    {
        return true;
    }
    let channel_ok = dest.channels.is_empty() || dest.channels.iter().any(|c| c == ctx.channel);
    let path_ok = dest.paths.is_empty()
        || dest
            .paths
            .iter()
            .any(|prefix| ctx.file_path.starts_with(prefix.as_str()));
    // Apps are resolved from the process name (Scenario 08); treat the process
    // as the app identity for now.
    let app_ok = dest.apps.is_empty()
        || dest
            .apps
            .iter()
            .any(|app| ctx.process.contains(app.as_str()));
    let app_category_ok = dest.app_categories.is_empty()
        || ctx
            .app_category
            .map(|category| dest.app_categories.iter().any(|v| v == category))
            .unwrap_or(false);
    let domain_category_ok = dest.domain_categories.is_empty()
        || ctx
            .domain_category
            .map(|category| dest.domain_categories.iter().any(|v| v == category))
            .unwrap_or(false);
    channel_ok && path_ok && app_ok && app_category_ok && domain_category_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_event_log_gate_requires_non_empty_opt_in() {
        assert!(!debug_event_log_enabled_value(None));
        assert!(!debug_event_log_enabled_value(Some("   ")));
        assert!(debug_event_log_enabled_value(Some("1")));
    }

    #[test]
    fn policy_classifier_respects_configured_file_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.txt");
        let mut data = vec![b'a'; 11 * 1024 * 1024];
        data.extend_from_slice(b" SECRET_MARKER");
        std::fs::write(&path, data).unwrap();
        let policy = DlpPolicyEnvelope {
            policy_id: "large-file".into(),
            name: String::new(),
            priority: 0,
            classifiers: vec![DlpClassifierRef {
                classifier_type: "regex_rule".into(),
                r#ref: String::new(),
                pattern: "SECRET_MARKER".into(),
                validator: "none".into(),
                context: vec![],
            }],
            match_mode: "any".into(),
            source: DlpSourceCond::default(),
            destination: DlpDestCond::default(),
            severity: "high".into(),
            action: "alert".into(),
            redaction: "full".into(),
            regulations: vec![],
            max_file_size_mb: 12,
            targets: DlpTargets::default(),
        };
        let path = path.to_str().unwrap();
        assert!(engine(vec![policy.clone()], None, None, None)
            .evaluate(&ctx(path, "explorer", "file_write"))
            .is_some());
        let mut smaller = policy;
        smaller.max_file_size_mb = 10;
        assert!(engine(vec![smaller], None, None, None)
            .evaluate(&ctx(path, "explorer", "file_write"))
            .is_none());
    }

    #[test]
    fn oversized_policy_file_is_audited_without_loading_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.txt");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(65 * 1024 * 1024).unwrap();
        let policy: DlpPolicyEnvelope = serde_json::from_str(
            r#"{"policy_id":"p-large","max_file_size_mb":128,"classifiers":[{"type":"regex_rule","pattern":"SECRET"}]}"#,
        ).unwrap();
        let found = engine(vec![policy], None, None, None)
            .evaluate(&ctx(path.to_str().unwrap(), "explorer", "file_write"))
            .unwrap();
        assert_eq!(found.rule_id, "p-large");
        assert_eq!(found.action, "audit");
    }

    fn engine(
        policies: Vec<DlpPolicyEnvelope>,
        fp: Option<ClassificationPolicy>,
        key: Option<Vec<u8>>,
        scanner: Option<detection::dlp::DlpScanner>,
    ) -> DlpPolicyEngine {
        DlpPolicyEngine::new(policies, fp, key, scanner)
    }

    fn ctx<'a>(path: &'a str, process: &'a str, channel: &'a str) -> DlpEvalContext<'a> {
        DlpEvalContext {
            file_path: path,
            process,
            channel,
            dst_domain: None,
            app_category: None,
            domain_category: None,
            user: None,
        }
    }

    #[test]
    fn empty_policy_set_matches_nothing() {
        let e = engine(vec![], None, None, None);
        assert!(e.is_empty());
        assert!(e
            .evaluate(&ctx("C:\\x\\a.txt", "explorer", "file_write"))
            .is_none());
    }

    #[test]
    fn destination_channel_gate_blocks_non_matching() {
        let policy = DlpPolicyEnvelope {
            policy_id: "p1".to_string(),
            name: "p1".to_string(),
            priority: 1,
            classifiers: vec![],
            match_mode: "any".to_string(),
            source: DlpSourceCond::default(),
            destination: DlpDestCond {
                channels: vec!["removable_media".to_string()],
                ..Default::default()
            },
            severity: "high".to_string(),
            action: "alert".to_string(),
            redaction: "mask_middle".to_string(),
            regulations: vec![],
            max_file_size_mb: 10,
            targets: DlpTargets::default(),
        };
        let e = engine(vec![policy], None, None, None);
        // No classifiers -> content matches; destination gate decides.
        assert!(e
            .evaluate(&ctx("E:\\x\\a.txt", "explorer", "removable_media"))
            .is_some());
        assert!(e
            .evaluate(&ctx("C:\\x\\a.txt", "explorer", "file_write"))
            .is_none());
    }

    #[test]
    fn server_nik_reference_resolves_local_rule_id() {
        let path = std::env::temp_dir().join("eguard-dlp-policy-nik.txt");
        std::fs::write(&path, "NIK 7371092301900001").expect("write fixture");
        let scanner = detection::dlp::DlpScanner::from_pack(detection::dlp::DlpRulePack {
            schema_version: "1".into(),
            pack_id: "test".into(),
            version: "1".into(),
            rules: vec![detection::dlp::DlpRule {
                id: "id.nik".into(),
                name: "NIK".into(),
                pattern: r"\b\d{16}\b".into(),
                validator: "nik_indonesia".into(),
                context: vec!["nik".into()],
                severity: "high".into(),
                default_action: "alert".into(),
                regulations: vec![],
                redaction: "mask_middle".into(),
                max_matches: 10,
            }],
        })
        .expect("scanner");
        let policy = DlpPolicyEnvelope {
            policy_id: "pii-to-usb".into(),
            name: "PII to USB".into(),
            priority: 1,
            classifiers: vec![DlpClassifierRef {
                classifier_type: "regex_rule".into(),
                r#ref: "nik_indonesia".into(),
                pattern: String::new(),
                validator: String::new(),
                context: vec![],
            }],
            match_mode: "any".into(),
            source: DlpSourceCond {
                channels: vec!["file_system".into()],
                ..Default::default()
            },
            destination: DlpDestCond {
                channels: vec!["removable_media".into()],
                ..Default::default()
            },
            severity: "high".into(),
            action: "alert".into(),
            redaction: "mask_middle".into(),
            regulations: vec![],
            max_file_size_mb: 10,
            targets: DlpTargets::default(),
        };
        let e = engine(vec![policy], None, None, Some(scanner));
        assert!(e
            .evaluate(&ctx(
                path.to_str().expect("path"),
                "System",
                "removable_media"
            ))
            .is_some());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn source_path_and_process_gates() {
        let policy = DlpPolicyEnvelope {
            policy_id: "p2".to_string(),
            name: "p2".to_string(),
            priority: 1,
            classifiers: vec![],
            match_mode: "any".to_string(),
            source: DlpSourceCond {
                paths: vec!["C:\\Users\\".to_string()],
                processes: vec!["notepad".to_string()],
                ..Default::default()
            },
            destination: DlpDestCond::default(),
            severity: "high".to_string(),
            action: "alert".to_string(),
            redaction: "mask_middle".to_string(),
            regulations: vec![],
            max_file_size_mb: 10,
            targets: DlpTargets::default(),
        };
        let e = engine(vec![policy], None, None, None);
        assert!(e
            .evaluate(&ctx("C:\\Users\\bob\\doc.txt", "notepad.exe", "file_write"))
            .is_some());
        assert!(e
            .evaluate(&ctx("D:\\other\\doc.txt", "notepad.exe", "file_write"))
            .is_none());
        assert!(e
            .evaluate(&ctx(
                "C:\\Users\\bob\\doc.txt",
                "explorer.exe",
                "file_write"
            ))
            .is_none());
    }

    #[test]
    fn exclude_paths_override_includes() {
        let policy = DlpPolicyEnvelope {
            policy_id: "p3".to_string(),
            name: "p3".to_string(),
            priority: 1,
            classifiers: vec![],
            match_mode: "any".to_string(),
            source: DlpSourceCond {
                paths: vec!["C:\\Users\\".to_string()],
                exclude_paths: vec!["C:\\Users\\bob\\excluded\\".to_string()],
                ..Default::default()
            },
            destination: DlpDestCond::default(),
            severity: "high".to_string(),
            action: "alert".to_string(),
            redaction: "mask_middle".to_string(),
            regulations: vec![],
            max_file_size_mb: 10,
            targets: DlpTargets::default(),
        };
        let e = engine(vec![policy], None, None, None);
        assert!(e
            .evaluate(&ctx("C:\\Users\\bob\\doc.txt", "x", "file_write"))
            .is_some());
        assert!(e
            .evaluate(&ctx(
                "C:\\Users\\bob\\excluded\\secret.txt",
                "x",
                "file_write"
            ))
            .is_none());
    }

    #[test]
    fn priority_order_first_match_wins() {
        let mk = |id: &str, priority: i64, channel: &str| DlpPolicyEnvelope {
            policy_id: id.to_string(),
            name: id.to_string(),
            priority,
            classifiers: vec![],
            match_mode: "any".to_string(),
            source: DlpSourceCond::default(),
            destination: DlpDestCond {
                channels: vec![channel.to_string()],
                ..Default::default()
            },
            severity: "high".to_string(),
            action: "alert".to_string(),
            redaction: "mask_middle".to_string(),
            regulations: vec![],
            max_file_size_mb: 10,
            targets: DlpTargets::default(),
        };
        let e = engine(
            vec![
                mk("low-prio", 100, "removable_media"),
                mk("high-prio", 1, "removable_media"),
            ],
            None,
            None,
            None,
        );
        let m = e
            .evaluate(&ctx("E:\\a.txt", "x", "removable_media"))
            .expect("match");
        assert_eq!(m.rule_id, "high-prio");
    }

    #[test]
    fn unknown_classifier_type_fails_closed() {
        let policy = DlpPolicyEnvelope {
            policy_id: "p4".to_string(),
            name: "p4".to_string(),
            priority: 1,
            classifiers: vec![DlpClassifierRef {
                classifier_type: "quantum".to_string(),
                r#ref: "x".to_string(),
                pattern: String::new(),
                validator: String::new(),
                context: vec![],
            }],
            match_mode: "any".to_string(),
            source: DlpSourceCond::default(),
            destination: DlpDestCond::default(),
            severity: "high".to_string(),
            action: "alert".to_string(),
            redaction: "mask_middle".to_string(),
            regulations: vec![],
            max_file_size_mb: 10,
            targets: DlpTargets::default(),
        };
        let e = engine(vec![policy], None, None, None);
        assert!(e.evaluate(&ctx("C:\\a.txt", "x", "file_write")).is_none());
    }

    #[test]
    fn user_targets_require_matching_resolved_user() {
        let policy = DlpPolicyEnvelope {
            policy_id: "targeted".to_string(),
            name: "targeted".to_string(),
            priority: 1,
            classifiers: vec![],
            match_mode: "any".to_string(),
            source: DlpSourceCond::default(),
            destination: DlpDestCond::default(),
            severity: "high".to_string(),
            action: "alert".to_string(),
            redaction: "mask_middle".to_string(),
            regulations: vec![],
            max_file_size_mb: 10,
            targets: DlpTargets {
                users: vec!["Budi.S".to_string()],
            },
        };
        let e = engine(vec![policy], None, None, None);
        let matching = DlpEvalContext {
            file_path: "C:\\Users\\budi\\doc.txt",
            process: "notepad.exe",
            channel: "file_write",
            dst_domain: None,
            app_category: None,
            domain_category: None,
            user: Some("budi.s"),
        };
        let missing = DlpEvalContext {
            user: None,
            ..matching
        };
        assert!(e.evaluate(&matching).is_some());
        assert!(e.evaluate(&missing).is_none());
    }

    #[test]
    fn custom_regex_classifier_matches_without_local_rule_pack_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("payroll.txt");
        std::fs::write(&path, "DOKUMEN UJI SLIP GAJI KARYAWAN").expect("write fixture");
        let policy = DlpPolicyEnvelope {
            policy_id: "deteksi-slip-gaji".to_string(),
            name: "Deteksi Slip Gaji".to_string(),
            priority: 1,
            classifiers: vec![DlpClassifierRef {
                classifier_type: "regex_rule".to_string(),
                r#ref: "slip-gaji".to_string(),
                pattern: r"(?i)\bSLIP\s+GAJI\s+KARYAWAN\b".to_string(),
                validator: "none".to_string(),
                context: vec![],
            }],
            match_mode: "any".to_string(),
            source: DlpSourceCond::default(),
            destination: DlpDestCond::default(),
            severity: "high".to_string(),
            action: "alert".to_string(),
            redaction: "mask_middle".to_string(),
            regulations: vec![],
            max_file_size_mb: 10,
            targets: DlpTargets::default(),
        };
        let matched = engine(vec![policy.clone()], None, None, None).evaluate(&ctx(
            path.to_str().unwrap(),
            "notepad.exe",
            "file_write",
        ));
        assert_eq!(
            matched.expect("custom classifier match").rule_id,
            "deteksi-slip-gaji"
        );

        std::fs::write(&path, "DOKUMEN UJI KEHADIRAN KARYAWAN").expect("write negative fixture");
        assert!(engine(vec![policy], None, None, None)
            .evaluate(&ctx(path.to_str().unwrap(), "notepad.exe", "file_write"))
            .is_none());
    }

    #[test]
    fn browser_app_category_gate_matches_classifier_without_domain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("browser-upload.txt");
        std::fs::write(&path, "NIK 3174123456780001").expect("write fixture");
        let policy = DlpPolicyEnvelope {
            policy_id: "browser-nik".to_string(),
            name: "Browser NIK".to_string(),
            priority: 1,
            classifiers: vec![DlpClassifierRef {
                classifier_type: "regex_rule".to_string(),
                r#ref: "nik-browser".to_string(),
                pattern: r"\b\d{16}\b".to_string(),
                validator: "context_only".to_string(),
                context: vec!["NIK".to_string(), "KTP".to_string()],
            }],
            match_mode: "any".to_string(),
            source: DlpSourceCond::default(),
            destination: DlpDestCond {
                app_categories: vec!["browser".to_string()],
                ..Default::default()
            },
            severity: "high".to_string(),
            action: "alert".to_string(),
            redaction: "mask_middle".to_string(),
            regulations: vec![],
            max_file_size_mb: 10,
            targets: DlpTargets::default(),
        };
        let mut browser_ctx = ctx(path.to_str().unwrap(), "chrome.exe", "browser_activity");
        browser_ctx.app_category = Some("browser");
        assert_eq!(
            engine(vec![policy.clone()], None, None, None)
                .evaluate(&browser_ctx)
                .expect("browser classifier match")
                .rule_id,
            "browser-nik"
        );
        browser_ctx.dst_domain = Some("drive.google.com");
        assert!(engine(vec![policy], None, None, None)
            .evaluate(&browser_ctx)
            .is_some());
    }
}
