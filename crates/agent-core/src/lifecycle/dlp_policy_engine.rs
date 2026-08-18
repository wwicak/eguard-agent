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

/// One content classifier reference in a policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DlpClassifierRef {
    #[serde(rename = "type")]
    pub classifier_type: String,
    #[serde(default)]
    pub r#ref: String,
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
            if self.matches(policy, ctx) {
                return Some(self.build_match(policy));
            }
        }
        None
    }

    fn matches(&self, policy: &DlpPolicyEnvelope, ctx: &DlpEvalContext<'_>) -> bool {
        if !self.match_classifiers(policy, ctx) {
            return false;
        }
        if !match_targets(&policy.targets, ctx.user) {
            return false;
        }
        if !match_source(&policy.source, ctx) {
            return false;
        }
        if !match_dest(&policy.destination, ctx) {
            return false;
        }
        true
    }

    fn match_classifiers(&self, policy: &DlpPolicyEnvelope, ctx: &DlpEvalContext<'_>) -> bool {
        if policy.classifiers.is_empty() {
            return true;
        }
        let mut matched = 0usize;
        for classifier in &policy.classifiers {
            if self.match_classifier(classifier, ctx) {
                matched += 1;
                if policy.match_mode == "any" {
                    return true;
                }
            }
        }
        policy.match_mode == "all" && matched == policy.classifiers.len()
    }

    fn match_classifier(&self, classifier: &DlpClassifierRef, ctx: &DlpEvalContext<'_>) -> bool {
        match classifier.classifier_type.as_str() {
            "regex_rule" => self.match_regex_rule(classifier, ctx),
            "structured_fingerprint" => self.match_structured(classifier, ctx),
            "unstructured_fingerprint" => self.match_unstructured(classifier, ctx),
            "label" => false, // Scenario 01: trusted label verifier not yet available
            _ => false,       // unknown classifier type: skip (fail closed)
        }
    }

    fn match_regex_rule(&self, classifier: &DlpClassifierRef, ctx: &DlpEvalContext<'_>) -> bool {
        let Some(scanner) = &self.regex_scanner else {
            return false;
        };
        let Ok(text) = std::fs::read_to_string(ctx.file_path) else {
            return false;
        };
        // Match by rule id when the policy pins a specific rule; otherwise any hit.
        if classifier.r#ref.is_empty() {
            return !scanner.scan(&text).is_empty();
        }
        scanner
            .scan(&text)
            .iter()
            .any(|m| m.rule_id == classifier.r#ref)
    }

    fn match_structured(&self, classifier: &DlpClassifierRef, ctx: &DlpEvalContext<'_>) -> bool {
        let (Some(policy), Some(key)) = (&self.fingerprint_policy, self.fingerprint_key.as_deref())
        else {
            return false;
        };
        let Ok(text) = std::fs::read_to_string(ctx.file_path) else {
            return false;
        };
        let Ok(object) =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&text)
        else {
            return false;
        };
        let fields = object
            .iter()
            .filter_map(|(name, value)| value.as_str().map(|value| (name.as_str(), value)))
            .collect();
        let record = StructuredRecord { fields };
        let matches =
            dlp_classification::classify(policy, None, Some((key, &record)), None);
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

    fn match_unstructured(&self, _classifier: &DlpClassifierRef, ctx: &DlpEvalContext<'_>) -> bool {
        let (Some(policy), Some(key)) = (&self.fingerprint_policy, self.fingerprint_key.as_deref())
        else {
            return false;
        };
        let Ok(text) = std::fs::read_to_string(ctx.file_path) else {
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
        || source.paths.iter().any(|prefix| path.starts_with(prefix.as_str()));
    let channel_ok = source.channels.is_empty()
        || source
            .channels
            .iter()
            .any(|c| c == ctx.channel);
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
    if dest.channels.is_empty() && dest.paths.is_empty() && dest.apps.is_empty() {
        return true;
    }
    let channel_ok = dest.channels.is_empty()
        || dest.channels.iter().any(|c| c == ctx.channel);
    let path_ok = dest.paths.is_empty()
        || dest
            .paths
            .iter()
            .any(|prefix| ctx.file_path.starts_with(prefix.as_str()));
    // Apps are resolved from the process name (Scenario 08); treat the process
    // as the app identity for now.
    let app_ok = dest.apps.is_empty()
        || dest.apps.iter().any(|app| ctx.process.contains(app.as_str()));
    channel_ok && path_ok && app_ok
}

#[cfg(test)]
mod tests {
    use super::*;

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
            user: None,
        }
    }

    #[test]
    fn empty_policy_set_matches_nothing() {
        let e = engine(vec![], None, None, None);
        assert!(e.is_empty());
        assert!(e.evaluate(&ctx("C:\\x\\a.txt", "explorer", "file_write")).is_none());
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
        assert!(e.evaluate(&ctx("E:\\x\\a.txt", "explorer", "removable_media")).is_some());
        assert!(e.evaluate(&ctx("C:\\x\\a.txt", "explorer", "file_write")).is_none());
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
        assert!(e.evaluate(&ctx("C:\\Users\\bob\\doc.txt", "notepad.exe", "file_write")).is_some());
        assert!(e.evaluate(&ctx("D:\\other\\doc.txt", "notepad.exe", "file_write")).is_none());
        assert!(e.evaluate(&ctx("C:\\Users\\bob\\doc.txt", "explorer.exe", "file_write")).is_none());
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
        assert!(e.evaluate(&ctx("C:\\Users\\bob\\doc.txt", "x", "file_write")).is_some());
        assert!(e.evaluate(&ctx("C:\\Users\\bob\\excluded\\secret.txt", "x", "file_write")).is_none());
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
            vec![mk("low-prio", 100, "removable_media"), mk("high-prio", 1, "removable_media")],
            None,
            None,
            None,
        );
        let m = e.evaluate(&ctx("E:\\a.txt", "x", "removable_media")).expect("match");
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
            user: Some("budi.s"),
        };
        let missing = DlpEvalContext {
            user: None,
            ..matching
        };
        assert!(e.evaluate(&matching).is_some());
        assert!(e.evaluate(&missing).is_none());
    }
}
