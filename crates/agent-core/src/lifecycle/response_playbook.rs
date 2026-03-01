//! Automated Response Playbooks
//!
//! Enables conditional multi-step responses based on detection signals.
//! Example: "if ransomware indicators + high confidence -> kill process,
//! quarantine file, isolate host, notify server"

use serde::Deserialize;
use tracing::info;

use detection::{Confidence, DetectionOutcome, DetectionSignals, TelemetryEvent};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single condition that must be true for the playbook to trigger.
#[derive(Debug, Clone, Deserialize)]
pub struct PlaybookCondition {
    /// Minimum confidence level: "medium", "high", "very_high", "definite"
    pub min_confidence: Option<String>,
    /// Required detection signals (all must be true).
    pub require_signals: Vec<String>,
    /// Required event class: "process_exec", "file_open", "network_connect", etc.
    pub event_class: Option<String>,
}

/// A response action in the playbook.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PlaybookAction {
    /// Action type: "kill", "quarantine", "isolate", "alert", "capture", "log"
    pub action: String,
    /// Optional delay before execution (seconds).
    pub delay_secs: Option<u64>,
}

/// A complete playbook rule.
#[derive(Debug, Clone, Deserialize)]
pub struct PlaybookRule {
    pub name: String,
    pub enabled: bool,
    /// Lower number = higher priority (evaluated first).
    pub priority: u32,
    pub conditions: PlaybookCondition,
    pub actions: Vec<PlaybookAction>,
}

// ---------------------------------------------------------------------------
// PlaybookEngine
// ---------------------------------------------------------------------------

/// The playbook engine that evaluates rules against detection outcomes.
pub struct PlaybookEngine {
    rules: Vec<PlaybookRule>,
}

impl PlaybookEngine {
    /// Create an empty engine with no rules.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Load the built-in default playbooks.
    pub fn load_default_playbooks(&mut self) {
        let defaults = default_playbooks();
        info!(
            playbook_count = defaults.len(),
            "loaded default response playbooks"
        );
        self.rules.extend(defaults);
        self.sort_rules();
    }

    /// Load playbooks from a server policy JSON.
    ///
    /// Expects `policy_json["response_playbooks"]` to be an array of
    /// [`PlaybookRule`] objects. Existing rules are replaced.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn load_from_policy(&mut self, policy_json: &serde_json::Value) {
        let Some(arr) = policy_json.get("response_playbooks") else {
            return;
        };

        match serde_json::from_value::<Vec<PlaybookRule>>(arr.clone()) {
            Ok(rules) => {
                info!(
                    playbook_count = rules.len(),
                    "loaded response playbooks from policy"
                );
                self.rules = rules;
                self.sort_rules();
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to deserialize response_playbooks from policy; keeping existing rules"
                );
            }
        }
    }

    /// Evaluate all enabled rules against a detection outcome and event.
    ///
    /// Returns an ordered list of actions from the *first* matching rule
    /// (rules are sorted by priority -- lower number first).
    pub fn evaluate(
        &self,
        outcome: &DetectionOutcome,
        event: &TelemetryEvent,
    ) -> Vec<PlaybookAction> {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if matches_condition(&rule.conditions, outcome, event) {
                info!(
                    playbook = %rule.name,
                    action_count = rule.actions.len(),
                    "playbook matched"
                );
                return rule.actions.clone();
            }
        }
        Vec::new()
    }

    /// Return a reference to the loaded rules (useful for tests/observability).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn rules(&self) -> &[PlaybookRule] {
        &self.rules
    }

    /// Keep rules sorted by priority (ascending -- lower number = higher priority).
    fn sort_rules(&mut self) {
        self.rules.sort_by_key(|r| r.priority);
    }
}

// ---------------------------------------------------------------------------
// Condition matching
// ---------------------------------------------------------------------------

/// Check whether a condition matches the given detection outcome and event.
pub fn matches_condition(
    condition: &PlaybookCondition,
    outcome: &DetectionOutcome,
    event: &TelemetryEvent,
) -> bool {
    // 1. Minimum confidence gate
    if let Some(ref label) = condition.min_confidence {
        let required = parse_confidence(label);
        if outcome.confidence < required {
            return false;
        }
    }

    // 2. All required signals must be true
    for signal_name in &condition.require_signals {
        if !signal_value(&outcome.signals, signal_name) {
            return false;
        }
    }

    // 3. Event class filter
    if let Some(ref required_class) = condition.event_class {
        if event.event_class.as_str() != required_class.as_str() {
            return false;
        }
    }

    true
}

/// Map a signal name string to the corresponding boolean field on
/// [`DetectionSignals`]. Unknown names return `false`.
fn signal_value(signals: &DetectionSignals, name: &str) -> bool {
    match name {
        "z1_exact_ioc" => signals.z1_exact_ioc,
        "yara_hit" => signals.yara_hit,
        "z2_temporal" => signals.z2_temporal,
        "z3_anomaly_high" => signals.z3_anomaly_high,
        "z3_anomaly_med" => signals.z3_anomaly_med,
        "z4_kill_chain" => signals.z4_kill_chain,
        "l1_prefilter_hit" => signals.l1_prefilter_hit,
        "exploit_indicator" => signals.exploit_indicator,
        "kernel_integrity" => signals.kernel_integrity,
        "tamper_indicator" => signals.tamper_indicator,
        "c2_beaconing_detected" => signals.c2_beaconing_detected,
        "process_tree_anomaly" => signals.process_tree_anomaly,
        "campaign_correlated" => signals.campaign_correlated,
        "network_ioc_hit" => signals.network_ioc_hit,
        "vulnerable_software" => signals.vulnerable_software,
        _ => {
            // Unknown signal names (e.g. future additions like "fim_violation")
            // gracefully evaluate to false so they don't block other conditions.
            false
        }
    }
}

/// Parse a confidence label string into the [`Confidence`] enum.
fn parse_confidence(label: &str) -> Confidence {
    match label {
        "none" => Confidence::None,
        "low" => Confidence::Low,
        "medium" => Confidence::Medium,
        "high" => Confidence::High,
        "very_high" => Confidence::VeryHigh,
        "definite" => Confidence::Definite,
        _ => Confidence::None,
    }
}

// ---------------------------------------------------------------------------
// Default playbooks
// ---------------------------------------------------------------------------

fn default_playbooks() -> Vec<PlaybookRule> {
    vec![
        // Ransomware: kill + quarantine + alert
        PlaybookRule {
            name: "ransomware_response".into(),
            enabled: true,
            priority: 1,
            conditions: PlaybookCondition {
                min_confidence: Some("high".into()),
                require_signals: vec!["z1_exact_ioc".into(), "yara_hit".into()],
                event_class: Some("process_exec".into()),
            },
            actions: vec![
                PlaybookAction {
                    action: "kill".into(),
                    delay_secs: None,
                },
                PlaybookAction {
                    action: "quarantine".into(),
                    delay_secs: None,
                },
                PlaybookAction {
                    action: "alert".into(),
                    delay_secs: None,
                },
            ],
        },
        // C2 beaconing: alert + capture network details
        PlaybookRule {
            name: "c2_beaconing_response".into(),
            enabled: true,
            priority: 2,
            conditions: PlaybookCondition {
                min_confidence: Some("medium".into()),
                require_signals: vec!["c2_beaconing_detected".into()],
                event_class: None,
            },
            actions: vec![
                PlaybookAction {
                    action: "alert".into(),
                    delay_secs: None,
                },
                PlaybookAction {
                    action: "capture".into(),
                    delay_secs: None,
                },
            ],
        },
        // Vulnerable software exploitation attempt
        PlaybookRule {
            name: "cve_exploit_response".into(),
            enabled: true,
            priority: 3,
            conditions: PlaybookCondition {
                min_confidence: Some("high".into()),
                require_signals: vec!["vulnerable_software".into(), "exploit_indicator".into()],
                event_class: None,
            },
            actions: vec![
                PlaybookAction {
                    action: "kill".into(),
                    delay_secs: None,
                },
                PlaybookAction {
                    action: "quarantine".into(),
                    delay_secs: None,
                },
                PlaybookAction {
                    action: "alert".into(),
                    delay_secs: None,
                },
            ],
        },
        // Campaign-correlated threat: full response
        PlaybookRule {
            name: "campaign_threat_response".into(),
            enabled: true,
            priority: 1,
            conditions: PlaybookCondition {
                min_confidence: Some("very_high".into()),
                require_signals: vec!["campaign_correlated".into()],
                event_class: None,
            },
            actions: vec![
                PlaybookAction {
                    action: "kill".into(),
                    delay_secs: None,
                },
                PlaybookAction {
                    action: "quarantine".into(),
                    delay_secs: None,
                },
                PlaybookAction {
                    action: "isolate".into(),
                    delay_secs: Some(5),
                },
                PlaybookAction {
                    action: "alert".into(),
                    delay_secs: None,
                },
            ],
        },
        // FIM violation: alert + capture
        // NOTE: The "fim_violation" signal is a placeholder for a future
        // DetectionSignals field. Until added, this playbook will not trigger.
        PlaybookRule {
            name: "fim_violation_response".into(),
            enabled: true,
            priority: 4,
            conditions: PlaybookCondition {
                min_confidence: Some("high".into()),
                require_signals: vec!["fim_violation".into()],
                event_class: None,
            },
            actions: vec![
                PlaybookAction {
                    action: "alert".into(),
                    delay_secs: None,
                },
                PlaybookAction {
                    action: "capture".into(),
                    delay_secs: None,
                },
            ],
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use detection::{EventClass, TelemetryEvent};

    fn make_event(event_class: EventClass) -> TelemetryEvent {
        TelemetryEvent {
            ts_unix: 1_700_000_000,
            event_class,
            pid: 1234,
            ppid: 1,
            uid: 0,
            process: "malware".into(),
            parent_process: "bash".into(),
            session_id: 1,
            file_path: Some("/tmp/evil.bin".into()),
            file_write: false,
            file_hash: Some("abc123".into()),
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: None,
            event_size: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        }
    }

    fn make_outcome(confidence: Confidence, signals: DetectionSignals) -> DetectionOutcome {
        DetectionOutcome {
            confidence,
            signals,
            temporal_hits: Vec::new(),
            kill_chain_hits: Vec::new(),
            exploit_indicators: Vec::new(),
            kernel_integrity_indicators: Vec::new(),
            tamper_indicators: Vec::new(),
            yara_hits: Vec::new(),
            anomaly: None,
            layer1: detection::Layer1EventHit::default(),
            ml_score: None,
            behavioral_alarms: Vec::new(),
        }
    }

    #[test]
    fn ransomware_playbook_matches_on_high_confidence_with_signals() {
        let mut engine = PlaybookEngine::new();
        engine.load_default_playbooks();

        let mut signals = DetectionSignals::default();
        signals.z1_exact_ioc = true;
        signals.yara_hit = true;

        let outcome = make_outcome(Confidence::High, signals);
        let event = make_event(EventClass::ProcessExec);

        let actions = engine.evaluate(&outcome, &event);
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0].action, "kill");
        assert_eq!(actions[1].action, "quarantine");
        assert_eq!(actions[2].action, "alert");
    }

    #[test]
    fn ransomware_playbook_does_not_match_on_low_confidence() {
        let mut engine = PlaybookEngine::new();
        engine.load_default_playbooks();

        let mut signals = DetectionSignals::default();
        signals.z1_exact_ioc = true;
        signals.yara_hit = true;

        let outcome = make_outcome(Confidence::Low, signals);
        let event = make_event(EventClass::ProcessExec);

        let actions = engine.evaluate(&outcome, &event);
        assert!(
            actions.is_empty(),
            "ransomware playbook should not match with Low confidence"
        );
    }

    #[test]
    fn ransomware_playbook_requires_correct_event_class() {
        let mut engine = PlaybookEngine::new();
        engine.load_default_playbooks();

        let mut signals = DetectionSignals::default();
        signals.z1_exact_ioc = true;
        signals.yara_hit = true;

        let outcome = make_outcome(Confidence::High, signals);
        // NetworkConnect event should not match the ransomware playbook
        // which requires process_exec
        let event = make_event(EventClass::NetworkConnect);

        let actions = engine.evaluate(&outcome, &event);
        // The ransomware playbook (priority 1) requires process_exec, so it
        // won't match. No other priority-1+ playbook should match these signals
        // without campaign_correlated being set, so we expect no match.
        assert!(
            actions.is_empty(),
            "ransomware playbook requires process_exec event class"
        );
    }

    #[test]
    fn c2_beaconing_playbook_matches() {
        let mut engine = PlaybookEngine::new();
        engine.load_default_playbooks();

        let mut signals = DetectionSignals::default();
        signals.c2_beaconing_detected = true;

        let outcome = make_outcome(Confidence::Medium, signals);
        let event = make_event(EventClass::NetworkConnect);

        let actions = engine.evaluate(&outcome, &event);
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].action, "alert");
        assert_eq!(actions[1].action, "capture");
    }

    #[test]
    fn priority_ordering_higher_priority_wins() {
        let mut engine = PlaybookEngine::new();
        engine.load_default_playbooks();

        // campaign_threat_response has priority 1 and requires campaign_correlated + very_high
        // ransomware_response has priority 1 and requires z1_exact_ioc + yara_hit + process_exec
        // Both have priority 1 -- campaign is loaded after ransomware in defaults,
        // but with the same priority the stable sort preserves order.
        // Let's trigger the campaign playbook specifically.
        let mut signals = DetectionSignals::default();
        signals.campaign_correlated = true;

        let outcome = make_outcome(Confidence::VeryHigh, signals);
        let event = make_event(EventClass::ProcessExec);

        let actions = engine.evaluate(&outcome, &event);
        // campaign_threat_response includes an "isolate" action with delay
        assert!(
            actions.len() == 4,
            "campaign playbook should produce 4 actions, got {}",
            actions.len()
        );
        assert_eq!(actions[0].action, "kill");
        assert_eq!(actions[1].action, "quarantine");
        assert_eq!(actions[2].action, "isolate");
        assert_eq!(actions[2].delay_secs, Some(5));
        assert_eq!(actions[3].action, "alert");
    }

    #[test]
    fn empty_signals_match_no_playbook() {
        let mut engine = PlaybookEngine::new();
        engine.load_default_playbooks();

        let signals = DetectionSignals::default();
        let outcome = make_outcome(Confidence::None, signals);
        let event = make_event(EventClass::ProcessExec);

        let actions = engine.evaluate(&outcome, &event);
        assert!(
            actions.is_empty(),
            "no playbook should match with all-default signals"
        );
    }

    #[test]
    fn custom_playbook_from_json_deserialization() {
        let json = serde_json::json!({
            "response_playbooks": [
                {
                    "name": "custom_test",
                    "enabled": true,
                    "priority": 1,
                    "conditions": {
                        "min_confidence": "medium",
                        "require_signals": ["z1_exact_ioc"],
                        "event_class": null
                    },
                    "actions": [
                        { "action": "log", "delay_secs": null },
                        { "action": "alert", "delay_secs": 10 }
                    ]
                }
            ]
        });

        let mut engine = PlaybookEngine::new();
        engine.load_from_policy(&json);

        assert_eq!(engine.rules().len(), 1);
        assert_eq!(engine.rules()[0].name, "custom_test");
        assert_eq!(engine.rules()[0].actions.len(), 2);
        assert_eq!(engine.rules()[0].actions[1].delay_secs, Some(10));

        // Verify it actually matches
        let mut signals = DetectionSignals::default();
        signals.z1_exact_ioc = true;
        let outcome = make_outcome(Confidence::High, signals);
        let event = make_event(EventClass::FileOpen);

        let actions = engine.evaluate(&outcome, &event);
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].action, "log");
        assert_eq!(actions[1].action, "alert");
    }

    #[test]
    fn disabled_playbook_is_skipped() {
        let json = serde_json::json!({
            "response_playbooks": [
                {
                    "name": "disabled_rule",
                    "enabled": false,
                    "priority": 1,
                    "conditions": {
                        "min_confidence": null,
                        "require_signals": [],
                        "event_class": null
                    },
                    "actions": [
                        { "action": "kill", "delay_secs": null }
                    ]
                }
            ]
        });

        let mut engine = PlaybookEngine::new();
        engine.load_from_policy(&json);

        let outcome = make_outcome(Confidence::Definite, DetectionSignals::default());
        let event = make_event(EventClass::ProcessExec);

        let actions = engine.evaluate(&outcome, &event);
        assert!(actions.is_empty(), "disabled rule should not match");
    }

    #[test]
    fn cve_exploit_playbook_matches_on_both_signals() {
        let mut engine = PlaybookEngine::new();
        engine.load_default_playbooks();

        let mut signals = DetectionSignals::default();
        signals.vulnerable_software = true;
        signals.exploit_indicator = true;

        let outcome = make_outcome(Confidence::High, signals);
        let event = make_event(EventClass::ProcessExec);

        let actions = engine.evaluate(&outcome, &event);
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0].action, "kill");
        assert_eq!(actions[1].action, "quarantine");
        assert_eq!(actions[2].action, "alert");
    }

    #[test]
    fn cve_exploit_playbook_does_not_match_with_only_one_signal() {
        let mut engine = PlaybookEngine::new();
        engine.load_default_playbooks();

        let mut signals = DetectionSignals::default();
        signals.vulnerable_software = true;
        // exploit_indicator is false

        let outcome = make_outcome(Confidence::High, signals);
        let event = make_event(EventClass::ProcessExec);

        let actions = engine.evaluate(&outcome, &event);
        assert!(
            actions.is_empty(),
            "cve_exploit_response requires both vulnerable_software and exploit_indicator"
        );
    }

    #[test]
    fn empty_engine_returns_no_actions() {
        let engine = PlaybookEngine::new();
        let outcome = make_outcome(Confidence::Definite, DetectionSignals::default());
        let event = make_event(EventClass::ProcessExec);

        let actions = engine.evaluate(&outcome, &event);
        assert!(actions.is_empty());
    }

    #[test]
    fn policy_load_with_invalid_json_preserves_existing_rules() {
        let mut engine = PlaybookEngine::new();
        engine.load_default_playbooks();
        let original_count = engine.rules().len();

        let bad_json = serde_json::json!({
            "response_playbooks": "not_an_array"
        });
        engine.load_from_policy(&bad_json);

        assert_eq!(
            engine.rules().len(),
            original_count,
            "invalid policy should not remove existing rules"
        );
    }

    #[test]
    fn policy_load_without_playbooks_key_is_noop() {
        let mut engine = PlaybookEngine::new();
        engine.load_default_playbooks();
        let original_count = engine.rules().len();

        let json = serde_json::json!({ "some_other_key": 42 });
        engine.load_from_policy(&json);

        assert_eq!(engine.rules().len(), original_count);
    }

    #[test]
    fn parse_confidence_handles_all_levels() {
        assert_eq!(parse_confidence("none"), Confidence::None);
        assert_eq!(parse_confidence("low"), Confidence::Low);
        assert_eq!(parse_confidence("medium"), Confidence::Medium);
        assert_eq!(parse_confidence("high"), Confidence::High);
        assert_eq!(parse_confidence("very_high"), Confidence::VeryHigh);
        assert_eq!(parse_confidence("definite"), Confidence::Definite);
        assert_eq!(parse_confidence("unknown_label"), Confidence::None);
    }

    #[test]
    fn signal_value_maps_all_known_signals() {
        let mut signals = DetectionSignals::default();
        signals.z1_exact_ioc = true;
        signals.yara_hit = true;
        signals.c2_beaconing_detected = true;
        signals.vulnerable_software = true;
        signals.exploit_indicator = true;
        signals.campaign_correlated = true;
        signals.network_ioc_hit = true;
        signals.kernel_integrity = true;
        signals.tamper_indicator = true;

        assert!(signal_value(&signals, "z1_exact_ioc"));
        assert!(signal_value(&signals, "yara_hit"));
        assert!(signal_value(&signals, "c2_beaconing_detected"));
        assert!(signal_value(&signals, "vulnerable_software"));
        assert!(signal_value(&signals, "exploit_indicator"));
        assert!(signal_value(&signals, "campaign_correlated"));
        assert!(signal_value(&signals, "network_ioc_hit"));
        assert!(signal_value(&signals, "kernel_integrity"));
        assert!(signal_value(&signals, "tamper_indicator"));

        // Unknown signal
        assert!(!signal_value(&signals, "fim_violation"));
        assert!(!signal_value(&signals, "nonexistent"));
    }
}
