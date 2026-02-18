use std::collections::HashMap;
use std::sync::OnceLock;

use tracing::{info, warn};

use compliance::{
    collect_linux_snapshot, evaluate, evaluate_snapshot, execute_remediation_actions,
    plan_remediation_actions, ComplianceCheck, ComplianceResult, RemediationAction,
    ShellCommandRunner,
};
use nac::Posture;
use serde::Deserialize;

use super::{interval_due, now_unix, remediation_check_type, AgentRuntime, COMPLIANCE_INTERVAL_SECS};

impl AgentRuntime {
    pub(super) fn log_posture(&self, posture: Posture) {
        info!(?posture, "computed nac posture");
    }

    pub(super) fn evaluate_compliance(&mut self) -> ComplianceResult {
        let now_unix = now_unix();
        if let (Some(last_checked), Some(cached)) =
            (self.last_compliance_checked_unix, self.last_compliance_result.as_ref())
        {
            if !interval_due(Some(last_checked), now_unix, self.compliance_interval_secs()) {
                return cached.clone();
            }
        }

        self.last_compliance_remediations.clear();
        let snapshot = match collect_linux_snapshot() {
            Ok(snapshot) => snapshot,
            Err(err) => {
                warn!(error = %err, "linux compliance probe failed, using minimal fallback checks");
                let fallback = evaluate(&self.compliance_policy, true, "unknown");
                self.last_compliance_checked_unix = Some(now_unix);
                self.last_compliance_result = Some(fallback.clone());
                return fallback;
            }
        };

        let mut result = evaluate_snapshot(&self.compliance_policy, &snapshot);
        self.apply_compliance_grace(now_unix, &mut result);

        let auto_remediate = self.config.compliance_auto_remediate
            && self.compliance_policy.auto_remediate.unwrap_or(false)
            && !self
                .compliance_policy
                .remediation_mode
                .as_deref()
                .unwrap_or("auto")
                .eq_ignore_ascii_case("approve");
        if auto_remediate {
            let actions = plan_remediation_actions(&self.compliance_policy, &snapshot);
            let actions = filter_remediation_allowlist(actions);
            if !actions.is_empty() {
                let runner = ShellCommandRunner;
                let outcomes = execute_remediation_actions(&runner, &actions);
                for outcome in &outcomes {
                    let key = remediation_check_type(&outcome.action_id)
                        .unwrap_or_else(|| outcome.action_id.clone());
                    self.last_compliance_remediations
                        .insert(key, outcome.clone());
                }
                self.apply_remediation_outcomes(&mut result, &outcomes);

                if outcomes.iter().any(|o| o.success) {
                    if let Ok(snapshot_after) = collect_linux_snapshot() {
                        result = evaluate_snapshot(&self.compliance_policy, &snapshot_after);
                        self.apply_compliance_grace(now_unix, &mut result);
                        self.apply_remediation_outcomes(&mut result, &outcomes);
                    }
                }
            }
        }

        self.last_compliance_checked_unix = Some(now_unix);
        self.last_compliance_result = Some(result.clone());
        result
    }

    pub(super) fn compliance_interval_secs(&self) -> i64 {
        let policy_interval = self
            .compliance_policy
            .check_interval_secs
            .unwrap_or(self.config.compliance_check_interval_secs);
        if policy_interval == 0 {
            COMPLIANCE_INTERVAL_SECS
        } else {
            policy_interval as i64
        }
    }

    fn apply_compliance_grace(&mut self, now_unix: i64, result: &mut ComplianceResult) {
        let default_grace = self.compliance_policy.grace_period_secs.unwrap_or(0) as i64;
        for check in result.checks.iter_mut() {
            if check.status == "non_compliant" {
                let grace_secs = if check.grace_period_secs > 0 {
                    check.grace_period_secs as i64
                } else {
                    default_grace
                };
                if grace_secs > 0 {
                    let entry = self
                        .compliance_grace_state
                        .entry(check.check_id.clone())
                        .or_insert(now_unix);
                    let expires = *entry + grace_secs;
                    check.grace_expires_at_unix = expires;
                    if now_unix < expires {
                        check.status = "in_grace".to_string();
                    }
                }
            } else {
                self.compliance_grace_state.remove(&check.check_id);
                check.grace_expires_at_unix = 0;
            }
        }

        update_overall_status(result);
    }

    fn apply_remediation_outcomes(
        &mut self,
        result: &mut ComplianceResult,
        outcomes: &[compliance::RemediationOutcome],
    ) {
        let mut outcome_map = HashMap::new();
        for outcome in outcomes {
            outcome_map.insert(outcome.action_id.as_str(), outcome);
        }

        for check in result.checks.iter_mut() {
            if let Some(outcome) = outcome_map
                .get(check.check_id.as_str())
                .or_else(|| outcome_map.get(check.check_type.as_str()))
            {
                check.auto_remediated = outcome.success;
                check.remediation_action_id = outcome.action_id.clone();
                check.remediation_detail = outcome.detail.clone();
            }
        }
    }
}

fn update_overall_status(result: &mut ComplianceResult) {
    let failed = result
        .checks
        .iter()
        .filter(|c| c.status == "non_compliant")
        .count();
    let errored = result
        .checks
        .iter()
        .filter(|c| c.status == "error")
        .count();
    let in_grace = result
        .checks
        .iter()
        .filter(|c| c.status == "in_grace")
        .count();

    if failed > 0 {
        let failed_checks = result
            .checks
            .iter()
            .filter(|c| c.status == "non_compliant")
            .map(|c| c.check_id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        result.status = "non_compliant".to_string();
        result.detail = format!("{} check(s) failed: {}", failed, failed_checks);
    } else if errored > 0 {
        result.status = "error".to_string();
        result.detail = format!("{} check(s) errored", errored);
    } else if in_grace > 0 {
        result.status = "compliant".to_string();
        result.detail = format!("{} check(s) in grace", in_grace);
    } else {
        result.status = "compliant".to_string();
        result.detail = "policy checks passed".to_string();
    }
}

fn filter_remediation_allowlist(actions: Vec<RemediationAction>) -> Vec<RemediationAction> {
    let allowlist = remediation_allowlist();
    actions
        .into_iter()
        .filter(|action| {
            if action.allowlist_id.trim().is_empty() {
                return true;
            }
            allowlist
                .get(action.allowlist_id.as_str())
                .map(|allowed| {
                    allowed.iter().any(|entry| {
                        entry.command == action.command && entry.args == action.args
                    })
                })
                .unwrap_or(false)
        })
        .collect()
}

#[derive(Debug, Deserialize, Default)]
struct RemediationAllowlistConfig {
    #[serde(default)]
    allowlists: HashMap<String, Vec<RemediationAllowlistEntry>>,
}

#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq)]
struct RemediationAllowlistEntry {
    #[serde(default)]
    command: String,
    #[serde(default)]
    args: Vec<String>,
}

fn remediation_allowlist() -> &'static HashMap<String, Vec<RemediationAllowlistEntry>> {
    static CACHE: OnceLock<HashMap<String, Vec<RemediationAllowlistEntry>>> = OnceLock::new();
    CACHE.get_or_init(load_remediation_allowlist)
}

fn load_remediation_allowlist() -> HashMap<String, Vec<RemediationAllowlistEntry>> {
    let raw = if let Ok(value) = std::env::var("EGUARD_MDM_REMEDIATION_ALLOWLIST_JSON") {
        value
    } else if let Ok(path) = std::env::var("EGUARD_MDM_REMEDIATION_ALLOWLIST_PATH") {
        std::fs::read_to_string(path).unwrap_or_default()
    } else {
        String::new()
    };

    if raw.trim().is_empty() {
        return HashMap::new();
    }

    if let Ok(config) = serde_json::from_str::<RemediationAllowlistConfig>(&raw) {
        if !config.allowlists.is_empty() {
            return config.allowlists;
        }
    }

    match serde_json::from_str::<HashMap<String, Vec<RemediationAllowlistEntry>>>(&raw) {
        Ok(map) => map,
        Err(_) => HashMap::new(),
    }
}
