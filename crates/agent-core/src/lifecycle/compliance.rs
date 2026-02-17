use tracing::{info, warn};

use compliance::{
    collect_linux_snapshot, evaluate, evaluate_snapshot, execute_remediation_actions,
    plan_remediation_actions, ComplianceResult, ShellCommandRunner,
};
use nac::Posture;

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

        let auto_remediate = self.config.compliance_auto_remediate
            && self.compliance_policy.auto_remediate.unwrap_or(false);
        if auto_remediate {
            let actions = plan_remediation_actions(&self.compliance_policy, &snapshot);
            if !actions.is_empty() {
                let runner = ShellCommandRunner;
                let outcomes = execute_remediation_actions(&runner, &actions);
                for outcome in &outcomes {
                    if let Some(check_type) = remediation_check_type(&outcome.action_id) {
                        self.last_compliance_remediations
                            .insert(check_type, outcome.clone());
                    }
                }

                if outcomes.iter().any(|o| o.success) {
                    if let Ok(snapshot_after) = collect_linux_snapshot() {
                        result = evaluate_snapshot(&self.compliance_policy, &snapshot_after);
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
}
