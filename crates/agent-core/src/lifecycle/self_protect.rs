use anyhow::Result;
use serde_json::json;
use tracing::warn;

use grpc_client::EventEnvelope;
use self_protect::SelfProtectReport;

use super::{AgentRuntime, DegradedCause};

impl AgentRuntime {
    pub(crate) async fn run_self_protection_if_due(&mut self, now_unix: i64) -> Result<()> {
        if self.tamper_forced_degraded {
            return Ok(());
        }

        let interval = self.config.self_protection_integrity_check_interval_secs;
        if std::env::var("EGUARD_DEBUG_SELF_PROTECT_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            tracing::info!(
                interval_secs = interval,
                last_check = self.last_self_protect_check_unix,
                now_unix,
                integrity_paths = ?self.self_protect_engine.config().runtime_integrity_paths,
                config_paths = ?self.self_protect_engine.config().runtime_config_paths,
                "debug self-protect tick"
            );
        }
        if interval == 0 {
            return Ok(());
        }

        if let Some(last) = self.last_self_protect_check_unix {
            if now_unix.saturating_sub(last) < interval as i64 {
                return Ok(());
            }
        }
        self.last_self_protect_check_unix = Some(now_unix);

        let report = self.self_protect_engine.evaluate();
        if std::env::var("EGUARD_DEBUG_SELF_PROTECT_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            tracing::info!(
                clean = report.is_clean(),
                violations = ?report.violation_codes(),
                tampered_paths = ?report.tampered_paths(),
                "debug self-protect report"
            );
        }
        if report.is_clean() {
            return Ok(());
        }

        self.handle_self_protection_violation(now_unix, &report)
            .await
    }

    pub(super) async fn handle_self_protection_violation(
        &mut self,
        now_unix: i64,
        report: &SelfProtectReport,
    ) -> Result<()> {
        if self.tamper_forced_degraded {
            return Ok(());
        }

        let alert = EventEnvelope {
            agent_id: self.config.agent_id.clone(),
            event_type: "alert".to_string(),
            severity: "critical".to_string(),
            rule_name: "agent_tamper".to_string(),
            payload_json: self.self_protect_alert_payload(report, now_unix),
            created_at_unix: now_unix,
        };

        if self.client.is_online() {
            if let Err(err) = self.client.send_events(std::slice::from_ref(&alert)).await {
                warn!(
                    error = %err,
                    pending = self.buffer.pending_count(),
                    "failed sending self-protect alert; buffering locally"
                );
                self.buffer.enqueue(alert)?;
            }
        } else {
            self.buffer.enqueue(alert)?;
        }

        self.tamper_forced_degraded = true;
        self.transition_to_degraded(DegradedCause::SelfProtection);
        warn!(
            violations = ?report.violation_codes(),
            summary = %report.summary(),
            "self-protection violation detected; forcing degraded mode"
        );

        Ok(())
    }

    pub(super) fn self_protect_alert_payload(
        &self,
        report: &SelfProtectReport,
        now_unix: i64,
    ) -> String {
        let tampered_paths = report.tampered_paths();
        let tamper_indicators: Vec<String> = tampered_paths
            .iter()
            .map(|path| format!("self_protect:{}", path))
            .collect();
        json!({
            "rule_name": "agent_tamper",
            "severity": "critical",
            "timestamp": now_unix,
            "violations": report.violation_codes(),
            "tampered_paths": tampered_paths,
            "tamper_indicators": tamper_indicators,
            "detail": report.summary(),
        })
        .to_string()
    }
}
