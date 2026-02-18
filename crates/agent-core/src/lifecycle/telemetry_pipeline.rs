use std::time::Instant;

use anyhow::Result;
use serde_json::json;
use tracing::{info, warn};

use super::{
    compute_poll_timeout, compute_sampling_stride, elapsed_micros, AgentRuntime, DegradedCause,
    EventEnvelope, RawEvent, TickEvaluation, DEGRADE_AFTER_SEND_FAILURES, EVENT_BATCH_SIZE,
};

impl AgentRuntime {
    pub(super) async fn run_connected_telemetry_stage(
        &mut self,
        evaluation: Option<&TickEvaluation>,
    ) -> Result<()> {
        let Some(evaluation) = evaluation else {
            return Ok(());
        };

        let send_batch_started = Instant::now();
        self.send_event_batch(evaluation.event_envelope.clone())
            .await?;

        let compliance_alerts =
            self.collect_compliance_alerts(&evaluation.compliance, evaluation.event_envelope.created_at_unix);
        for alert in compliance_alerts {
            self.send_event_batch(alert).await?;
        }

        self.metrics.last_send_event_batch_micros = elapsed_micros(send_batch_started);
        Ok(())
    }

    pub(super) async fn send_event_batch(&mut self, envelope: EventEnvelope) -> Result<()> {
        let send_started = Instant::now();
        let pending_before = self.buffer.pending_count();
        let mut batch = self.buffer.drain_batch(EVENT_BATCH_SIZE)?;
        batch.push(envelope);

        if let Err(err) = self.client.send_events(&batch).await {
            for ev in batch {
                self.buffer.enqueue(ev)?;
            }

            self.consecutive_send_failures = self.consecutive_send_failures.saturating_add(1);
            if self.consecutive_send_failures >= DEGRADE_AFTER_SEND_FAILURES {
                self.transition_to_degraded(DegradedCause::SendFailures);
            }

            warn!(
                error = %err,
                pending = self.buffer.pending_count(),
                "send failed, events re-buffered"
            );
        } else {
            self.consecutive_send_failures = 0;
            if std::env::var("EGUARD_DEBUG_OFFLINE_LOG")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .is_some()
            {
                info!(
                    pending_before,
                    pending_after = self.buffer.pending_count(),
                    sent = batch.len(),
                    "offline buffer flushed"
                );
            }
        }

        self.metrics.last_send_event_batch_micros = elapsed_micros(send_started);
        Ok(())
    }

    pub(super) fn collect_compliance_alerts(
        &mut self,
        compliance: &super::ComplianceResult,
        now_unix: i64,
    ) -> Vec<EventEnvelope> {
        let mut alerts = Vec::new();
        let policy_key = format!(
            "{}:{}:{}",
            self.compliance_policy_id,
            self.compliance_policy_version,
            self.compliance_policy_hash
        );

        for check in &compliance.checks {
            let key = format!("{}:{}", policy_key, check.check_id);
            if check.status == "non_compliant" {
                if !self.compliance_alert_state.contains_key(&key) {
                    self.compliance_alert_state.insert(key.clone(), now_unix);
                    alerts.push(self.build_compliance_alert_envelope(check, now_unix));
                }
            } else {
                self.compliance_alert_state.remove(&key);
            }
        }

        alerts
    }

    fn build_compliance_alert_envelope(
        &self,
        check: &compliance::ComplianceCheck,
        now_unix: i64,
    ) -> EventEnvelope {
        let severity = normalize_severity(&check.severity);
        let payload_json = json!({
            "observed_at_unix": now_unix,
            "mdm": {
                "policy_id": self.compliance_policy_id,
                "policy_version": self.compliance_policy_version,
                "policy_hash": self.compliance_policy_hash,
                "check_id": check.check_id,
                "check_type": check.check_type,
                "status": check.status,
                "severity": check.severity,
                "expected_value": check.expected_value,
                "actual_value": check.actual_value,
                "evidence_json": check.evidence_json,
                "evidence_source": check.evidence_source,
                "grace_expires_at_unix": check.grace_expires_at_unix,
                "remediation_action_id": check.remediation_action_id,
                "remediation_detail": check.remediation_detail,
            },
            "detection": {
                "rule_type": "mdm",
                "detection_layers": ["MDM_compliance"],
                "severity": severity,
            },
            "audit": {
                "primary_rule_name": check.check_id,
                "rule_type": "mdm",
                "detection_layers": ["MDM_compliance"],
                "matched_fields": {
                    "policy_id": self.compliance_policy_id,
                    "policy_version": self.compliance_policy_version,
                    "policy_hash": self.compliance_policy_hash,
                    "check_id": check.check_id,
                    "expected_value": check.expected_value,
                    "actual_value": check.actual_value,
                }
            }
        })
        .to_string();

        EventEnvelope {
            agent_id: self.config.agent_id.clone(),
            event_type: "alert".to_string(),
            severity: severity.to_string(),
            rule_name: check.check_id.clone(),
            payload_json,
            created_at_unix: now_unix,
        }
    }

    pub(super) fn next_raw_event(&mut self) -> Option<RawEvent> {
        let timeout = self.adaptive_poll_timeout();
        let sampling_stride =
            compute_sampling_stride(self.buffer.pending_count(), self.recent_ebpf_drops);
        let polled = self.ebpf_engine.poll_once(timeout);
        self.observe_ebpf_stats();

        match polled {
            Ok(events) => {
                if sampling_stride > 1 {
                    info!(
                        sampling_stride,
                        backlog = self.buffer.pending_count(),
                        recent_ebpf_drops = self.recent_ebpf_drops,
                        "applying statistical sampling due to backpressure"
                    );
                }
                events.into_iter().step_by(sampling_stride).next()
            }
            Err(err) => {
                warn!(error = %err, "eBPF poll failed; skipping telemetry event for this tick");
                None
            }
        }
    }

    fn adaptive_poll_timeout(&self) -> std::time::Duration {
        compute_poll_timeout(self.buffer.pending_count(), self.recent_ebpf_drops)
    }

    fn observe_ebpf_stats(&mut self) {
        let stats = self.ebpf_engine.stats();
        self.recent_ebpf_drops = stats
            .events_dropped
            .saturating_sub(self.last_ebpf_stats.events_dropped);
        self.last_ebpf_stats = stats;
    }
}

fn normalize_severity(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "low" => "low",
        "medium" | "med" => "medium",
        "high" => "high",
        "critical" => "critical",
        _ => "medium",
    }
}
