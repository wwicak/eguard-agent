use std::collections::HashSet;
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

        let compliance_alerts = self.collect_compliance_alerts(
            &evaluation.compliance,
            evaluation.event_envelope.created_at_unix,
        );
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
            self.compliance_policy_id, self.compliance_policy_version, self.compliance_policy_hash
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
        self.refresh_strict_budget_mode();
        let sampling_stride = self.sampling_stride();
        if let Some(event) = self.dequeue_sampled_raw_event(sampling_stride) {
            return Some(event);
        }

        let timeout = self.adaptive_poll_timeout();
        let polled = self.ebpf_engine.poll_once(timeout);
        self.observe_ebpf_stats();

        match polled {
            Ok(events) => {
                if events.is_empty() {
                    self.refresh_strict_budget_mode();
                    return None;
                }

                let before = events.len();
                let coalesced = self.coalesce_file_event_burst(events);
                let dropped = before.saturating_sub(coalesced.len());
                if dropped > 0 {
                    info!(
                        dropped,
                        retained = coalesced.len(),
                        window_ns = self.file_event_coalesce_window_ns,
                        "coalesced burst file events before deep analysis"
                    );
                }

                self.raw_event_backlog.extend(coalesced);
                self.enforce_raw_event_backlog_cap();
                self.refresh_strict_budget_mode();

                let stride = self.sampling_stride();
                if stride > 1 {
                    info!(
                        sampling_stride = stride,
                        backlog = self.telemetry_backlog_depth(),
                        recent_ebpf_drops = self.recent_ebpf_drops,
                        strict_budget_mode = self.strict_budget_mode,
                        "applying statistical sampling due to telemetry backpressure"
                    );
                }

                self.dequeue_sampled_raw_event(stride)
            }
            Err(err) => {
                warn!(error = %err, "eBPF poll failed; skipping telemetry event for this tick");
                None
            }
        }
    }

    fn telemetry_backlog_depth(&self) -> usize {
        self.buffer
            .pending_count()
            .saturating_add(self.raw_event_backlog.len())
    }

    fn refresh_strict_budget_mode(&mut self) {
        self.strict_budget_mode = self.buffer.pending_count()
            >= self.strict_budget_pending_threshold
            || self.raw_event_backlog.len() >= self.strict_budget_raw_backlog_threshold;
    }

    fn sampling_stride(&self) -> usize {
        compute_sampling_stride(self.telemetry_backlog_depth(), self.recent_ebpf_drops)
    }

    fn dequeue_sampled_raw_event(&mut self, stride: usize) -> Option<RawEvent> {
        if self.raw_event_backlog.is_empty() {
            return None;
        }

        let stride = stride.max(1);
        if stride > 1 {
            let available = self.raw_event_backlog.len();
            let skips = stride.saturating_sub(1).min(available.saturating_sub(1));
            for _ in 0..skips {
                let _ = self.raw_event_backlog.pop_front();
            }
        }

        self.raw_event_backlog.pop_front()
    }

    fn coalesce_file_event_burst(&mut self, events: Vec<RawEvent>) -> Vec<RawEvent> {
        if self.file_event_coalesce_window_ns == 0 {
            return events;
        }

        let mut output = Vec::with_capacity(events.len());
        let mut batch_seen = HashSet::new();

        for event in events {
            let key = Self::file_event_burst_key(&event);
            let Some(key) = key else {
                output.push(event);
                continue;
            };

            let event_ts = if event.ts_ns == 0 {
                unix_now_ns()
            } else {
                event.ts_ns
            };

            if !batch_seen.insert(key.clone()) {
                continue;
            }

            let should_drop = self
                .recent_file_event_keys
                .get(&key)
                .map(|prev_ts| {
                    event_ts.saturating_sub(*prev_ts) <= self.file_event_coalesce_window_ns
                })
                .unwrap_or(false);
            if should_drop {
                continue;
            }

            self.recent_file_event_keys.insert(key, event_ts);
            output.push(event);
        }

        self.prune_file_event_coalesce_state();
        output
    }

    fn prune_file_event_coalesce_state(&mut self) {
        if self.recent_file_event_keys.len() <= self.file_event_coalesce_key_limit {
            return;
        }

        let now_ns = unix_now_ns();
        let retention = self.file_event_coalesce_window_ns.saturating_mul(4);
        self.recent_file_event_keys
            .retain(|_, seen_ns| now_ns.saturating_sub(*seen_ns) <= retention);

        if self.recent_file_event_keys.len() > self.file_event_coalesce_key_limit.saturating_mul(2)
        {
            self.recent_file_event_keys.clear();
        }
    }

    fn enforce_raw_event_backlog_cap(&mut self) {
        if self.raw_event_backlog.len() <= self.raw_event_backlog_cap {
            return;
        }

        let overflow = self
            .raw_event_backlog
            .len()
            .saturating_sub(self.raw_event_backlog_cap);
        for _ in 0..overflow {
            let _ = self.raw_event_backlog.pop_front();
        }

        warn!(
            overflow,
            backlog_cap = self.raw_event_backlog_cap,
            backlog_after = self.raw_event_backlog.len(),
            "raw event backlog exceeded cap; dropped oldest events"
        );
    }

    fn file_event_burst_key(event: &RawEvent) -> Option<String> {
        match event.event_type {
            crate::platform::EventType::FileWrite | crate::platform::EventType::FileOpen => {
                parse_payload_path(&event.payload).map(|path| format!("write:{}", path))
            }
            crate::platform::EventType::FileRename => {
                let (src, dst) = parse_payload_rename_paths(&event.payload);
                if let Some(dst) = dst {
                    Some(format!("rename:{}", dst))
                } else {
                    src.map(|src| format!("rename:{}", src))
                }
            }
            crate::platform::EventType::FileUnlink => {
                parse_payload_path(&event.payload).map(|path| format!("unlink:{}", path))
            }
            _ => None,
        }
    }

    fn adaptive_poll_timeout(&self) -> std::time::Duration {
        compute_poll_timeout(self.telemetry_backlog_depth(), self.recent_ebpf_drops)
    }

    fn observe_ebpf_stats(&mut self) {
        let stats = self.ebpf_engine.stats();
        self.recent_ebpf_drops = stats
            .events_dropped
            .saturating_sub(self.last_ebpf_stats.events_dropped);
        self.last_ebpf_stats = stats;
    }
}

fn parse_payload_field(payload: &str, field: &str) -> Option<String> {
    payload
        .split([';', ','])
        .filter_map(|segment| segment.split_once('='))
        .find_map(|(key, value)| {
            if key.trim().eq_ignore_ascii_case(field) {
                let value = value.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                }
            } else {
                None
            }
        })
}

fn parse_payload_path(payload: &str) -> Option<String> {
    if let Some(path) = parse_payload_field(payload, "path") {
        return Some(path);
    }

    let trimmed = payload.trim();
    if trimmed.is_empty() || trimmed.contains('=') {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_payload_rename_paths(payload: &str) -> (Option<String>, Option<String>) {
    let src = parse_payload_field(payload, "src")
        .or_else(|| parse_payload_field(payload, "old"))
        .or_else(|| parse_payload_field(payload, "old_path"));
    let dst = parse_payload_field(payload, "dst")
        .or_else(|| parse_payload_field(payload, "new"))
        .or_else(|| parse_payload_field(payload, "new_path"));
    (src, dst)
}

fn unix_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
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
