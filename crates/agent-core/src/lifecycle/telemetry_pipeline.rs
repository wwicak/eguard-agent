use std::collections::HashSet;
use std::time::Instant;

use anyhow::Result;
use serde_json::json;
use tokio::time::timeout;
use tracing::{info, warn};

use super::{
    coalesce_file_event_key, compute_poll_timeout, compute_sampling_stride, elapsed_micros,
    AgentRuntime, DegradedCause, EventEnvelope, RawEvent, TickEvaluation,
    DEGRADE_AFTER_SEND_FAILURES, EVENT_BATCH_SIZE, INTERNAL_SUBPROCESS_ENV_NAME,
};

const INTERNAL_PROCESS_TTL_NS: u64 = 15 * 60 * 1_000_000_000;
const INTERNAL_PROCESS_PID_LIMIT: usize = 4_096;
const TELEMETRY_SEND_TIMEOUT_MS: u64 = 5_000;

impl AgentRuntime {
    pub(super) async fn run_connected_telemetry_stage(
        &mut self,
        evaluation: Option<&TickEvaluation>,
    ) -> Result<()> {
        let Some(evaluation) = evaluation else {
            return Ok(());
        };

        if std::env::var("EGUARD_DEBUG_EVENT_TXN_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(
                txn_key = %evaluation.event_txn.key,
                txn_operation = %evaluation.event_txn.operation,
                "debug event transaction"
            );
        }

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

        let send_result = timeout(
            std::time::Duration::from_millis(TELEMETRY_SEND_TIMEOUT_MS),
            self.client.send_events(&batch),
        )
        .await;

        if let Err(err) = match send_result {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "telemetry send timed out after {}ms",
                TELEMETRY_SEND_TIMEOUT_MS
            )),
        } {
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
                timeout_ms = TELEMETRY_SEND_TIMEOUT_MS,
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
        let timeout = if self.raw_event_backlog.is_empty() {
            self.adaptive_poll_timeout()
        } else {
            std::time::Duration::from_millis(0)
        };
        let polled = self.ebpf_engine.poll_once(timeout);
        self.observe_ebpf_stats();

        match polled {
            Ok(events) => self.ingest_polled_raw_events(events),
            Err(err) => {
                warn!(error = %err, "eBPF poll failed; skipping telemetry event for this tick");
            }
        }

        self.refresh_strict_budget_mode();
        let sampling_stride = self.sampling_stride();
        self.dequeue_sampled_raw_event(sampling_stride)
    }

    fn is_agent_self_event(event: &RawEvent) -> bool {
        event.pid == std::process::id()
    }

    fn ingest_polled_raw_events(&mut self, events: Vec<RawEvent>) {
        if events.is_empty() {
            self.refresh_strict_budget_mode();
            return;
        }

        debug_trace_matching_raw_events("polled", &events);
        let self_filtered = self.filter_agent_noise_events(events);
        if self_filtered.is_empty() {
            self.refresh_strict_budget_mode();
            return;
        }

        debug_trace_matching_raw_events("filtered", &self_filtered);
        let before = self_filtered.len();
        let file_coalesced = self.coalesce_file_event_burst(self_filtered);
        debug_trace_matching_raw_events("file_coalesced", &file_coalesced);
        let file_dropped = before.saturating_sub(file_coalesced.len());
        if file_dropped > 0 {
            self.metrics.telemetry_coalesced_events_total = self
                .metrics
                .telemetry_coalesced_events_total
                .saturating_add(file_dropped as u64);
            info!(
                dropped = file_dropped,
                retained = file_coalesced.len(),
                window_ns = self.file_event_coalesce_window_ns,
                coalesced_total = self.metrics.telemetry_coalesced_events_total,
                "coalesced burst file events before deep analysis"
            );
        }

        let txn_coalesced = self.coalesce_event_txn_burst(file_coalesced);
        debug_trace_matching_raw_events("txn_coalesced", &txn_coalesced);
        let txn_dropped = before
            .saturating_sub(file_dropped)
            .saturating_sub(txn_coalesced.len());
        if txn_dropped > 0 {
            self.metrics.telemetry_event_txn_coalesced_total = self
                .metrics
                .telemetry_event_txn_coalesced_total
                .saturating_add(txn_dropped as u64);
            info!(
                dropped = txn_dropped,
                retained = txn_coalesced.len(),
                window_ns = self.event_txn_coalesce_window_ns,
                txn_coalesced_total = self.metrics.telemetry_event_txn_coalesced_total,
                "coalesced duplicate event transactions before deep analysis"
            );
        }

        let prioritized = Self::prioritize_raw_events(txn_coalesced);
        debug_trace_matching_raw_events("prioritized", &prioritized);
        let retained = self.limit_raw_event_ingress(prioritized);
        debug_trace_matching_raw_events("ingress_retained", &retained);
        self.enqueue_raw_events_with_priority(retained);
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
    }

    fn filter_agent_noise_events(&mut self, events: Vec<RawEvent>) -> Vec<RawEvent> {
        let now_ns = events
            .last()
            .map(|event| event.ts_ns)
            .filter(|value| *value > 0)
            .unwrap_or_else(unix_now_ns);
        self.prune_suppressed_internal_process_pids(now_ns);

        let mut kept = Vec::with_capacity(events.len());
        for event in events {
            if Self::is_agent_self_event(&event) {
                debug_trace_matching_raw_event("drop_self", &event);
                continue;
            }
            if self.should_suppress_internal_process_event(&event) {
                debug_trace_matching_raw_event("drop_internal", &event);
                continue;
            }
            if Self::should_drop_low_value_linux_raw_event(&event) {
                debug_trace_matching_raw_event("drop_low_value", &event);
                continue;
            }
            kept.push(event);
        }
        kept
    }

    pub(super) fn should_drop_low_value_linux_raw_event(event: &RawEvent) -> bool {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = event;
            false
        }

        #[cfg(target_os = "linux")]
        {
            let path = parse_payload_field(&event.payload, "path").unwrap_or_default();
            let comm = parse_payload_field(&event.payload, "comm")
                .map(|value| value.to_ascii_lowercase())
                .unwrap_or_default();
            let parent_comm = parse_payload_field(&event.payload, "parent_comm")
                .map(|value| value.to_ascii_lowercase())
                .unwrap_or_default();
            let command_line = parse_payload_field(&event.payload, "cmdline")
                .or_else(|| parse_payload_field(&event.payload, "command_line"))
                .map(|value| value.to_ascii_lowercase())
                .unwrap_or_default();

            if matches!(event.event_type, crate::platform::EventType::ProcessExec)
                && is_expected_linux_procfd_runtime_artifact(
                    &comm,
                    &parent_comm,
                    &path,
                    &command_line,
                )
            {
                return true;
            }

            if matches!(event.event_type, crate::platform::EventType::ProcessExec)
                && is_expected_linux_auth_stack_process_noise(
                    &comm,
                    &parent_comm,
                    &path,
                    &command_line,
                )
            {
                return true;
            }

            if matches!(event.event_type, crate::platform::EventType::ProcessExec)
                && is_expected_linux_systemd_process_noise(
                    &comm,
                    &parent_comm,
                    &path,
                    &command_line,
                )
            {
                return true;
            }

            if matches!(event.event_type, crate::platform::EventType::ProcessExec)
                && is_expected_linux_shell_startup_process_noise(
                    &comm,
                    &parent_comm,
                    &path,
                    &command_line,
                )
            {
                return true;
            }

            if !matches!(event.event_type, crate::platform::EventType::FileOpen) {
                if matches!(event.event_type, crate::platform::EventType::FileWrite)
                    && path.is_empty()
                {
                    return true;
                }

                return false;
            }

            if path == "/dev/console" || path == "/dev/tty" || path.starts_with("/dev/pts/") {
                return true;
            }

            if is_low_value_linux_systemd_noise(&comm, &parent_comm, &path) {
                return true;
            }

            if is_expected_linux_agent_control_plane_noise(&comm, &parent_comm, &path) {
                return true;
            }

            if is_expected_linux_auth_stack_noise(&comm, &parent_comm, &path) {
                return true;
            }

            if is_expected_linux_ssh_bootstrap_noise(&comm, &parent_comm, &path) {
                return true;
            }

            false
        }
    }

    fn should_suppress_internal_process_event(&mut self, event: &RawEvent) -> bool {
        let event_ns = if event.ts_ns == 0 {
            unix_now_ns()
        } else {
            event.ts_ns
        };
        self.prune_suppressed_internal_process_pids(event_ns);

        if matches!(event.event_type, crate::platform::EventType::ProcessExit) {
            return self
                .suppressed_internal_process_pids
                .remove(&event.pid)
                .is_some();
        }

        if self.is_tracked_internal_process(event.pid, event_ns)
            || self.should_track_internal_process_event(event, event_ns)
        {
            return true;
        }

        false
    }

    fn should_track_internal_process_event(&mut self, event: &RawEvent, event_ns: u64) -> bool {
        if let Some(parent_pid) = payload_parent_pid(&event.payload) {
            if parent_pid == std::process::id()
                || self.is_tracked_internal_process(parent_pid, event_ns)
            {
                self.track_internal_process_pid(event.pid, event_ns);
                return true;
            }
        }

        if payload_parent_process_name(&event.payload)
            .map(|value| is_eguard_agent_process(&value))
            .unwrap_or(false)
            || is_marked_internal_process(event.pid)
        {
            self.track_internal_process_pid(event.pid, event_ns);
            return true;
        }

        false
    }

    fn track_internal_process_pid(&mut self, pid: u32, event_ns: u64) {
        if pid == 0 || pid == std::process::id() {
            return;
        }

        self.suppressed_internal_process_pids
            .insert(pid, event_ns.saturating_add(INTERNAL_PROCESS_TTL_NS));
        self.prune_suppressed_internal_process_pids(event_ns);
    }

    fn is_tracked_internal_process(&mut self, pid: u32, event_ns: u64) -> bool {
        let Some(expires_ns) = self.suppressed_internal_process_pids.get(&pid).copied() else {
            return false;
        };

        if event_ns <= expires_ns {
            return true;
        }

        self.suppressed_internal_process_pids.remove(&pid);
        false
    }

    fn prune_suppressed_internal_process_pids(&mut self, now_ns: u64) {
        self.suppressed_internal_process_pids
            .retain(|_, expires_ns| now_ns <= *expires_ns);
        if self.suppressed_internal_process_pids.len()
            > INTERNAL_PROCESS_PID_LIMIT.saturating_mul(2)
        {
            self.suppressed_internal_process_pids.clear();
        }
    }

    fn telemetry_backlog_depth(&self) -> usize {
        self.buffer
            .pending_count()
            .saturating_add(self.raw_event_backlog.len())
    }

    fn refresh_strict_budget_mode(&mut self) {
        let next = self.buffer.pending_count() >= self.strict_budget_pending_threshold
            || self.raw_event_backlog.len() >= self.strict_budget_raw_backlog_threshold;

        if next != self.strict_budget_mode {
            self.metrics.strict_budget_mode_transition_total = self
                .metrics
                .strict_budget_mode_transition_total
                .saturating_add(1);
        }
        self.strict_budget_mode = next;
    }

    fn sampling_stride(&self) -> usize {
        compute_sampling_stride(self.telemetry_backlog_depth(), self.recent_ebpf_drops)
    }

    pub(super) fn dequeue_sampled_raw_event(&mut self, stride: usize) -> Option<RawEvent> {
        let stride = stride.max(1);

        loop {
            let Some(event) = self.raw_event_backlog.pop_front() else {
                return None;
            };

            if Self::is_agent_self_event(&event) {
                debug_trace_matching_raw_event("dequeue_drop_self", &event);
                continue;
            }
            if self.should_suppress_internal_process_event(&event) {
                debug_trace_matching_raw_event("dequeue_drop_internal", &event);
                continue;
            }
            if Self::should_drop_low_value_linux_raw_event(&event) {
                debug_trace_matching_raw_event("dequeue_drop_low_value", &event);
                continue;
            }

            if stride > 1 {
                self.sample_low_priority_backlog_events(stride.saturating_sub(1));
            }

            debug_trace_matching_raw_event("dequeued", &event);
            return Some(event);
        }
    }

    fn sample_low_priority_backlog_events(&mut self, max_skips: usize) {
        if max_skips == 0 || self.raw_event_backlog.is_empty() {
            return;
        }

        let mut preserved = Vec::new();
        let mut skipped = 0usize;

        while skipped < max_skips {
            let Some(candidate) = self.raw_event_backlog.pop_front() else {
                break;
            };

            if Self::raw_event_priority(&candidate) <= 1 {
                preserved.push(candidate);
                continue;
            }

            skipped = skipped.saturating_add(1);
        }

        for event in preserved.into_iter().rev() {
            self.raw_event_backlog.push_front(event);
        }
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

    fn coalesce_event_txn_burst(&mut self, events: Vec<RawEvent>) -> Vec<RawEvent> {
        if self.event_txn_coalesce_window_ns == 0 {
            return events;
        }

        let mut output = Vec::with_capacity(events.len());
        let mut batch_seen = HashSet::new();

        for event in events {
            let key = Self::event_txn_burst_key(&event);
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
                .recent_event_txn_keys
                .get(&key)
                .map(|prev_ts| {
                    event_ts.saturating_sub(*prev_ts) <= self.event_txn_coalesce_window_ns
                })
                .unwrap_or(false);
            if should_drop {
                continue;
            }

            self.recent_event_txn_keys.insert(key, event_ts);
            output.push(event);
        }

        self.prune_event_txn_coalesce_state();
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

    fn prune_event_txn_coalesce_state(&mut self) {
        if self.recent_event_txn_keys.len() <= self.event_txn_coalesce_key_limit {
            return;
        }

        let now_ns = unix_now_ns();
        let retention = self.event_txn_coalesce_window_ns.max(1).saturating_mul(4);
        self.recent_event_txn_keys
            .retain(|_, seen_ns| now_ns.saturating_sub(*seen_ns) <= retention);

        if self.recent_event_txn_keys.len() > self.event_txn_coalesce_key_limit.saturating_mul(2) {
            self.recent_event_txn_keys.clear();
        }
    }

    pub(super) fn limit_raw_event_ingress(&mut self, mut events: Vec<RawEvent>) -> Vec<RawEvent> {
        if events.len() <= self.raw_event_ingest_cap {
            return events;
        }

        // Within the same primary priority tier, keep high-value FileOpen events
        // ahead of ProcessExec bursts so a same-session /tmp exact-IOC read is not
        // dropped purely because many benign helper execs arrived in the same poll.
        events.sort_by_key(|event| {
            (
                Self::raw_event_priority(event),
                Self::raw_event_ingest_secondary_key(event),
            )
        });

        let dropped = events.len().saturating_sub(self.raw_event_ingest_cap);
        events.truncate(self.raw_event_ingest_cap);
        self.metrics.telemetry_raw_backlog_dropped_total = self
            .metrics
            .telemetry_raw_backlog_dropped_total
            .saturating_add(dropped as u64);

        warn!(
            dropped,
            ingest_cap = self.raw_event_ingest_cap,
            retained = events.len(),
            backlog_dropped_total = self.metrics.telemetry_raw_backlog_dropped_total,
            "raw event ingress exceeded cap; dropped lowest-priority events from this poll"
        );

        events
    }

    fn raw_event_ingest_secondary_key(event: &RawEvent) -> u8 {
        match event.event_type {
            crate::platform::EventType::FileOpen => {
                let path = parse_payload_field(&event.payload, "path").unwrap_or_default();
                if path.starts_with("/tmp/") || path.starts_with("/var/tmp/") {
                    0
                } else if is_high_value_linux_file_path(&path) {
                    1
                } else {
                    2
                }
            }
            _ => 2,
        }
    }

    pub(super) fn enforce_raw_event_backlog_cap(&mut self) {
        if self.raw_event_backlog.len() <= self.raw_event_backlog_cap {
            return;
        }

        let overflow = self
            .raw_event_backlog
            .len()
            .saturating_sub(self.raw_event_backlog_cap);
        for _ in 0..overflow {
            if let Some(event) = self.raw_event_backlog.pop_back() {
                debug_trace_matching_raw_event("backlog_evicted", &event);
            }
        }

        self.metrics.telemetry_raw_backlog_dropped_total = self
            .metrics
            .telemetry_raw_backlog_dropped_total
            .saturating_add(overflow as u64);

        warn!(
            overflow,
            backlog_cap = self.raw_event_backlog_cap,
            backlog_after = self.raw_event_backlog.len(),
            backlog_dropped_total = self.metrics.telemetry_raw_backlog_dropped_total,
            "raw event backlog exceeded cap; dropped tail events to preserve frontloaded high-priority telemetry"
        );
    }

    fn prioritize_raw_events(mut events: Vec<RawEvent>) -> Vec<RawEvent> {
        events.sort_by_key(Self::raw_event_priority);
        events
    }

    pub(super) fn enqueue_raw_events_with_priority(&mut self, events: Vec<RawEvent>) {
        let mut frontload = Vec::new();
        let mut normal = Vec::new();

        for event in events {
            if Self::raw_event_priority(&event) <= 1 {
                frontload.push(event);
            } else {
                normal.push(event);
            }
        }

        for event in frontload.into_iter().rev() {
            debug_trace_matching_raw_event("enqueue_front", &event);
            self.raw_event_backlog.push_front(event);
        }
        for event in normal {
            debug_trace_matching_raw_event("enqueue_back", &event);
            self.raw_event_backlog.push_back(event);
        }
    }

    pub(super) fn raw_event_priority(event: &RawEvent) -> u8 {
        match event.event_type {
            crate::platform::EventType::ProcessExec => 0,
            crate::platform::EventType::ProcessExit => 1,
            crate::platform::EventType::FileWrite
            | crate::platform::EventType::FileRename
            | crate::platform::EventType::FileUnlink
            | crate::platform::EventType::TcpConnect
            | crate::platform::EventType::DnsQuery
            | crate::platform::EventType::LsmBlock => 1,
            crate::platform::EventType::FileOpen => {
                if Self::should_drop_low_value_linux_raw_event(event) {
                    return 3;
                }

                let path = parse_payload_field(&event.payload, "path").unwrap_or_default();
                if is_high_value_linux_file_path(&path) {
                    0
                } else {
                    2
                }
            }
            crate::platform::EventType::ModuleLoad => 2,
        }
    }

    fn file_event_burst_key(event: &RawEvent) -> Option<String> {
        if is_high_value_linux_file_open_event(event) {
            return None;
        }

        coalesce_file_event_key(event)
    }

    fn event_txn_burst_key(event: &RawEvent) -> Option<String> {
        if is_high_value_linux_file_open_event(event) {
            return None;
        }

        match event.event_type {
            crate::platform::EventType::FileOpen => {
                let txn = super::EventTxn::from_raw(event);
                if txn.subject.is_none() && txn.object.is_none() {
                    return None;
                }
                Some(format!(
                    "txn:{}|access:{}",
                    txn.key,
                    raw_file_open_access_intent(event)
                ))
            }
            crate::platform::EventType::FileWrite
            | crate::platform::EventType::FileRename
            | crate::platform::EventType::FileUnlink
            | crate::platform::EventType::TcpConnect
            | crate::platform::EventType::DnsQuery => {
                let txn = super::EventTxn::from_raw(event);
                if txn.subject.is_none() && txn.object.is_none() {
                    return None;
                }
                Some(format!("txn:{}", txn.key))
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

fn raw_file_open_access_intent(event: &RawEvent) -> &'static str {
    let payload = &event.payload;
    let flags = parse_payload_field(payload, "flags");
    let mode = parse_payload_field(payload, "mode");
    if parse_file_write_flags(flags.as_deref(), mode.as_deref()) {
        "write"
    } else {
        "read"
    }
}

fn is_high_value_linux_file_open_event(event: &RawEvent) -> bool {
    if !matches!(event.event_type, crate::platform::EventType::FileOpen) {
        return false;
    }

    let path = parse_payload_field(&event.payload, "path").unwrap_or_default();
    is_high_value_linux_file_path(&path)
}

fn parse_file_write_flags(flags: Option<&str>, mode: Option<&str>) -> bool {
    let flags_val = flags
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let mode_val = mode
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);

    const O_WRONLY: u32 = 1;
    const O_RDWR: u32 = 2;
    const O_CREAT: u32 = 0x40;
    const O_TRUNC: u32 = 0x200;

    let write_intent = (flags_val & O_WRONLY) != 0 || (flags_val & O_RDWR) != 0;
    let destructive = (flags_val & O_TRUNC) != 0 || (flags_val & O_CREAT) != 0;
    let executable_bit = (mode_val & 0o111) != 0;

    write_intent || destructive || executable_bit
}

fn is_expected_linux_procfd_runtime_artifact(
    comm: &str,
    parent_comm: &str,
    path: &str,
    command_line: &str,
) -> bool {
    let lower = path.to_ascii_lowercase();
    if !(lower.starts_with("/proc/self/fd/")
        || (lower.starts_with("/proc/") && lower.contains("/fd/")))
    {
        return false;
    }

    let comm_numeric = !comm.is_empty() && comm.chars().all(|ch| ch.is_ascii_digit());
    let cmd_numeric =
        !command_line.is_empty() && command_line.chars().all(|ch| ch.is_ascii_digit());

    (parent_comm == "systemd" || parent_comm == "sshd" || parent_comm == "sshd-session")
        && (comm_numeric || cmd_numeric)
}

fn is_expected_linux_auth_stack_process_noise(
    comm: &str,
    parent_comm: &str,
    path: &str,
    command_line: &str,
) -> bool {
    let process = normalize_linux_process_name(comm);
    let parent = normalize_linux_process_name(parent_comm);
    let lower = path.to_ascii_lowercase();
    let cmd = command_line.to_ascii_lowercase();

    if process == "sshd-session" && parent == "sshd" {
        return lower.ends_with("/sshd-session") || cmd.contains("sshd-session: [accepted]");
    }

    if process == "unix_chkpwd" && parent == "sshd-session" {
        return lower.ends_with("/unix_chkpwd") || cmd == "unix_chkpwd";
    }

    if process == "unix_chkpwd" && parent == "systemd" {
        return lower.is_empty() || lower.ends_with("/unix_chkpwd");
    }

    false
}

fn is_expected_linux_auth_stack_noise(comm: &str, parent_comm: &str, path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let process = comm.to_ascii_lowercase();
    let parent = parent_comm.to_ascii_lowercase();

    if matches!(process.as_str(), "unix_chkpwd" | "chkpwd")
        && (lower.starts_with("/etc/shadow")
            || lower.starts_with("/etc/gshadow")
            || lower.starts_with("/etc/master.passwd")
            || lower == "/etc/passwd"
            || lower == "/etc/nsswitch.conf")
    {
        return true;
    }

    if matches!(process.as_str(), "sudo" | "sudoedit" | "su" | "login") {
        if lower.starts_with("/etc/sudoers")
            || lower.starts_with("/etc/sudoers.d")
            || lower.starts_with("/etc/pam.d/")
            || lower.starts_with("/etc/security/")
            || lower.starts_with("/usr/lib64/security/pam_")
            || lower.starts_with("/usr/lib/security/pam_")
            || lower.starts_with("/lib64/security/pam_")
            || lower.starts_with("/lib/security/pam_")
            || lower == "/etc/login.defs"
            || lower == "/etc/group"
            || lower == "/dev/tty"
        {
            return true;
        }
    }

    if process == "systemd-userwork" && lower.starts_with("/etc/shadow") {
        return true;
    }

    if process == "sudo" && parent == "bash" && lower.starts_with("/run/systemd/userdb/") {
        return true;
    }

    false
}

fn is_expected_linux_systemd_process_noise(
    comm: &str,
    parent_comm: &str,
    path: &str,
    command_line: &str,
) -> bool {
    let process = normalize_linux_process_name(comm);
    let parent = normalize_linux_process_name(parent_comm);
    let lower = path.to_ascii_lowercase();
    let cmd = command_line.to_ascii_lowercase();

    if !is_systemd_family_process(&process) && !is_systemd_family_process(&parent) {
        return false;
    }

    if lower.is_empty() {
        if process.ends_with("-generator") && matches!(parent.as_str(), "sd-exec-strv" | "systemd")
        {
            return true;
        }
        if parent == "systemd"
            && matches!(
                process.as_str(),
                "systemd" | "systemd-user-runtime-dir" | "systemd-tmpfiles" | "systemctl"
            )
        {
            return true;
        }
        return false;
    }

    if process == "systemd"
        && (lower.ends_with("/systemd") || lower.ends_with("/systemd/systemd"))
        && cmd.ends_with("systemd --user")
    {
        return true;
    }

    if process == "systemd-user-runtime-dir"
        && (lower.ends_with("/systemd-user-runtime-dir")
            || lower.ends_with("/systemd/systemd-user-runtime-dir"))
        && parent == "systemd"
    {
        return true;
    }

    if lower.starts_with("/usr/lib/systemd/user-generators/")
        || lower.starts_with("/usr/lib64/systemd/user-generators/")
        || lower.starts_with("/usr/lib/systemd/user-environment-generators/")
        || lower.starts_with("/usr/lib64/systemd/user-environment-generators/")
    {
        return process.ends_with("-generator")
            && matches!(parent.as_str(), "systemd" | "sd-exec-strv");
    }

    if process == "systemd-tmpfiles" && parent == "systemd" && cmd.contains("--user") {
        return true;
    }

    false
}

fn is_expected_linux_shell_startup_process_noise(
    comm: &str,
    parent_comm: &str,
    path: &str,
    command_line: &str,
) -> bool {
    let process = normalize_linux_process_name(comm);
    let parent = normalize_linux_process_name(parent_comm);
    let lower = path.to_ascii_lowercase();
    let cmd = command_line.to_ascii_lowercase();

    if process == "bash"
        && parent == "systemd"
        && matches!(lower.as_str(), "/usr/bin/bash" | "/bin/bash")
        && (cmd.is_empty() || cmd == "bash" || cmd == "/usr/bin/bash" || cmd == "/bin/bash")
    {
        return true;
    }

    if parent != "bash" {
        return false;
    }

    (process == "grepconf.sh" && (lower == "/usr/libexec/grepconf.sh" || cmd == "grepconf.sh"))
        || (process == "systemctl" && cmd.contains("--user") && cmd.contains("show-environment"))
        || (process == "nohup"
            && matches!(lower.as_str(), "/usr/bin/nohup" | "/bin/nohup")
            && cmd == "nohup")
        || (process == "tty" && lower == "/usr/bin/tty" && cmd == "tty")
        || (process == "sed"
            && matches!(lower.as_str(), "/usr/bin/sed" | "/bin/sed")
            && cmd == "sed")
        || (process == "curl"
            && matches!(lower.as_str(), "/usr/bin/curl" | "/bin/curl")
            && cmd == "curl")
}

fn is_expected_linux_ssh_bootstrap_noise(comm: &str, parent_comm: &str, path: &str) -> bool {
    let process = normalize_linux_process_name(comm);
    let parent = normalize_linux_process_name(parent_comm);
    let lower = path.to_ascii_lowercase();

    if process == "sshd-session" && matches!(parent.as_str(), "sshd" | "sshd-session") {
        return is_low_value_linux_ssh_bootstrap_path(&lower);
    }

    if process == "bash" && matches!(parent.as_str(), "sshd-session" | "systemd") {
        return is_low_value_linux_shell_startup_path(&lower);
    }

    if process == "curl" && parent == "bash" && lower.ends_with("/.curlrc") {
        return true;
    }

    if process == "unix_chkpwd" && parent == "sshd-session" {
        return lower.is_empty() || lower == "/etc/localtime";
    }

    false
}

fn is_low_value_linux_systemd_noise(comm: &str, parent_comm: &str, path: &str) -> bool {
    (is_systemd_family_process(comm) || is_systemd_family_process(parent_comm))
        && is_low_value_linux_systemd_path(path)
}

fn is_systemd_family_process(process: &str) -> bool {
    let normalized = normalize_linux_process_name(process);
    normalized == "systemd"
        || normalized.starts_with("systemd-")
        || matches!(normalized.as_str(), "sd-rmrf" | "sd-exec-strv")
}

fn is_eguard_agent_process(process: &str) -> bool {
    matches!(
        normalize_linux_process_name(process).as_str(),
        "eguard-agent" | "eguard-agent.exe" | "agent-core" | "agent-core.exe"
    )
}

fn normalize_linux_process_name(process: &str) -> String {
    process_basename(process.trim().trim_start_matches('(').trim_end_matches(')'))
        .to_ascii_lowercase()
}

fn is_low_value_linux_runtime_loader_path(path: &str) -> bool {
    path.is_empty()
        || path == "/etc/ld.so.cache"
        || path == "/dev/null"
        || path.starts_with("/proc/self/")
        || path.starts_with("/proc/thread-self/")
        || path.starts_with("/lib/")
        || path.starts_with("/lib64/")
        || path.starts_with("/usr/lib64/")
}

fn is_low_value_linux_ssh_bootstrap_path(path: &str) -> bool {
    is_low_value_linux_runtime_loader_path(path)
        || path == "/proc/sys/crypto/fips_enabled"
        || path.starts_with("/sys/fs/selinux/")
        || path.starts_with("/etc/pam.d/")
        || path.starts_with("/etc/pki/tls/")
        || path.starts_with("/etc/crypto-policies/")
        || path.starts_with("/etc/selinux/")
        || path.starts_with("/etc/security/")
        || path.starts_with("/etc/gss/")
        || path.ends_with("/.ssh/authorized_keys")
        || matches!(
            path,
            "/etc/login.defs"
                | "/etc/environment"
                | "/etc//environment"
                | "/etc/passwd"
                | "/etc/group"
                | "/etc/nsswitch.conf"
                | "/etc/gai.conf"
                | "/var/run/nologin"
                | "/var/log/btmp"
        )
}

fn is_low_value_linux_shell_startup_path(path: &str) -> bool {
    matches!(path, "/etc/profile" | "/etc/bashrc")
        || path.starts_with("/etc/profile.d/")
        || path.ends_with("/.bashrc")
        || path.ends_with("/.bash_profile")
        || path.ends_with("/.profile")
        || path.ends_with("/.inputrc")
}

fn is_low_value_linux_systemd_path(path: &str) -> bool {
    is_low_value_linux_runtime_loader_path(path)
        || path.is_empty()
        || !path.starts_with('/')
        || path.starts_with("/sys/")
        || path.starts_with("/proc/self/")
        || path.starts_with("/proc/")
        || path.starts_with("/run/")
        || path.starts_with("/var/run/")
        || path.starts_with("/var/log/journal/")
        || path.starts_with("/usr/lib/systemd/")
        || path.starts_with("/usr/lib64/systemd/")
        || path.starts_with("/run/udev/data/")
        || path.starts_with("/etc/pam.d/")
        || path.starts_with("/etc/selinux/")
        || path.ends_with("/.config/systemd/user.conf")
        || path.contains("/.config/systemd/user.conf.d/")
}

fn is_low_value_linux_control_plane_runtime_path(path: &str) -> bool {
    if path.starts_with("/usr/lib/systemd/system/")
        || path.starts_with("/usr/lib64/systemd/system/")
        || path.starts_with("/usr/lib/systemd/user/")
        || path.starts_with("/usr/lib64/systemd/user/")
    {
        return false;
    }

    is_low_value_linux_runtime_loader_path(path)
        || path.starts_with("/proc/")
        || path.starts_with("/run/")
        || path.starts_with("/var/run/")
        || path.starts_with("/dev/")
        || path.starts_with("/usr/lib/locale/")
        || path.starts_with("/usr/lib/systemd/")
        || path.starts_with("/usr/lib64/systemd/")
}

fn is_low_value_linux_rpm_metadata_path(path: &str) -> bool {
    path.starts_with("/usr/lib/rpm/")
        || path.starts_with("/usr/lib64/rpm/")
        || path.starts_with("/usr/share/rpm/")
        || path.starts_with("/var/lib/rpm/")
}

fn is_expected_linux_agent_control_plane_noise(comm: &str, parent_comm: &str, path: &str) -> bool {
    if !is_eguard_agent_process(parent_comm) {
        return false;
    }

    let process = normalize_linux_process_name(comm);
    let lower = path.to_ascii_lowercase();
    match process.as_str() {
        "systemctl" => is_low_value_linux_control_plane_runtime_path(&lower),
        "rpm" => {
            is_low_value_linux_control_plane_runtime_path(&lower)
                || is_low_value_linux_rpm_metadata_path(&lower)
        }
        _ => false,
    }
}

fn is_high_value_linux_file_path(path: &str) -> bool {
    path.starts_with("/tmp/")
        || path.starts_with("/var/tmp/")
        || path.starts_with("/etc/eguard-agent/")
        || path.starts_with("/home/")
        || path.starts_with("/root/")
        || path.starts_with("/opt/")
        || path.starts_with("/srv/")
        || path.starts_with("/var/www/")
}

fn debug_trace_matching_raw_events(stage: &'static str, events: &[RawEvent]) {
    for event in events {
        debug_trace_matching_raw_event(stage, event);
    }
}

fn debug_trace_matching_raw_event(stage: &'static str, event: &RawEvent) {
    let Some(raw_filter) = std::env::var("EGUARD_DEBUG_TRACE_FILE_SUBSTRING")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return;
    };

    let path = parse_payload_field(&event.payload, "path").unwrap_or_default();
    let payload_matches = event.payload.contains(&raw_filter);
    let path_matches = !path.is_empty() && path.contains(&raw_filter);
    if !payload_matches && !path_matches {
        return;
    }

    info!(
        stage,
        event_type = ?event.event_type,
        pid = event.pid,
        uid = event.uid,
        ts_ns = event.ts_ns,
        path = %path,
        payload = %event.payload,
        "debug traced raw file event"
    );
}

fn parse_payload_field(payload: &str, field: &str) -> Option<String> {
    payload
        .split([';', ','])
        .filter_map(|segment| segment.split_once('='))
        .find_map(|(key, value)| {
            if key.trim().eq_ignore_ascii_case(field) {
                let value = value.trim().trim_matches('"');
                if value.is_empty() {
                    None
                } else {
                    Some(decode_payload_value(value))
                }
            } else {
                None
            }
        })
}

fn parse_payload_u32_field(payload: &str, field: &str) -> Option<u32> {
    let raw = parse_payload_field(payload, field)?;
    let trimmed = raw.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16)
            .ok()
            .and_then(|value| u32::try_from(value).ok());
    }
    trimmed.parse::<u32>().ok()
}

fn payload_parent_pid(payload: &str) -> Option<u32> {
    parse_payload_u32_field(payload, "ppid")
        .or_else(|| parse_payload_u32_field(payload, "parent_pid"))
}

fn payload_parent_process_name(payload: &str) -> Option<String> {
    parse_payload_field(payload, "parent_process")
        .or_else(|| parse_payload_field(payload, "parent_process_name"))
        .or_else(|| parse_payload_field(payload, "parent_name"))
        .or_else(|| parse_payload_field(payload, "parent_comm"))
}

fn process_basename(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
}

fn is_marked_internal_process(pid: u32) -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        false
    }

    #[cfg(target_os = "linux")]
    {
        if pid == 0 {
            return false;
        }

        let Ok(raw) = std::fs::read(format!("/proc/{pid}/environ")) else {
            return false;
        };

        raw.split(|byte| *byte == 0).any(|entry| {
            let Ok(value) = std::str::from_utf8(entry) else {
                return false;
            };
            let Some(marker) = value.strip_prefix(INTERNAL_SUBPROCESS_ENV_NAME) else {
                return false;
            };

            if marker.is_empty() {
                return true;
            }

            marker
                .strip_prefix('=')
                .map(|raw_value| matches!(raw_value.trim(), "1" | "true" | "TRUE" | "True"))
                .unwrap_or(false)
        })
    }
}

fn decode_payload_value(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = &raw[index + 1..index + 3];
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                out.push(value as char);
                index += 3;
                continue;
            }
        }

        if let Some(ch) = raw[index..].chars().next() {
            out.push(ch);
            index += ch.len_utf8();
        } else {
            break;
        }
    }

    out
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
