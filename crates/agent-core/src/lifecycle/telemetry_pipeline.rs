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
        self.queue_connected_telemetry(evaluation).await?;
        // Preserve first-send outcome/backpressure state before scheduling and
        // commands. Only additional evaluations share the end-of-tick send.
        let events = self
            .tick_telemetry
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default();
        let mut first_error = None;
        for envelope in events {
            // Base drains old rows again for each event/compliance envelope.
            // Attempt every envelope even if an earlier recovery enqueue fails.
            if let Err(err) = self.flush_telemetry_batch(vec![envelope], true).await {
                first_error.get_or_insert(err);
            }
        }
        if let Some(err) = first_error {
            return Err(err);
        }
        Ok(())
    }

    pub(super) async fn queue_connected_telemetry(
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

        self.send_event_batch(evaluation.event_envelope.clone())
            .await?;

        let compliance_alerts = self.collect_compliance_alerts(
            &evaluation.compliance,
            evaluation.event_envelope.created_at_unix,
        );
        for alert in compliance_alerts {
            self.send_event_batch(alert).await?;
        }

        Ok(())
    }

    pub(super) async fn send_event_batch(&mut self, envelope: EventEnvelope) -> Result<()> {
        if let Some(events) = self.tick_telemetry.as_mut() {
            events.push(envelope);
            return Ok(());
        }
        self.flush_event_batch(vec![envelope]).await
    }

    pub(super) fn buffer_events(&mut self, events: Vec<EventEnvelope>) -> Result<()> {
        let mut first_error = None;
        let mut failed_enqueues = 0usize;
        for event in events {
            if let Err(err) = self.enqueue_buffer_event(event) {
                failed_enqueues += 1;
                first_error.get_or_insert(err);
            }
        }
        if let Some(err) = first_error {
            warn!(failed_enqueues, error = %err, "failed to buffer telemetry events");
            return Err(err.context(format!("{failed_enqueues} telemetry enqueues failed")));
        }
        Ok(())
    }

    fn enqueue_buffer_event(&mut self, event: EventEnvelope) -> Result<()> {
        #[cfg(test)]
        if let Some(remaining) = self.buffer_enqueue_failure_at.as_mut() {
            if *remaining == 0 {
                self.buffer_enqueue_failure_at = None;
                anyhow::bail!("injected buffer enqueue failure");
            }
            *remaining -= 1;
        }
        self.buffer.enqueue(event)
    }

    pub(super) async fn flush_event_batch(&mut self, events: Vec<EventEnvelope>) -> Result<()> {
        self.flush_telemetry_batch(events, false).await
    }

    async fn flush_telemetry_batch(
        &mut self,
        events: Vec<EventEnvelope>,
        include_all_current: bool,
    ) -> Result<()> {
        let send_started = Instant::now();
        let pending_before = self.buffer.pending_count();
        let mut batch = match self.buffer.drain_batch(EVENT_BATCH_SIZE) {
            Ok(batch) => batch,
            Err(err) => {
                // buffer_events logs recovery failures without hiding the drain error.
                let _ = self.buffer_events(events);
                return Err(err);
            }
        };
        let mut overflow = Vec::new();
        for event in events {
            if include_all_current || batch.len() < EVENT_BATCH_SIZE {
                batch.push(event);
            } else {
                overflow.push(event);
            }
        }
        if batch.is_empty() {
            return self.buffer_events(overflow);
        }

        #[cfg(test)]
        self.telemetry_send_batches.push(batch.len());
        #[cfg(test)]
        let send_result = if self.telemetry_send_success {
            Ok(Ok(()))
        } else {
            timeout(
                std::time::Duration::from_millis(TELEMETRY_SEND_TIMEOUT_MS),
                self.client.send_events(&batch),
            )
            .await
        };
        #[cfg(not(test))]
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
            self.consecutive_send_failures = self.consecutive_send_failures.saturating_add(1);
            if self.consecutive_send_failures >= DEGRADE_AFTER_SEND_FAILURES {
                self.transition_to_degraded(DegradedCause::SendFailures);
            }

            // Requeue before new overflow. Existing buffered old-tail rows still
            // precede this batch with the append-only API (pre-existing; follow-up F9).
            let requeue_result = self.buffer_events(batch);
            let overflow_result = self.buffer_events(overflow);
            warn!(
                error = %err,
                pending = self.buffer.pending_count(),
                timeout_ms = TELEMETRY_SEND_TIMEOUT_MS,
                "send failed, event re-buffering attempted"
            );
            self.metrics.last_send_event_batch_micros = elapsed_micros(send_started);
            return requeue_result.and(overflow_result);
        } else {
            self.consecutive_send_failures = 0;
            self.pipeline_events_sent =
                self.pipeline_events_sent.saturating_add(batch.len() as u64);
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

        let overflow_result = self.buffer_events(overflow);
        self.metrics.last_send_event_batch_micros = elapsed_micros(send_started);
        overflow_result
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

        // Only the current policy's checks need dedupe state. Prune old
        // contexts before admission so a policy replacement cannot starve alerts.
        let current_keys: HashSet<_> = compliance
            .checks
            .iter()
            .map(|check| format!("{}:{}", policy_key, check.check_id))
            .collect();
        self.compliance_alert_state
            .retain(|key, _| current_keys.contains(key));

        for check in &compliance.checks {
            let key = format!("{}:{}", policy_key, check.check_id);
            if check.status == "non_compliant" {
                // Budget emissions per evaluation, not remembered failures:
                // overflow is deferred, while admitted checks stay deduplicated.
                // State is bounded by the current policy's check count.
                if !self.compliance_alert_state.contains_key(&key)
                    && alerts.len() < super::COMPLIANCE_ALERT_STATE_LIMIT
                {
                    self.compliance_alert_state.insert(key.clone(), now_unix);
                    alerts.push(self.build_compliance_alert_envelope(check, now_unix));
                }
            } else {
                self.compliance_alert_state.remove(&key);
            }
        }

        self.enforce_collection_caps();
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
        self.next_raw_event_with_wait(true)
    }

    pub(super) fn next_raw_event_with_wait(&mut self, allow_wait: bool) -> Option<RawEvent> {
        self.refresh_strict_budget_mode();
        let timeout = if allow_wait && self.raw_event_backlog.is_empty() {
            self.adaptive_poll_timeout()
        } else {
            std::time::Duration::from_millis(0)
        };
        // Retain an oversized poll without preprocessing its tail or polling again.
        let polled = if self.pending_raw_polls.is_empty()
            && self.raw_ingested_this_tick < self.raw_event_ingest_cap
        {
            self.ebpf_engine.poll_once(timeout)
        } else {
            Ok(Vec::new())
        };
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

    // Benchmark the real per-commit ingress implementation without exposing production API.
    #[cfg(test)]
    pub(super) fn bench_ingest_polled(&mut self, events: Vec<RawEvent>) {
        self.ingest_polled_raw_events(events);
    }

    pub(super) fn pending_raw_event_count(&self) -> usize {
        self.pending_raw_polls
            .iter()
            .fold(self.raw_event_backlog.len(), |count, poll| {
                count.saturating_add(poll.len())
            })
    }

    fn ingest_polled_raw_events(&mut self, mut events: Vec<RawEvent>) {
        // Deferred records share the backlog's residency cap. Preserve already
        // queued work and discard the incoming tail before preprocessing it.
        let available = self
            .raw_event_backlog_cap
            .saturating_sub(self.pending_raw_event_count());
        let dropped = events.len().saturating_sub(available);
        if dropped > 0 {
            events.truncate(available);
            events.shrink_to_fit();
            self.metrics.telemetry_raw_backlog_dropped_total = self
                .metrics
                .telemetry_raw_backlog_dropped_total
                .saturating_add(dropped as u64);
            warn!(
                dropped,
                backlog_cap = self.raw_event_backlog_cap,
                "combined raw backlog exceeded cap; dropped incoming tail"
            );
        }
        if !events.is_empty() {
            self.pending_raw_polls.push_back(events.into_iter());
        }
        let remaining = self
            .raw_event_ingest_cap
            .saturating_sub(self.raw_ingested_this_tick);
        let mut events = Vec::new();
        while events.len() < remaining {
            let Some(poll) = self.pending_raw_polls.front_mut() else {
                break;
            };
            events.extend(poll.take(remaining - events.len()));
            if poll.len() == 0 {
                self.pending_raw_polls.pop_front();
            }
        }
        self.raw_ingested_this_tick += events.len();
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

        for event in &txn_coalesced {
            self.enrichment_cache.prime_process_metadata(event);
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

            if is_expected_linux_shell_startup_file_noise(&comm, &parent_comm, &path, &command_line)
            {
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

        if matches!(
            event.event_type,
            crate::platform::EventType::ProcessExec | crate::platform::EventType::ProcessExit
        ) {
            self.unmarked_internal_process_pids.remove(&event.pid);
        }
        if payload_has_duplicate_security_fields(&event.payload) {
            return false;
        }
        if matches!(event.event_type, crate::platform::EventType::ProcessExit) {
            let tracked = self.is_tracked_internal_process(event.pid, event_ns);
            self.suppressed_internal_process_pids.remove(&event.pid);
            return tracked;
        }

        if self.is_tracked_internal_process(event.pid, event_ns)
            || self.should_track_internal_process_event(event, event_ns)
        {
            return true;
        }

        false
    }

    fn should_track_internal_process_event(&mut self, event: &RawEvent, event_ns: u64) -> bool {
        // macOS can forward a JSON fallback. Its string contents are not
        // authenticated k=v ancestry, even if they contain ';ppid=...'.
        if payload_is_json_container(&event.payload)
            || payload_has_duplicate_security_fields(&event.payload)
        {
            return false;
        }
        if let Some(parent_pid) = payload_parent_pid(&event.payload) {
            if parent_pid == std::process::id()
                || self.is_tracked_internal_process(parent_pid, event_ns)
            {
                self.track_internal_process_pid(event.pid, event_ns);
                return true;
            }
        }

        // Parent comm and environment are user-controlled, not proof of ancestry.
        if self.is_marked_internal_process_cached(event.pid, event_ns) {
            self.track_internal_process_pid(event.pid, event_ns);
            return true;
        }

        false
    }

    fn is_marked_internal_process_cached(&mut self, pid: u32, event_ns: u64) -> bool {
        // mark_internal_command sets the marker at spawn; treat it as immutable until exec.
        // Stale negatives (including failed reads) only fail toward visibility, bounded by TTL.
        if self
            .unmarked_internal_process_pids
            .get(&pid)
            .is_some_and(|expires_ns| event_ns <= *expires_ns)
        {
            return false;
        }
        if is_marked_internal_process(pid) {
            self.unmarked_internal_process_pids.remove(&pid);
            return true;
        }
        self.unmarked_internal_process_pids
            .insert(pid, event_ns.saturating_add(INTERNAL_PROCESS_TTL_NS));
        self.prune_suppressed_internal_process_pids(event_ns);
        false
    }

    fn track_internal_process_pid(&mut self, pid: u32, event_ns: u64) {
        if pid == 0 || pid == std::process::id() {
            return;
        }

        let Some(start_time) = self.internal_process_start_time(pid) else {
            return;
        };
        self.suppressed_internal_process_pids.insert(
            pid,
            (event_ns.saturating_add(INTERNAL_PROCESS_TTL_NS), start_time),
        );
        self.prune_suppressed_internal_process_pids(event_ns);
    }

    fn is_tracked_internal_process(&mut self, pid: u32, event_ns: u64) -> bool {
        let Some((expires_ns, start_time)) =
            self.suppressed_internal_process_pids.get(&pid).copied()
        else {
            return false;
        };

        if event_ns <= expires_ns && self.internal_process_start_time(pid) == Some(start_time) {
            return true;
        }

        self.suppressed_internal_process_pids.remove(&pid);
        false
    }

    fn internal_process_start_time(&self, pid: u32) -> Option<u64> {
        #[cfg(test)]
        if let Some(reader) = self.internal_process_start_time_reader {
            return reader(pid);
        }
        #[cfg(target_os = "linux")]
        {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            parse_process_start_time(&stat)
        }
        // Non-Linux retains the existing PID/TTL behavior until a native
        // process-generation reader is available.
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            Some(0)
        }
    }

    fn prune_suppressed_internal_process_pids(&mut self, now_ns: u64) {
        if now_ns.saturating_sub(self.internal_process_last_prune_ns) >= 1_000_000_000 {
            self.internal_process_last_prune_ns = now_ns;
            self.suppressed_internal_process_pids
                .retain(|_, (expires_ns, _)| now_ns <= *expires_ns);
            self.unmarked_internal_process_pids
                .retain(|_, expires_ns| now_ns <= *expires_ns);
        }
        if self.unmarked_internal_process_pids.len() > INTERNAL_PROCESS_PID_LIMIT.saturating_mul(2)
        {
            self.unmarked_internal_process_pids.clear();
        }
        if self.suppressed_internal_process_pids.len()
            > INTERNAL_PROCESS_PID_LIMIT.saturating_mul(2)
        {
            self.suppressed_internal_process_pids.clear();
        }
    }

    pub(super) fn telemetry_backlog_depth(&self) -> usize {
        self.buffer
            .pending_count()
            .saturating_add(self.pending_raw_event_count())
    }

    fn refresh_strict_budget_mode(&mut self) {
        let next = self.buffer.pending_count() >= self.strict_budget_pending_threshold
            || self.pending_raw_event_count() >= self.strict_budget_raw_backlog_threshold;

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

        // A filtered prefix must not monopolize the tick before the control plane.
        for examined in 0..256 {
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
                self.sample_low_priority_backlog_events(
                    stride.saturating_sub(1).min((255 - examined) / 2),
                );
            }

            debug_trace_matching_raw_event("dequeued", &event);
            return Some(event);
        }
        // None with pending work is a yield, not an empty backlog. The first
        // evaluation may yield too; do not retry it in this tick's drain.
        self.raw_candidate_budget_exhausted = !self.raw_event_backlog.is_empty();
        None
    }

    fn sample_low_priority_backlog_events(&mut self, max_skips: usize) {
        if max_skips == 0 || self.raw_event_backlog.is_empty() {
            return;
        }

        let mut preserved = Vec::new();
        let mut skipped = 0usize;

        // A frontloaded high-priority prefix must not be rescanned in full on
        // every dequeue. Sampling may skip fewer events; the backlog cap remains.
        for _ in 0..max_skips.saturating_mul(2) {
            if skipped == max_skips {
                break;
            }
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

    fn prioritize_raw_events(events: Vec<RawEvent>) -> Vec<RawEvent> {
        prioritize_raw_events_by_key(events, Self::raw_event_priority)
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
        #[cfg(test)]
        priority_tests::PRIORITY_CALLS.with(|calls| calls.set(calls.get() + 1));
        match event.event_type {
            crate::platform::EventType::ProcessExec => 0,
            crate::platform::EventType::ProcessExit => 1,
            crate::platform::EventType::LsmBlock => 1,
            crate::platform::EventType::FileWrite
            | crate::platform::EventType::FileRename
            | crate::platform::EventType::FileUnlink => 2,
            crate::platform::EventType::TcpConnect | crate::platform::EventType::DnsQuery => 3,
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

    if process == "unix_chkpwd" && parent == "sudo" {
        return lower.is_empty() || lower.ends_with("/unix_chkpwd") || cmd == "unix_chkpwd";
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

    if process == "systemd-userwork" && (lower.starts_with("/etc/shadow") || lower == "/") {
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
        && matches!(parent.as_str(), "systemd" | "sshd-session")
        && (matches!(lower.as_str(), "/usr/bin/bash" | "/bin/bash")
            || (lower.is_empty()
                && (cmd.is_empty()
                    || cmd == "bash"
                    || cmd == "/usr/bin/bash"
                    || cmd == "/bin/bash")))
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
        || (process == "basename"
            && (matches!(lower.as_str(), "/usr/bin/basename" | "/bin/basename")
                || lower.is_empty())
            && cmd == "basename")
        || (process == "readlink"
            && (matches!(lower.as_str(), "/usr/bin/readlink" | "/bin/readlink")
                || lower.is_empty())
            && cmd == "readlink")
        || (process == "locale"
            && (matches!(lower.as_str(), "/usr/bin/locale" | "/bin/locale") || lower.is_empty())
            && cmd == "locale")
        || (process == "tr"
            && (matches!(lower.as_str(), "/usr/bin/tr" | "/bin/tr") || lower.is_empty())
            && cmd == "tr")
        || (process == "cat"
            && (matches!(lower.as_str(), "/usr/bin/cat" | "/bin/cat") || lower.is_empty())
            && cmd == "cat")
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
        return lower.is_empty()
            || lower == "/etc/localtime"
            || is_low_value_linux_runtime_loader_path(&lower);
    }

    false
}

fn is_expected_linux_shell_startup_file_noise(
    comm: &str,
    parent_comm: &str,
    path: &str,
    command_line: &str,
) -> bool {
    let process = normalize_linux_process_name(comm);
    let parent = normalize_linux_process_name(parent_comm);
    let lower = path.to_ascii_lowercase();
    let cmd = command_line.to_ascii_lowercase();

    if !lower.is_empty() {
        return false;
    }

    if parent == "bash"
        && matches!(
            process.as_str(),
            "basename" | "readlink" | "locale" | "tr" | "cat" | "grep" | "rm"
        )
        && (cmd.is_empty() || cmd == process)
    {
        return true;
    }

    if process == "sshd-session" && parent == "sshd" && cmd.contains("sshd-session: [accepted]") {
        return true;
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
        || path == "/proc/sys/kernel/random/boot_id"
        || path == "/proc/sys/kernel/ngroups_max"
        || path.starts_with("/sys/fs/selinux/")
        || path.starts_with("/etc/pam.d/")
        || path.starts_with("/etc/pki/tls/")
        || path.starts_with("/etc/crypto-policies/")
        || path.starts_with("/etc/selinux/")
        || path.starts_with("/etc/security/")
        || path.starts_with("/etc/gss/")
        || path.starts_with("/run/systemd/userdb/")
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
                | "/etc/motd"
                | "/etc/nologin"
                | "/etc/localtime"
                | "/proc/self/oom_score_adj"
                | "/var/run/nologin"
                | "/var/log/btmp"
        )
}

fn is_low_value_linux_shell_startup_path(path: &str) -> bool {
    matches!(path, "/etc/profile" | "/etc/bashrc")
        || path.starts_with("/etc/profile.d/")
        || path.starts_with("/usr/lib/locale/")
        || path.starts_with("/usr/lib64/gconv/")
        || path.starts_with("/usr/lib/gconv/")
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
    let decoded_payload = decode_raw_payload(&event.payload);
    let payload_matches = decoded_payload.contains(&raw_filter);
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
        payload = %decoded_payload,
        "debug traced raw file event"
    );
}

// Priority classification parses FileOpen payloads. Cache it once per event rather
// than repeating that work for every comparison; equal priorities remain stable.
fn prioritize_raw_events_by_key(
    mut events: Vec<RawEvent>,
    priority: impl FnMut(&RawEvent) -> u8,
) -> Vec<RawEvent> {
    events.sort_by_cached_key(priority);
    events
}

fn parse_payload_field(payload: &str, field: &str) -> Option<String> {
    payload
        .split([';', ','])
        .filter_map(|segment| segment.split_once('='))
        .find_map(|(key, value)| {
            if key.trim().eq_ignore_ascii_case(field) {
                let value = trim_enclosing_quotes(value.trim());
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

#[cfg(any(target_os = "linux", test))]
fn parse_process_start_time(stat: &str) -> Option<u64> {
    // comm (field 2) may contain spaces and parentheses; field 22 is
    // index 19 in the fields following the final closing parenthesis.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn payload_is_json_container(payload: &str) -> bool {
    payload.trim_start().starts_with(['{', '['])
}

fn payload_has_duplicate_security_fields(payload: &str) -> bool {
    if payload_is_json_container(payload) {
        return false; // JSON has no k=v fields; cached PID identity is independent.
    }
    let mut seen = [false; 4];
    for (key, _) in payload.split([';', ',']).filter_map(|s| s.split_once('=')) {
        let key = key.trim();
        let index = if key.eq_ignore_ascii_case("parent_pid") {
            0
        } else if let Some(index) = ["ppid", "pid", "uid", "cgroup_id"]
            .iter()
            .position(|field| key.eq_ignore_ascii_case(field))
        {
            index
        } else {
            continue;
        };
        if std::mem::replace(&mut seen[index], true) {
            return true;
        }
    }
    false
}

fn payload_parent_pid(payload: &str) -> Option<u32> {
    parse_payload_u32_field(payload, "ppid")
        .or_else(|| parse_payload_u32_field(payload, "parent_pid"))
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

        #[cfg(test)]
        priority_tests::ENVIRON_READS.with(|calls| calls.set(calls.get() + 1));
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/environ")) else {
            return false;
        };

        let marked = raw.split(|byte| *byte == 0).any(|entry| {
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
        });
        marked
            && std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
                .is_ok_and(|content| is_agent_internal_systemd_cgroup(&content))
    }
}

#[cfg(target_os = "linux")]
fn is_agent_internal_systemd_cgroup(content: &str) -> bool {
    // Only root-created system services authenticate the otherwise forgeable marker.
    // Unified hierarchy is authoritative on hybrid hosts. Legacy systemd uses
    // its named hierarchy, not arbitrary cpu/memory controller paths.
    let path = content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .or_else(|| {
            content.lines().find_map(|line| {
                let (_, rest) = line.split_once(':')?;
                rest.strip_prefix("name=systemd:")
            })
        });
    path.is_some_and(|path| {
        let Some(unit) = path.strip_prefix("/system.slice/") else {
            return false;
        };
        let Some(name) = unit.strip_suffix(".service") else {
            return false;
        };
        ["eguard-agent-update-", "eguard-agent-self-restart-"]
            .iter()
            .any(|prefix| {
                name.strip_prefix(prefix).is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
                })
            })
    })
}

/// Raw-string consumers must see OS text, never the escaped transport.
/// macOS retains its existing lossy producer and raw-consumer semantics.
pub(super) fn decode_raw_payload(raw: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        raw.to_string()
    }
    #[cfg(not(target_os = "macos"))]
    {
        decode_payload_value(raw)
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

fn trim_enclosing_quotes(raw: &str) -> &str {
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        &raw[1..raw.len() - 1]
    } else {
        raw
    }
}

fn unix_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "tests_payload_integrity.rs"]
mod tests_payload_integrity;

fn normalize_severity(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "low" => "low",
        "medium" | "med" => "medium",
        "high" => "high",
        "critical" => "critical",
        _ => "medium",
    }
}

#[cfg(test)]
mod priority_tests {
    use super::*;

    thread_local! {
        pub(super) static ENVIRON_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        pub(super) static PRIORITY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    #[cfg(target_os = "linux")]
    fn check_internal_process_cache(marked: bool) {
        let cfg = crate::config::AgentConfig {
            offline_buffer_backend: "memory".to_string(),
            server_addr: "127.0.0.1:1".to_string(),
            ..Default::default()
        };
        let mut runtime = AgentRuntime::new(cfg).expect("runtime");
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .env(INTERNAL_SUBPROCESS_ENV_NAME, if marked { "1" } else { "0" })
            .spawn()
            .expect("child");
        let mut event = RawEvent {
            pid: child.id(),
            uid: 1000,
            ts_ns: 1,
            event_type: crate::platform::EventType::FileOpen,
            // Omit parent metadata: this must exercise environ, not ancestry tracking.
            payload: "path=/tmp/test;comm=sleep".to_string(),
        };
        // spawn can return before /proc exposes the child's post-exec environment.
        let marker = format!(
            "{INTERNAL_SUBPROCESS_ENV_NAME}={}",
            if marked { "1" } else { "0" }
        );
        for _ in 0..100 {
            if std::fs::read(format!("/proc/{}/environ", child.id()))
                .unwrap_or_default()
                .split(|byte| *byte == 0)
                .any(|entry| entry == marker.as_bytes())
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        ENVIRON_READS.with(|calls| calls.set(0));
        let first = runtime.should_suppress_internal_process_event(&event);
        let second = runtime.should_suppress_internal_process_event(&event);
        let reads = ENVIRON_READS.with(|calls| calls.get());
        event.event_type = crate::platform::EventType::ProcessExec;
        let exec = runtime.should_suppress_internal_process_event(&event);
        let exec_reads = ENVIRON_READS.with(|calls| calls.get());
        let _ = child.kill();
        child.wait().expect("reap child");
        assert_eq!((first, second, exec), (false, false, false));
        assert_eq!(reads, 1, "normal repeated events must not reread environ");
        assert_eq!(exec_reads, 2, "exec invalidates negative cache");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn internal_process_negative_cache_avoids_reads_and_exec_rechecks() {
        check_internal_process_cache(false);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn internal_process_marker_without_system_unit_is_negative_cached() {
        check_internal_process_cache(true);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn internal_process_cgroup_requires_root_system_service() {
        for prefix in ["eguard-agent-update-", "eguard-agent-self-restart-"] {
            assert!(is_agent_internal_systemd_cgroup(&format!(
                "0::/system.slice/{prefix}123.service\n"
            )));
        }
        for content in [
            "1:name=systemd:/system.slice/eguard-agent-update-123.service",
            "1:cpu:/other\n2:name=systemd:/system.slice/eguard-agent-self-restart-123.service",
            "1:name=systemd:/other\n0::/system.slice/eguard-agent-update-123.service",
        ] {
            assert!(is_agent_internal_systemd_cgroup(content), "{content}");
        }
        for content in [
            "0::/user.slice/system.slice/eguard-agent-update-123.service",
            "0::/system.slice/other.service",
            "1:cpu,memory:/system.slice/eguard-agent-update-123.service",
            "1:name=systemd:/user.slice/eguard-agent-update-123.service",
            "0::/user.slice/other.service\n1:name=systemd:/system.slice/eguard-agent-update-123.service",
            "0::/system.slice/eguard-agent-update-evil/../",
            "0::/system.slice/eguard-agent-update-../123.service",
            "0::/system.slice/eguard-agent-update-.service",
            "0::/system.slice/eguard-agent-update-123.service/child",
        ] {
            assert!(!is_agent_internal_systemd_cgroup(content), "{content}");
        }
    }

    #[test]
    fn internal_process_parent_comm_cannot_authenticate_but_direct_pid_can() {
        let cfg = crate::config::AgentConfig {
            offline_buffer_backend: "memory".to_string(),
            server_addr: "127.0.0.1:1".to_string(),
            ..Default::default()
        };
        let mut runtime = AgentRuntime::new(cfg).expect("runtime");
        let mut event = RawEvent {
            pid: u32::MAX,
            uid: 1000,
            ts_ns: 1,
            event_type: crate::platform::EventType::ProcessExec,
            payload: "ppid=0;parent_comm=eguard-agent;comm=malware".to_string(),
        };
        assert!(
            !runtime.should_suppress_internal_process_event(&event),
            "an attacker can name its parent binary eguard-agent"
        );
        event.payload = format!("ppid={};parent_comm=anything", std::process::id());
        assert!(
            runtime.should_suppress_internal_process_event(&event),
            "Command children retain the agent PID as their kernel parent"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn internal_process_detached_forged_marker_does_not_hide_events() {
        let cfg = crate::config::AgentConfig {
            offline_buffer_backend: "memory".to_string(),
            server_addr: "127.0.0.1:1".to_string(),
            ..Default::default()
        };
        let mut runtime = AgentRuntime::new(cfg).expect("runtime");
        let output = std::process::Command::new("sh")
            .args([
                "-c",
                "EGUARD_INTERNAL_SUBPROCESS=1 sleep 30 >/dev/null 2>&1 & echo $!",
            ])
            .output()
            .expect("detached child");
        let pid: u32 = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let marker = b"EGUARD_INTERNAL_SUBPROCESS=1";
        let mut ready = false;
        for _ in 0..100 {
            ready = std::fs::read(format!("/proc/{pid}/environ"))
                .unwrap_or_default()
                .split(|byte| *byte == 0)
                .any(|entry| entry == marker);
            if ready {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let ppid = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        let event = RawEvent {
            pid,
            uid: 1000,
            ts_ns: 1,
            event_type: crate::platform::EventType::ProcessExec,
            payload: format!("ppid={ppid};comm=sleep;parent_comm=sh"),
        };
        let suppressed = runtime.should_suppress_internal_process_event(&event);
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
        assert!(
            ready,
            "real post-exec environment must contain the forged marker"
        );
        assert_ne!(
            ppid,
            std::process::id(),
            "must exercise marker rather than trusted ancestry"
        );
        assert!(
            !suppressed,
            "unprivileged environment markers must not hide malware"
        );
    }

    #[test]
    fn dequeue_sampling_bounds_priority_work_and_preserves_high_priority_order() {
        let cfg = crate::config::AgentConfig {
            offline_buffer_backend: "memory".to_string(),
            server_addr: "127.0.0.1:1".to_string(),
            ..Default::default()
        };
        let mut runtime = AgentRuntime::new(cfg).expect("runtime");
        for index in 0..4020 {
            runtime.raw_event_backlog.push_back(RawEvent {
                pid: 7001,
                uid: 1000,
                ts_ns: index,
                event_type: if index < 4000 {
                    crate::platform::EventType::ProcessExec
                } else if index == 4000 {
                    crate::platform::EventType::ProcessExit
                } else {
                    crate::platform::EventType::FileOpen
                },
                payload: "path=/var/log/messages;comm=cat;parent_comm=bash".to_string(),
            });
        }
        PRIORITY_CALLS.with(|calls| calls.set(0));
        let first = runtime.dequeue_sampled_raw_event(8).expect("event");
        assert_eq!(first.ts_ns, 0);
        let calls = PRIORITY_CALLS.with(|calls| calls.get());
        assert!(calls > 0 && calls <= 14, "priority calls: {calls}");
        assert_eq!(
            runtime
                .raw_event_backlog
                .iter()
                .map(|event| event.ts_ns)
                .collect::<Vec<_>>(),
            (1..4020).collect::<Vec<_>>()
        );
    }

    #[test]
    fn batch_priority_is_computed_once_per_event_and_ties_stay_stable() {
        let events: Vec<_> = (0..128)
            .map(|pid| RawEvent {
                pid,
                event_type: crate::platform::EventType::FileOpen,
                payload: format!("path=/tmp/file-{pid};comm=cat;parent_comm=bash"),
                uid: 1000,
                ts_ns: 1,
            })
            .collect();
        let mut expected = events.clone();
        expected.sort_by_key(|event| event.pid % 3);
        let mut calls = [0; 128];
        let sorted = prioritize_raw_events_by_key(events, |event| {
            calls[event.pid as usize] += 1;
            // Mixed keys force comparisons; payload parsing must not scale with them.
            (event.pid % 3) as u8
        });
        assert!(calls.iter().all(|&count| count == 1), "{calls:?}");
        assert_eq!(
            sorted.iter().map(|event| event.pid).collect::<Vec<_>>(),
            expected.iter().map(|event| event.pid).collect::<Vec<_>>()
        );
    }
}
