use std::collections::HashSet;
use std::time::Instant;

use anyhow::Result;
use serde_json::json;
use tokio::time::timeout;
use tracing::{info, warn};

use super::{
    coalesce_file_event_key, compute_poll_timeout, compute_sampling_stride, elapsed_micros,
    AgentRuntime, DegradedCause, EventEnvelope, RawEvent, TickEvaluation,
    DEGRADE_AFTER_SEND_FAILURES, EVENT_BATCH_SIZE,
};

const WINDOWS_SENSOR_CHILD_TTL_NS: u64 = 15 * 60 * 1_000_000_000;
const WINDOWS_SENSOR_CHILD_PID_LIMIT: usize = 4_096;
const WINDOWS_SENSOR_CHILD_PATTERNS_POWERSHELL: &[&str] = &[
    "get-mpcomputerstatus",
    "get-netfirewallprofile",
    "get-bitlockervolume",
    "get-ciminstance win32_computersystem",
    "get-ciminstance win32_networkadapterconfiguration",
    "get-ciminstance -classname win32_deviceguard",
    "get-ciminstance win32_processor",
    "get-ciminstance win32_operatingsystem",
    "get-ciminstance win32_bios",
    "get-ciminstance win32_physicalmemory",
    "get-ciminstance win32_diskdrive",
    "get-ciminstance win32_logicaldisk",
    "get-ciminstance win32_videocontroller",
    "get-netadapter",
    "confirm-securebootuefi",
    "get-tpm",
    "get-itemproperty hklm:\\software\\microsoft\\windows\\currentversion\\uninstall",
    "attacksurfacereductionrules_ids",
    "get-mppreference",
    "get-nettcpconnection -owningprocess",
    "[system.security.principal.securityidentifier]::new",
    "windowsupdate\\auto update\\rebootrequired",
];
const WINDOWS_SENSOR_CHILD_PATTERNS_REG: &[&str] = &[
    "\\windows nt\\currentversion",
    "\\control\\deviceguard",
    "\\control\\lsa",
    "\\policies\\system",
];
const WINDOWS_SENSOR_CHILD_PATTERNS_AUDITPOL: &[&str] = &["subcategory:\"process creation\""];
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
        let sampling_stride = self.sampling_stride();
        if let Some(event) = self.dequeue_sampled_raw_event(sampling_stride) {
            return Some(event);
        }

        let timeout = self.adaptive_poll_timeout();
        let polled = self.ebpf_engine.poll_once(timeout);
        self.observe_ebpf_stats();

        match polled {
            Ok(events) => self.ingest_polled_raw_events(events),
            Err(err) => {
                warn!(error = %err, "eBPF poll failed; skipping telemetry event for this tick");
                None
            }
        }
    }

    fn is_agent_self_event(event: &RawEvent) -> bool {
        event.pid == std::process::id()
    }

    fn ingest_polled_raw_events(&mut self, events: Vec<RawEvent>) -> Option<RawEvent> {
        if events.is_empty() {
            self.refresh_strict_budget_mode();
            return None;
        }

        let self_filtered = self.filter_agent_noise_events(events);
        if self_filtered.is_empty() {
            self.refresh_strict_budget_mode();
            return None;
        }

        let before = self_filtered.len();
        let file_coalesced = self.coalesce_file_event_burst(self_filtered);
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
        let retained = self.limit_raw_event_ingress(prioritized);
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

        self.dequeue_sampled_raw_event(stride)
    }

    fn filter_agent_noise_events(&mut self, events: Vec<RawEvent>) -> Vec<RawEvent> {
        let now_ns = events
            .last()
            .map(|event| event.ts_ns)
            .filter(|value| *value > 0)
            .unwrap_or_else(unix_now_ns);
        self.prune_suppressed_windows_sensor_pids(now_ns);

        let mut kept = Vec::with_capacity(events.len());
        for event in events {
            if Self::is_agent_self_event(&event)
                || self.should_suppress_sensor_child_event(&event)
                || Self::should_drop_low_value_linux_raw_event(&event)
            {
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
            if !matches!(event.event_type, crate::platform::EventType::FileOpen) {
                return false;
            }

            let path = parse_payload_field(&event.payload, "path").unwrap_or_default();
            let comm = parse_payload_field(&event.payload, "comm")
                .map(|value| value.to_ascii_lowercase())
                .unwrap_or_default();
            let parent_comm = parse_payload_field(&event.payload, "parent_comm")
                .map(|value| value.to_ascii_lowercase())
                .unwrap_or_default();

            if path == "/dev/console"
                || path == "/dev/tty"
                || path.starts_with("/dev/pts/")
            {
                return true;
            }

            if comm == "systemd" && is_low_value_linux_systemd_path(&path) {
                return true;
            }

            if parent_comm == "systemd"
                && (path.is_empty()
                    || path.starts_with("/usr/lib/systemd/")
                    || path.starts_with("/usr/lib64/systemd/"))
            {
                return true;
            }

            if is_expected_linux_auth_stack_noise(&comm, &parent_comm, &path) {
                return true;
            }

            false
        }
    }

    fn should_suppress_sensor_child_event(&mut self, event: &RawEvent) -> bool {
        let event_ns = if event.ts_ns == 0 {
            unix_now_ns()
        } else {
            event.ts_ns
        };
        self.prune_suppressed_windows_sensor_pids(event_ns);

        if matches!(event.event_type, crate::platform::EventType::ProcessExit) {
            return self
                .suppressed_windows_sensor_pids
                .remove(&event.pid)
                .is_some();
        }

        if let Some(expires_ns) = self.suppressed_windows_sensor_pids.get(&event.pid).copied() {
            if event_ns <= expires_ns {
                return true;
            }
            self.suppressed_windows_sensor_pids.remove(&event.pid);
        }

        if Self::is_known_windows_sensor_child_process(event, std::process::id()) {
            self.suppressed_windows_sensor_pids.insert(
                event.pid,
                event_ns.saturating_add(WINDOWS_SENSOR_CHILD_TTL_NS),
            );
            self.prune_suppressed_windows_sensor_pids(event_ns);
            return true;
        }

        false
    }

    fn prune_suppressed_windows_sensor_pids(&mut self, now_ns: u64) {
        self.suppressed_windows_sensor_pids
            .retain(|_, expires_ns| now_ns <= *expires_ns);
        if self.suppressed_windows_sensor_pids.len()
            > WINDOWS_SENSOR_CHILD_PID_LIMIT.saturating_mul(2)
        {
            self.suppressed_windows_sensor_pids.clear();
        }
    }

    fn is_known_windows_sensor_child_process(event: &RawEvent, agent_pid: u32) -> bool {
        if !matches!(event.event_type, crate::platform::EventType::ProcessExec) {
            return false;
        }

        let process_name = payload_process_name(&event.payload)
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default();
        if process_name.is_empty() {
            return false;
        }

        let parent_pid = parse_payload_u32_field(&event.payload, "ppid")
            .or_else(|| parse_payload_u32_field(&event.payload, "parent_pid"));
        let parent_process = parse_payload_field(&event.payload, "parent_process")
            .or_else(|| parse_payload_field(&event.payload, "parent_process_name"))
            .or_else(|| parse_payload_field(&event.payload, "parent_name"))
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default();
        let parent_name = process_basename(&parent_process).to_ascii_lowercase();
        let parent_matches = parent_pid == Some(agent_pid) || parent_name == "eguard-agent.exe";
        if !parent_matches {
            return false;
        }

        let command_line = parse_payload_field(&event.payload, "cmdline")
            .or_else(|| parse_payload_field(&event.payload, "command_line"))
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default();
        if command_line.is_empty() {
            return false;
        }

        match process_name.as_str() {
            "powershell.exe" => WINDOWS_SENSOR_CHILD_PATTERNS_POWERSHELL
                .iter()
                .any(|pattern| command_line.contains(pattern)),
            "reg.exe" => {
                command_line.contains(" query")
                    && WINDOWS_SENSOR_CHILD_PATTERNS_REG
                        .iter()
                        .any(|pattern| command_line.contains(pattern))
            }
            "auditpol.exe" => WINDOWS_SENSOR_CHILD_PATTERNS_AUDITPOL
                .iter()
                .any(|pattern| command_line.contains(pattern)),
            _ => false,
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

    fn dequeue_sampled_raw_event(&mut self, stride: usize) -> Option<RawEvent> {
        let stride = stride.max(1);

        loop {
            let Some(event) = self.raw_event_backlog.pop_front() else {
                return None;
            };

            if Self::is_agent_self_event(&event) || self.should_suppress_sensor_child_event(&event)
            {
                continue;
            }

            if stride > 1 {
                let skips = stride.saturating_sub(1).min(self.raw_event_backlog.len());
                for _ in 0..skips {
                    let _ = self.raw_event_backlog.pop_front();
                }
            }

            return Some(event);
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

    pub(super) fn enforce_raw_event_backlog_cap(&mut self) {
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

        self.metrics.telemetry_raw_backlog_dropped_total = self
            .metrics
            .telemetry_raw_backlog_dropped_total
            .saturating_add(overflow as u64);

        warn!(
            overflow,
            backlog_cap = self.raw_event_backlog_cap,
            backlog_after = self.raw_event_backlog.len(),
            backlog_dropped_total = self.metrics.telemetry_raw_backlog_dropped_total,
            "raw event backlog exceeded cap; dropped oldest events"
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
            self.raw_event_backlog.push_front(event);
        }
        self.raw_event_backlog.extend(normal);
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
        coalesce_file_event_key(event)
    }

    fn event_txn_burst_key(event: &RawEvent) -> Option<String> {
        match event.event_type {
            crate::platform::EventType::FileOpen
            | crate::platform::EventType::FileWrite
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

fn is_expected_linux_auth_stack_noise(comm: &str, parent_comm: &str, path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let process = comm.to_ascii_lowercase();
    let parent = parent_comm.to_ascii_lowercase();

    if matches!(process.as_str(), "unix_chkpwd" | "chkpwd")
        && (lower.starts_with("/etc/shadow")
            || lower.starts_with("/etc/gshadow")
            || lower.starts_with("/etc/master.passwd"))
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

fn is_low_value_linux_systemd_path(path: &str) -> bool {
    path.is_empty()
        || !path.starts_with('/')
        || path.starts_with("/sys/fs/cgroup/")
        || path.starts_with("/proc/self/")
        || path.starts_with("/proc/")
        || path.starts_with("/run/udev/data/")
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

fn payload_process_name(payload: &str) -> Option<String> {
    parse_payload_field(payload, "path")
        .or_else(|| parse_payload_field(payload, "exe"))
        .or_else(|| parse_payload_field(payload, "process_path"))
        .or_else(|| parse_payload_field(payload, "process_image"))
        .map(|value| process_basename(&value).to_string())
        .or_else(|| {
            parse_payload_field(payload, "cmdline")
                .or_else(|| parse_payload_field(payload, "command_line"))
                .and_then(|value| {
                    value
                        .split(['\0', ' '])
                        .find(|segment| !segment.trim().is_empty())
                        .map(|segment| process_basename(segment).to_string())
                })
        })
}

fn process_basename(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
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
