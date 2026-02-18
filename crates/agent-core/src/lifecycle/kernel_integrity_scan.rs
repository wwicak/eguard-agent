use tracing::{info, warn};

use detection::{Confidence, EventClass, TelemetryEvent};
use platform_linux::{scan_kernel_integrity, EnrichedEvent, EventType, KernelIntegrityScanOptions, RawEvent};

use super::{interval_due, AgentRuntime};
use super::detection_event::confidence_to_severity;

impl AgentRuntime {
    pub(super) fn run_kernel_integrity_scan_if_due(&mut self, now_unix: i64) {
        if !self.config.detection_kernel_integrity_enabled {
            return;
        }
        if !interval_due(
            self.last_kernel_integrity_scan_unix,
            now_unix,
            self.config.detection_kernel_integrity_interval_secs as i64,
        ) {
            return;
        }
        self.last_kernel_integrity_scan_unix = Some(now_unix);

        let report = match scan_kernel_integrity(&KernelIntegrityScanOptions::from_env()) {
            Ok(report) => report,
            Err(err) => {
                warn!(error = %err, "kernel integrity scan failed");
                return;
            }
        };
        if report.indicators.is_empty() {
            return;
        }

        let event = TelemetryEvent {
            ts_unix: now_unix,
            event_class: EventClass::Alert,
            pid: 0,
            ppid: 0,
            uid: 0,
            process: "kernel_integrity_scan".to_string(),
            parent_process: String::new(),
            session_id: 0,
            file_path: None,
            file_write: false,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: Some(report.command_line()),
            event_size: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let outcome = match self.detection_state.process_event(&event) {
            Ok(outcome) => outcome,
            Err(err) => {
                warn!(error = %err, "kernel integrity scan detection failed");
                return;
            }
        };
        if outcome.kernel_integrity_indicators.is_empty() {
            return;
        }

        let confidence = outcome.confidence.max(Confidence::High);
        if std::env::var("EGUARD_DEBUG_EVENT_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(
                indicators = ?outcome.kernel_integrity_indicators,
                confidence = ?confidence,
                "debug kernel integrity scan detection"
            );
        }

        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::ProcessExec,
                pid: 0,
                uid: 0,
                ts_ns: (now_unix.max(0) as u64) * 1_000_000_000,
                payload: String::new(),
            },
            process_exe: None,
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: None,
            parent_chain: Vec::new(),
            file_path: None,
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let mut event_envelope = self.build_event_envelope(
            &enriched,
            &event,
            &outcome,
            confidence,
            now_unix,
        );
        event_envelope.event_type = event.event_class.as_str().to_string();
        event_envelope.severity = confidence_to_severity(confidence).to_string();
        if let Some(rule_name) = Self::detection_rule_name(&outcome) {
            event_envelope.rule_name = rule_name;
        }

        if let Err(err) = self.buffer.enqueue(event_envelope) {
            warn!(error = %err, "kernel integrity scan enqueue failed");
        }
    }
}
