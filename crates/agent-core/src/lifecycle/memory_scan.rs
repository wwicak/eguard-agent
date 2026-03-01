use tracing::{info, warn};

use detection::memory_scanner::{find_suspicious_pids, MemoryScanResult, ScanMode};
use detection::{Confidence, EventClass, TelemetryEvent};
use response::plan_action;

use super::{interval_due, AgentRuntime};

impl AgentRuntime {
    pub(super) async fn run_memory_scan_if_due(&mut self, now_unix: i64) {
        if !self.config.detection_memory_scan_enabled {
            return;
        }
        if !interval_due(
            self.last_memory_scan_unix,
            now_unix,
            self.config.detection_memory_scan_interval_secs as i64,
        ) {
            return;
        }
        self.last_memory_scan_unix = Some(now_unix);

        let mode = match self.config.detection_memory_scan_mode.as_str() {
            "all" => ScanMode::AllReadable,
            "exec+anon" => ScanMode::ExecutableAndAnonymous,
            _ => ScanMode::ExecutableOnly,
        };

        let mut pids = match find_suspicious_pids() {
            Ok(list) => list,
            Err(err) => {
                warn!(error = %err, "memory scan failed to enumerate pids");
                return;
            }
        };

        if pids.len() > self.config.detection_memory_scan_max_pids {
            pids.truncate(self.config.detection_memory_scan_max_pids);
        }

        if std::env::var("EGUARD_DEBUG_EVENT_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(pids = ?pids, "debug memory scan pids");
        }

        let mut detections = Vec::new();
        for pid in pids {
            match self.detection_state.scan_process_memory(pid, mode) {
                Ok(res) => {
                    if std::env::var("EGUARD_DEBUG_EVENT_LOG")
                        .ok()
                        .filter(|v| !v.trim().is_empty())
                        .is_some()
                    {
                        info!(
                            pid = res.pid,
                            hits = res.hits.len(),
                            regions_scanned = res.regions_scanned,
                            bytes_scanned = res.bytes_scanned,
                            errors = res.errors.len(),
                            "debug memory scan result"
                        );
                    }
                    if !res.hits.is_empty() {
                        detections.push(res);
                    }
                }
                Err(err) => {
                    warn!(pid = pid, error = %err, "memory scan failed on shard");
                }
            }
        }
        for detection in detections {
            self.handle_memory_scan_detection(&detection, now_unix).await;
        }
    }

    async fn handle_memory_scan_detection(&mut self, detection: &MemoryScanResult, now_unix: i64) {
        let mut notes = Vec::new();
        notes.push(format!("memory_hits={}", detection.hits.len()));
        notes.push(format!("bytes_scanned={}", detection.bytes_scanned));
        if let Some(first) = detection.hits.first() {
            notes.push(format!("rule_name={}", first.rule_name));
            notes.push(format!("matched_literal={}", first.matched_literal));
            notes.push(format!("region_perms={}", first.region_perms));
        }
        if !detection.errors.is_empty() {
            notes.push(format!("scan_errors={}", detection.errors.len()));
        }

        let event = TelemetryEvent {
            ts_unix: now_unix,
            event_class: EventClass::Alert,
            pid: detection.pid,
            ppid: 0,
            uid: 0,
            process: "memory_scan".to_string(),
            parent_process: String::new(),
            session_id: detection.pid,
            file_path: None,
            file_write: false,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: Some(notes.join(";")),
            event_size: Some(detection.bytes_scanned),
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let detection_outcome = match self.detection_state.process_event(&event) {
            Ok(outcome) => outcome,
            Err(err) => {
                warn!(error = %err, "memory scan event processing failed");
                return;
            }
        };

        let confidence = detection_outcome.confidence.max(Confidence::VeryHigh);
        if std::env::var("EGUARD_DEBUG_EVENT_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            let rule_name = detection
                .hits
                .first()
                .map(|hit| hit.rule_name.clone())
                .unwrap_or_default();
            let matched_literal = detection
                .hits
                .first()
                .map(|hit| hit.matched_literal.clone())
                .unwrap_or_default();
            info!(
                event_class = ?event.event_class,
                pid = event.pid,
                confidence = ?confidence,
                rule_name = %rule_name,
                matched_literal = %matched_literal,
                "debug memory scan detection"
            );
        }
        let response_cfg = self.effective_response_config();
        let action = plan_action(confidence, &response_cfg);
        let rule_name = detection
            .hits
            .first()
            .map(|hit| hit.rule_name.clone())
            .unwrap_or_default();
        self.report_local_action_if_needed(
            action,
            confidence,
            &event,
            now_unix,
            (&["BEH_behavioral".to_string()], &rule_name, "behavioral"),
        )
        .await;
    }
}
