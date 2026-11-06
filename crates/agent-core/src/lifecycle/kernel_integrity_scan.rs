use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tracing::{info, warn};

use detection::{Confidence, EventClass, TelemetryEvent};

use crate::platform::{
    scan_kernel_integrity, EnrichedEvent, EventType, KernelIntegrityScanOptions, RawEvent,
};

use super::detection_event::confidence_to_severity;
use super::{interval_due, AgentRuntime};

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

        let mut report = match scan_kernel_integrity(&KernelIntegrityScanOptions::from_env()) {
            Ok(report) => report,
            Err(err) => {
                warn!(error = %err, "kernel integrity scan failed");
                return;
            }
        };
        // RAFIX shared: baseline/dedupe survives restarts; transient discrepancies do not alert.
        let state_path = Path::new(&self.config.offline_buffer_path)
            .with_file_name("kernel-integrity-state.json");
        let mut state = self.kernel_integrity_scan_state.clone().unwrap_or_else(|| {
            std::fs::read(&state_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default()
        });
        report.indicators = state.filter(&report.indicators, now_unix);
        self.kernel_integrity_scan_state = Some(state.clone());
        let current: BTreeSet<String> = report.indicators.iter().cloned().collect();
        if report.indicators.is_empty() || state.last_emitted == current {
            state.last_emitted = current;
            save_scan_state(&state_path, &state);
            self.kernel_integrity_scan_state = Some(state);
            return;
        }
        let mut comparison_report = report.clone();
        comparison_report.indicators.sort();
        #[cfg(target_os = "linux")]
        comparison_report.bpffs_objects.sort();
        self.last_kernel_integrity_report = Some(comparison_report);

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
            // RAFIX shared: default optional image and unlink semantics in existing fixtures.
            process_exe: None,
            file_unlink: false,
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

        // RAFIX shared: inventory/tracing context must never be forced HIGH.
        let confidence =
            detection::kernel_integrity_confidence(&outcome.kernel_integrity_indicators);
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
                fields: Default::default(),
                pid_start_ns: None,
                ppid_start_ns: None,
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

        let event_txn = super::EventTxn::from_enriched(&enriched, &event, now_unix);
        self.metrics.telemetry_event_txn_total =
            self.metrics.telemetry_event_txn_total.saturating_add(1);
        let mut event_envelope = self.build_event_envelope(
            &enriched, &event, &outcome, &event_txn, confidence, now_unix,
        );
        event_envelope.event_type = event.event_class.as_str().to_string();
        event_envelope.severity = confidence_to_severity(confidence).to_string();
        if let Some(rule_name) = Self::detection_rule_name(&outcome) {
            event_envelope.rule_name = rule_name;
        }

        match self.buffer.enqueue(event_envelope) {
            Ok(_) => {
                state.last_emitted = current;
                save_scan_state(&state_path, &state);
                self.kernel_integrity_scan_state = Some(state);
            }
            Err(err) => warn!(error = %err, "kernel integrity scan enqueue failed"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct KernelScanState {
    initialized: bool,
    baseline: BTreeSet<String>,
    first_seen: BTreeMap<String, i64>,
    last_emitted: BTreeSet<String>,
}
impl KernelScanState {
    fn filter(&mut self, indicators: &[String], now: i64) -> Vec<String> {
        let inventory = |i: &str| {
            (i.starts_with("unsigned_oot_module:") || i.starts_with("bpffs_pinned_object:"))
                && detection::kernel_integrity_confidence(&[i.to_string()]) < Confidence::High
        };
        if !self.initialized {
            self.baseline = indicators
                .iter()
                .filter(|i| inventory(i))
                .cloned()
                .collect();
            self.initialized = true;
        }
        self.first_seen.retain(|i, _| indicators.contains(i));
        let filtered = indicators
            .iter()
            .filter(|i| {
                if inventory(i) && self.baseline.contains(*i) {
                    return false;
                }
                let persistent = i.starts_with("hidden_module_") || i.starts_with("ftrace_");
                let first = self.first_seen.entry((*i).clone()).or_insert(now);
                if now < *first {
                    *first = now;
                }
                !persistent || now.saturating_sub(*first) >= 2
            })
            .cloned()
            .collect();
        filtered
    }
}
fn save_scan_state(path: &Path, state: &KernelScanState) {
    use std::io::Write;
    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let save = || -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&serde_json::to_vec(state)?)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    if let Err(err) = save() {
        let _ = std::fs::remove_file(&tmp);
        warn!(error = %err, "kernel integrity state persistence failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rafix_kernel_scan_baseline_confirmation_and_restart_dedupe() {
        let initial = vec![
            "unsigned_oot_module:nvidia".into(),
            "bpffs_pinned_object:vendor_pin".into(),
            "hidden_module_sysfs:transient".into(),
        ];
        let mut state = KernelScanState::default();
        assert!(state.filter(&initial, 10).is_empty());
        assert!(
            state.filter(&initial[..2], 20).is_empty(),
            "load/unload race disappeared"
        );
        let stable = vec![
            "hidden_module_sysfs:rootkit".into(),
            "ftrace_filter_count:1".into(),
            "unsigned_oot_module:diamorphine".into(),
        ];
        assert_eq!(
            state.filter(&stable, 30),
            ["unsigned_oot_module:diamorphine"]
        );
        let confirmed = state.filter(&stable, 33);
        assert_eq!(confirmed, stable);
        state.last_emitted = confirmed.into_iter().collect();
        let bytes = serde_json::to_vec(&state).unwrap();
        let mut restarted: KernelScanState = serde_json::from_slice(&bytes).unwrap();
        let same: BTreeSet<_> = restarted.filter(&stable, 36).into_iter().collect();
        assert_eq!(same, restarted.last_emitted, "restart does not re-alert");
        assert_eq!(
            restarted.filter(&["bpffs_pinned_object:lsm_hide".into()], 40),
            ["bpffs_pinned_object:lsm_hide"]
        );
    }
}
