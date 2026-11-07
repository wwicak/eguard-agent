use tracing::{info, warn};

use detection::memory_scanner::{find_suspicious_pids, MemoryScanResult, ScanMode};

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
            self.handle_memory_scan_detection(&detection, now_unix)
                .await;
        }
    }

    async fn handle_memory_scan_detection(&mut self, detection: &MemoryScanResult, now_unix: i64) {
        if detection.hits.is_empty() {
            return;
        }
        // Memory substring hits are alert-only, never autonomous response evidence.
        let strong = detection.hits.iter().any(|hit| {
            hit.region_perms.as_bytes().get(2) == Some(&b'x')
                && (hit.region_path.is_empty()
                    || hit.region_path.starts_with('[')
                    || hit.region_path.contains("memfd:"))
        });
        let confidence = if strong { "high" } else { "medium" };
        let hits: Vec<_> = detection
            .hits
            .iter()
            .map(|hit| {
                serde_json::json!({
                    "rule_name": hit.rule_name, "region_start": hit.region_start,
                    "region_perms": hit.region_perms, "region_path": hit.region_path,
                })
            })
            .collect();
        let rule_name = format!("memory:{}", detection.hits[0].rule_name);
        let envelope = grpc_client::EventEnvelope {
            agent_id: self.config.agent_id.clone(),
            event_type: "alert".into(),
            severity: confidence.into(),
            rule_name,
            created_at_unix: now_unix,
            payload_json: serde_json::json!({
                "observed_at_unix": now_unix,
                "event": { "event_class": "alert", "ts_unix": now_unix,
                    "pid": detection.pid, "process": "memory_scan", "file_write": false },
                "detection": { "confidence": confidence, "rule_type": "memory",
                    "detection_layers": ["memory_scan"], "memory_scan_hits": hits,
                    "bytes_scanned": detection.bytes_scanned, "scan_errors": detection.errors.len(),
                    "signals": detection::DetectionSignals::default() },
            })
            .to_string(),
        };
        if let Err(err) = self.buffer.enqueue(envelope) {
            warn!(error = %err, "memory scan alert enqueue failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use detection::memory_scanner::MemoryYaraHit;

    #[tokio::test]
    async fn rafix_memory_hits_are_reported_without_destructive_response() {
        let root = std::env::temp_dir().join(format!("rafix-memory-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let replay = root.join("replay");
        std::fs::write(&replay, "").unwrap();
        let _guard = crate::test_support::TestEnvGuard::new(&[
            "EGUARD_EBPF_REPLAY_PATH",
            "EGUARD_AGENT_DATA_DIR",
            "EGUARD_BASELINE_PATH",
        ]);
        std::env::set_var("EGUARD_EBPF_REPLAY_PATH", &replay);
        std::env::set_var("EGUARD_AGENT_DATA_DIR", &root);
        std::env::set_var("EGUARD_BASELINE_PATH", root.join("baseline.bin"));
        let mut runtime = AgentRuntime::new(crate::config::AgentConfig {
            offline_buffer_backend: "memory".into(),
            server_addr: "127.0.0.1:1".into(),
            ..Default::default()
        })
        .unwrap();
        for (region_path, expected) in [
            ("", "high"),
            ("/memfd:stage (deleted)", "high"),
            ("/usr/lib/libfixture.so", "medium"),
        ] {
            let result = MemoryScanResult {
                pid: 424242,
                regions_scanned: 1,
                bytes_scanned: 4096,
                errors: vec![],
                hits: vec![MemoryYaraHit {
                    rule_name: "synthetic_memory_rule".into(),
                    matched_literal: "fixture".into(),
                    region_start: 0x1000,
                    region_perms: "r-xp".into(),
                    region_path: region_path.into(),
                }],
            };
            let before = runtime.buffer.pending_count();
            runtime.handle_memory_scan_detection(&result, 1).await;
            assert_eq!(
                runtime.buffer.pending_count(),
                before + 1,
                "memory hit was silently dropped"
            );
            let events = runtime.buffer.peek_batch(10).unwrap();
            assert_eq!(events.last().unwrap().1.severity, expected);
            let payload: serde_json::Value =
                serde_json::from_str(&events.last().unwrap().1.payload_json).unwrap();
            assert_eq!(
                payload["detection"]["memory_scan_hits"][0]["rule_name"],
                "synthetic_memory_rule"
            );
            assert!(runtime.pending_response_actions.is_empty());
        }
        let empty = MemoryScanResult {
            pid: 1,
            hits: vec![],
            regions_scanned: 1,
            bytes_scanned: 4096,
            errors: vec![],
        };
        runtime.handle_memory_scan_detection(&empty, 1).await;
        assert_eq!(runtime.buffer.pending_count(), 3);
        let _ = std::fs::remove_dir_all(root);
    }
}
