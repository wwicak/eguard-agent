use tracing::warn;

use grpc_client::ResponseEnvelope;

use super::{
    AgentRuntime, AsyncWorkerResult, PendingControlPlaneSend, PendingResponseReport,
    CONTROL_PLANE_SEND_CONCURRENCY, CONTROL_PLANE_SEND_QUEUE_CAPACITY, RESPONSE_REPORT_CONCURRENCY,
    RESPONSE_REPORT_QUEUE_CAPACITY,
};

impl AgentRuntime {
    pub(super) fn enqueue_control_plane_send(&mut self, send: PendingControlPlaneSend) {
        let kind = control_plane_send_kind(&send);
        if let Some(existing) = self
            .pending_control_plane_sends
            .iter_mut()
            .find(|existing| control_plane_send_kind(existing) == kind)
        {
            *existing = send;
            return;
        }

        if self.pending_control_plane_sends.len() >= CONTROL_PLANE_SEND_QUEUE_CAPACITY {
            warn!(
                queue_depth = self.pending_control_plane_sends.len(),
                capacity = CONTROL_PLANE_SEND_QUEUE_CAPACITY,
                "control-plane send queue reached capacity; dropping oldest pending send"
            );
            self.pending_control_plane_sends.pop_front();
        }

        self.pending_control_plane_sends.push_back(send);
    }

    pub(super) fn enqueue_response_report(&mut self, envelope: ResponseEnvelope) {
        if self.pending_response_reports.len() >= RESPONSE_REPORT_QUEUE_CAPACITY {
            warn!(
                queue_depth = self.pending_response_reports.len(),
                capacity = RESPONSE_REPORT_QUEUE_CAPACITY,
                "response report queue reached capacity; dropping oldest pending report"
            );
            self.pending_response_reports.pop_front();
        }

        self.pending_response_reports
            .push_back(PendingResponseReport { envelope });
    }

    pub(super) fn drive_async_workers(&mut self) {
        self.collect_control_plane_send_results();
        self.collect_response_report_results();
        self.dispatch_control_plane_send_tasks();
        self.dispatch_response_report_tasks();
    }

    fn collect_control_plane_send_results(&mut self) {
        while let Some(joined) = self.control_plane_send_tasks.try_join_next() {
            match joined {
                Ok(AsyncWorkerResult::ControlPlaneSend { kind, error }) => {
                    if let Some(err) = error {
                        warn!(kind, error = %err, "control-plane async send failed");
                    }
                }
                Ok(AsyncWorkerResult::ResponseReport { .. }) => {}
                Err(err) => {
                    warn!(error = %err, "control-plane async worker task join failed");
                }
            }
        }
    }

    fn collect_response_report_results(&mut self) {
        while let Some(joined) = self.response_report_tasks.try_join_next() {
            match joined {
                Ok(AsyncWorkerResult::ResponseReport { action_type, error }) => {
                    if let Some(err) = error {
                        warn!(action_type = %action_type, error = %err, "response report async send failed");
                    }
                }
                Ok(AsyncWorkerResult::ControlPlaneSend { .. }) => {}
                Err(err) => {
                    warn!(error = %err, "response report async worker task join failed");
                }
            }
        }
    }

    fn dispatch_control_plane_send_tasks(&mut self) {
        while self.control_plane_send_tasks.len() < CONTROL_PLANE_SEND_CONCURRENCY {
            let Some(send) = self.pending_control_plane_sends.pop_front() else {
                break;
            };

            let client = self.client.clone();
            self.control_plane_send_tasks.spawn(async move {
                match send {
                    PendingControlPlaneSend::Heartbeat {
                        agent_id,
                        compliance_status,
                        config_version,
                        baseline_status,
                        runtime,
                    } => {
                        let error = client
                            .send_heartbeat_with_runtime_config(
                                &agent_id,
                                &compliance_status,
                                &config_version,
                                &baseline_status,
                                Some(&runtime),
                            )
                            .await
                            .err()
                            .map(|err| err.to_string());
                        AsyncWorkerResult::ControlPlaneSend {
                            kind: "heartbeat",
                            error,
                        }
                    }
                    PendingControlPlaneSend::Compliance { envelope } => {
                        let error = client
                            .send_compliance(&envelope)
                            .await
                            .err()
                            .map(|err| err.to_string());
                        AsyncWorkerResult::ControlPlaneSend {
                            kind: "compliance",
                            error,
                        }
                    }
                    PendingControlPlaneSend::Inventory { envelope } => {
                        let error = client
                            .send_inventory(&envelope)
                            .await
                            .err()
                            .map(|err| err.to_string());
                        AsyncWorkerResult::ControlPlaneSend {
                            kind: "inventory",
                            error,
                        }
                    }
                }
            });
        }
    }

    fn dispatch_response_report_tasks(&mut self) {
        while self.response_report_tasks.len() < RESPONSE_REPORT_CONCURRENCY {
            let Some(report) = self.pending_response_reports.pop_front() else {
                break;
            };

            let client = self.client.clone();
            self.response_report_tasks.spawn(async move {
                let action_type = report.envelope.action_type.clone();
                let error = client
                    .send_response(&report.envelope)
                    .await
                    .err()
                    .map(|err| err.to_string());
                AsyncWorkerResult::ResponseReport { action_type, error }
            });
        }
    }
}

fn control_plane_send_kind(send: &PendingControlPlaneSend) -> &'static str {
    match send {
        PendingControlPlaneSend::Heartbeat { .. } => "heartbeat",
        PendingControlPlaneSend::Compliance { .. } => "compliance",
        PendingControlPlaneSend::Inventory { .. } => "inventory",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use grpc_client::{
        ComplianceEnvelope, HeartbeatAgentStatusEnvelope, HeartbeatResourceUsageEnvelope,
        HeartbeatRuntimeEnvelope, InventoryEnvelope,
    };

    fn new_runtime() -> AgentRuntime {
        let mut cfg = AgentConfig::default();
        cfg.offline_buffer_backend = "memory".to_string();
        cfg.server_addr = "127.0.0.1:1".to_string();
        cfg.self_protection_integrity_check_interval_secs = 0;
        AgentRuntime::new(cfg).expect("runtime")
    }

    fn heartbeat_send(config_version: &str, baseline_status: &str) -> PendingControlPlaneSend {
        PendingControlPlaneSend::Heartbeat {
            agent_id: "agent-1".to_string(),
            compliance_status: "ok".to_string(),
            config_version: config_version.to_string(),
            baseline_status: baseline_status.to_string(),
            runtime: HeartbeatRuntimeEnvelope {
                status: HeartbeatAgentStatusEnvelope {
                    mode: "active".to_string(),
                    ..HeartbeatAgentStatusEnvelope::default()
                },
                resource_usage: HeartbeatResourceUsageEnvelope::default(),
                buffered_events: 1,
            },
        }
    }

    fn compliance_send(status: &str) -> PendingControlPlaneSend {
        PendingControlPlaneSend::Compliance {
            envelope: ComplianceEnvelope {
                agent_id: "agent-1".to_string(),
                policy_id: "default".to_string(),
                policy_version: "v1".to_string(),
                checked_at_unix: 1_700_000_000,
                overall_status: status.to_string(),
                checks: Vec::new(),
                policy_hash: "hash".to_string(),
                schema_version: "1".to_string(),
                check_type: "overall".to_string(),
                status: status.to_string(),
                detail: status.to_string(),
                expected_value: "ok".to_string(),
                actual_value: status.to_string(),
            },
        }
    }

    #[test]
    fn enqueue_control_plane_send_replaces_heartbeat_payload_without_queue_growth() {
        let mut runtime = new_runtime();

        runtime.enqueue_control_plane_send(heartbeat_send("cfg-old", "learning"));
        runtime.enqueue_control_plane_send(heartbeat_send("cfg-new", "active"));

        assert_eq!(runtime.pending_control_plane_sends.len(), 1);
        let heartbeat = runtime
            .pending_control_plane_sends
            .front()
            .expect("queued heartbeat");
        match heartbeat {
            PendingControlPlaneSend::Heartbeat {
                config_version,
                baseline_status,
                ..
            } => {
                assert_eq!(config_version, "cfg-new");
                assert_eq!(baseline_status, "active");
            }
            other => panic!(
                "expected heartbeat send, got {}",
                control_plane_send_kind(other)
            ),
        }
    }

    #[test]
    fn enqueue_control_plane_send_replaces_only_matching_kind() {
        let mut runtime = new_runtime();

        runtime.enqueue_control_plane_send(heartbeat_send("cfg-old", "learning"));
        runtime.enqueue_control_plane_send(compliance_send("warn"));
        runtime.enqueue_control_plane_send(heartbeat_send("cfg-new", "active"));
        runtime.enqueue_control_plane_send(PendingControlPlaneSend::Inventory {
            envelope: InventoryEnvelope {
                agent_id: "agent-1".to_string(),
                os_type: "linux".to_string(),
                os_version: String::new(),
                kernel_version: String::new(),
                hostname: "host".to_string(),
                device_model: String::new(),
                device_serial: String::new(),
                user: String::new(),
                ownership: String::new(),
                disk_encrypted: false,
                jailbreak_detected: false,
                root_detected: false,
                mac: String::new(),
                ip_address: String::new(),
                collected_at_unix: 1_700_000_010,
                attributes: std::collections::HashMap::new(),
            },
        });

        assert_eq!(runtime.pending_control_plane_sends.len(), 3);
        assert!(matches!(
            runtime.pending_control_plane_sends.get(0),
            Some(PendingControlPlaneSend::Heartbeat {
                config_version,
                baseline_status,
                ..
            }) if config_version == "cfg-new" && baseline_status == "active"
        ));
        assert!(matches!(
            runtime.pending_control_plane_sends.get(1),
            Some(PendingControlPlaneSend::Compliance { envelope }) if envelope.status == "warn"
        ));
        assert!(matches!(
            runtime.pending_control_plane_sends.get(2),
            Some(PendingControlPlaneSend::Inventory { envelope }) if envelope.hostname == "host"
        ));
    }
}
