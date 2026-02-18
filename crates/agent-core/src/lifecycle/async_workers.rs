use tracing::warn;

use grpc_client::ResponseEnvelope;

use super::{
    AgentRuntime, AsyncWorkerResult, PendingControlPlaneSend, PendingResponseReport,
    CONTROL_PLANE_SEND_CONCURRENCY, CONTROL_PLANE_SEND_QUEUE_CAPACITY, RESPONSE_REPORT_CONCURRENCY,
    RESPONSE_REPORT_QUEUE_CAPACITY,
};

impl AgentRuntime {
    pub(super) fn enqueue_control_plane_send(&mut self, send: PendingControlPlaneSend) {
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
                    } => {
                        let error = client
                            .send_heartbeat_with_config(
                                &agent_id,
                                &compliance_status,
                                &config_version,
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
