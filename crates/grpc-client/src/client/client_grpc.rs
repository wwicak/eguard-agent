use std::time::Duration;

use anyhow::{Context, Result};
use tokio_stream::iter;
use tonic::transport::Channel;
use tracing::warn;

use crate::pb;
use crate::types::{
    CertificatePolicyEnvelope, CommandEnvelope, ComplianceEnvelope, EnrollmentEnvelope,
    EnrollmentResultEnvelope, EventEnvelope, InventoryEnvelope, PolicyEnvelope, ResponseEnvelope,
    ServerState, ThreatIntelVersionEnvelope,
};

use super::{
    from_pb_agent_command, from_pb_server_command, map_response_action, map_response_confidence,
    now_unix, to_pb_telemetry_event, Client, MAX_GRPC_RECV_MSG_SIZE_BYTES,
};

impl Client {
    pub(super) async fn send_events_grpc(&self, batch: &[EventEnvelope]) -> Result<()> {
        self.with_retry("send_events_grpc_stream", || async {
            let mut client = self.telemetry_client().await?;
            let events: Vec<pb::TelemetryEvent> = batch.iter().map(to_pb_telemetry_event).collect();
            let telemetry_batch = pb::TelemetryBatch {
                agent_id: batch
                    .first()
                    .map(|e| e.agent_id.clone())
                    .unwrap_or_default(),
                events,
                compressed: false,
                events_compressed: Vec::new(),
            };
            let stream = iter([telemetry_batch]);
            client
                .stream_events(tonic::Request::new(stream))
                .await
                .context("stream_events RPC failed")?;
            Ok(())
        })
        .await
    }

    pub(super) async fn enroll_grpc(
        &self,
        enrollment: &EnrollmentEnvelope,
    ) -> Result<Option<EnrollmentResultEnvelope>> {
        self.with_retry("enroll_grpc", || async {
            if enrollment.enrollment_token.is_some() {
                warn!("sending enrollment token via EnrollRequest");
            }

            let mut client = self.agent_control_client().await?;
            let response = client
                .enroll(pb::EnrollRequest {
                    enrollment_token: enrollment.enrollment_token.clone().unwrap_or_default(),
                    hostname: enrollment.hostname.clone(),
                    mac_address: enrollment.mac.clone(),
                    os_type: "linux".to_string(),
                    os_version: String::new(),
                    kernel_version: String::new(),
                    agent_version: self.agent_version.clone(),
                    machine_id: String::new(),
                    // Send empty CSR unless client cert bootstrap is wired; server falls back to static cert material.
                    csr: Vec::new(),
                    capabilities: Some(pb::AgentCapabilities {
                        ebpf_supported: true,
                        lsm_supported: true,
                        yara_supported: true,
                        ebpf_programs: Vec::new(),
                    }),
                    tenant_id: enrollment.tenant_id.clone().unwrap_or_default(),
                    agent_id: enrollment.agent_id.clone(),
                    mac: enrollment.mac.clone(),
                })
                .await
                .context("enroll RPC failed")?
                .into_inner();
            Ok(Some(EnrollmentResultEnvelope {
                agent_id: response.agent_id,
                signed_certificate: response.signed_certificate,
                ca_certificate: response.ca_certificate,
                initial_policy: response.initial_policy,
            }))
        })
        .await
    }

    pub(super) async fn send_heartbeat_grpc(
        &self,
        agent_id: &str,
        compliance_status: &str,
        config_version: &str,
    ) -> Result<()> {
        self.with_retry("heartbeat_grpc", || async {
            let mut client = self.agent_control_client().await?;
            client
                .heartbeat(pb::HeartbeatRequest {
                    agent_id: agent_id.to_string(),
                    timestamp: now_unix(),
                    agent_version: self.agent_version.clone(),
                    status: None,
                    resource_usage: None,
                    baseline_report: None,
                    config_version: config_version.to_string(),
                    buffered_events: 0,
                    compliance_status: compliance_status.to_string(),
                    sent_at_unix: now_unix(),
                })
                .await
                .context("heartbeat RPC failed")?;
            Ok(())
        })
        .await
    }

    pub(super) async fn send_compliance_grpc(&self, compliance: &ComplianceEnvelope) -> Result<()> {
        self.with_retry("compliance_grpc", || async {
            let mut client = self.compliance_client().await?;
            let checked_at = if compliance.checked_at_unix > 0 {
                compliance.checked_at_unix
            } else {
                now_unix()
            };
            let checks = compliance
                .checks
                .iter()
                .map(|check| pb::ComplianceCheckResult {
                    check_type: check.check_type.clone(),
                    status: map_check_status(&check.status) as i32,
                    actual_value: check.actual_value.clone(),
                    expected_value: check.expected_value.clone(),
                    detail: check.detail.clone(),
                    auto_remediated: check.auto_remediated,
                    remediation_detail: check.remediation_detail.clone(),
                    check_id: check.check_id.clone(),
                    severity: check.severity.clone(),
                    evidence_json: check.evidence_json.clone(),
                    evidence_source: check.evidence_source.clone(),
                    collected_at_unix: check.collected_at_unix,
                    grace_expires_at_unix: check.grace_expires_at_unix,
                    remediation_action_id: check.remediation_action_id.clone(),
                })
                .collect::<Vec<_>>();
            let overall_status =
                map_overall_status(&compliance.overall_status, &compliance.status) as i32;
            client
                .report_compliance(pb::ComplianceReport {
                    agent_id: compliance.agent_id.clone(),
                    policy_id: compliance.policy_id.clone(),
                    policy_version: compliance.policy_version.clone(),
                    checked_at,
                    checks,
                    overall_status,
                    policy_hash: compliance.policy_hash.clone(),
                    schema_version: compliance.schema_version.clone(),
                    check_type: compliance.check_type.clone(),
                    status: compliance.status.clone(),
                    detail: compliance.detail.clone(),
                    expected_value: compliance.expected_value.clone(),
                    actual_value: compliance.actual_value.clone(),
                    checked_at_unix: checked_at,
                })
                .await
                .context("report_compliance RPC failed")?;
            Ok(())
        })
        .await
    }

    pub(super) async fn send_inventory_grpc(&self, inventory: &InventoryEnvelope) -> Result<()> {
        self.with_retry("inventory_grpc", || async {
            let mut client = self.telemetry_client().await?;
            client
                .report_inventory(pb::InventoryReport {
                    agent_id: inventory.agent_id.clone(),
                    os_type: inventory.os_type.clone(),
                    os_version: inventory.os_version.clone(),
                    kernel_version: inventory.kernel_version.clone(),
                    hostname: inventory.hostname.clone(),
                    device_model: inventory.device_model.clone(),
                    device_serial: inventory.device_serial.clone(),
                    user: inventory.user.clone(),
                    ownership: inventory.ownership.clone(),
                    disk_encrypted: inventory.disk_encrypted,
                    jailbreak_detected: inventory.jailbreak_detected,
                    root_detected: inventory.root_detected,
                    mac: inventory.mac.clone(),
                    ip_address: inventory.ip_address.clone(),
                    collected_at_unix: inventory.collected_at_unix,
                    attributes: inventory.attributes.clone(),
                })
                .await
                .context("report_inventory RPC failed")?;
            Ok(())
        })
        .await
    }

    pub(super) async fn send_response_grpc(&self, response: &ResponseEnvelope) -> Result<()> {
        self.with_retry("response_grpc", || async {
            let mut client = self.response_client().await?;
            client
                .report_response(pb::ResponseReport {
                    agent_id: response.agent_id.clone(),
                    alert_id: String::new(),
                    action: map_response_action(&response.action_type) as i32,
                    confidence: map_response_confidence(&response.confidence) as i32,
                    detection_layers: Vec::new(),
                    detection_to_action_us: 0,
                    success: response.success,
                    error_message: response.error_message.clone(),
                    timestamp: now_unix(),
                    detail: None,
                    detail_text: response.error_message.clone(),
                    created_at_unix: now_unix(),
                })
                .await
                .context("report_response RPC failed")?;
            Ok(())
        })
        .await
    }

    pub(super) async fn stream_command_channel_grpc(
        &self,
        agent_id: &str,
        completed_command_ids: &[String],
        limit: usize,
    ) -> Result<Vec<CommandEnvelope>> {
        self.with_retry("command_channel_grpc", || async {
            let mut client = self.command_client().await?;
            let response = client
                .command_channel(pb::CommandPollRequest {
                    agent_id: agent_id.to_string(),
                    completed_command_ids: completed_command_ids.to_vec(),
                })
                .await
                .context("command_channel RPC failed")?;

            let mut stream = response.into_inner();
            let mut out = Vec::with_capacity(limit);
            while out.len() < limit {
                match tokio::time::timeout(Duration::from_millis(350), stream.message()).await {
                    Ok(Ok(Some(command))) => out.push(from_pb_server_command(command)),
                    Ok(Ok(None)) => break,
                    Ok(Err(err)) => {
                        return Err(err).context("command_channel stream read failed");
                    }
                    Err(_) => break,
                }
            }

            Ok(out)
        })
        .await
    }

    pub(super) async fn poll_commands_grpc(
        &self,
        agent_id: &str,
        limit: usize,
    ) -> Result<Vec<CommandEnvelope>> {
        self.with_retry("fetch_commands_grpc", || async {
            let mut client = self.command_client().await?;
            let response = client
                .poll_commands(pb::PollCommandsRequest {
                    agent_id: agent_id.to_string(),
                    limit: limit as i32,
                })
                .await
                .context("poll_commands RPC failed")?
                .into_inner();

            Ok(response
                .commands
                .into_iter()
                .map(from_pb_agent_command)
                .collect::<Vec<_>>())
        })
        .await
    }

    pub(super) async fn ack_command_grpc(
        &self,
        agent_id: &str,
        command_id: &str,
        status: &str,
    ) -> Result<()> {
        self.with_retry("ack_command_grpc", || async {
            let mut client = self.command_client().await?;
            client
                .ack_command(pb::AckCommandRequest {
                    command_id: command_id.to_string(),
                    status: status.to_string(),
                    agent_id: agent_id.to_string(),
                })
                .await
                .context("ack_command RPC failed")?;
            Ok(())
        })
        .await
    }

    pub(super) async fn fetch_latest_threat_intel_grpc(
        &self,
    ) -> Result<Option<ThreatIntelVersionEnvelope>> {
        self.with_retry("threat_intel_grpc", || async {
            let mut client = self.agent_control_client().await?;
            let res = client
                .get_latest_threat_intel(pb::ThreatIntelRequest {
                    agent_id: String::new(),
                })
                .await
                .context("get_latest_threat_intel RPC failed")?
                .into_inner();
            Ok(map_threat_intel_response(res))
        })
        .await
    }

    pub(super) async fn check_server_state_grpc(&self) -> Result<Option<ServerState>> {
        self.with_retry("check_state_grpc", || async {
            let mut client = self.agent_control_client().await?;
            let res = client
                .ping(pb::PingRequest {
                    agent_id: String::new(),
                })
                .await
                .context("ping RPC failed")?
                .into_inner();

            if res.status.is_empty() {
                Ok(None)
            } else {
                Ok(Some(ServerState {
                    persistence_enabled: false,
                }))
            }
        })
        .await
    }

    pub(super) async fn fetch_policy_grpc(&self, agent_id: &str) -> Result<Option<PolicyEnvelope>> {
        self.with_retry("fetch_policy_grpc", || async {
            let mut client = self.agent_service_client().await?;
            let response = client
                .get_policy(pb::PolicyRequest {
                    agent_id: agent_id.to_string(),
                })
                .await
                .context("get_policy RPC failed")?
                .into_inner();

            let cert_policy = response
                .certificate_policy
                .map(|policy| CertificatePolicyEnvelope {
                    pinned_ca_sha256: policy.pinned_ca_sha256,
                    rotate_before_expiry_days: policy.rotate_before_expiry_days,
                    seamless_rotation: policy.seamless_rotation,
                    require_client_cert_for_all_rpcs_except_enroll: policy
                        .require_client_cert_for_all_rpcs_except_enroll,
                    grpc_max_recv_msg_size_bytes: policy.grpc_max_recv_msg_size_bytes,
                    grpc_port: policy.grpc_port,
                });

            if response.policy_id.trim().is_empty()
                && response.config_version.trim().is_empty()
                && response.policy_json.trim().is_empty()
                && cert_policy.is_none()
            {
                Ok(None)
            } else {
                Ok(Some(PolicyEnvelope {
                    policy_id: response.policy_id,
                    config_version: response.config_version,
                    policy_json: response.policy_json,
                    certificate_policy: cert_policy,
                    policy_version: response.policy_version,
                    policy_hash: response.policy_hash,
                    policy_signature: response.policy_signature,
                    schema_version: response.schema_version,
                    issued_at_unix: response.issued_at_unix,
                }))
            }
        })
        .await
    }

    async fn telemetry_client(
        &self,
    ) -> Result<pb::telemetry_service_client::TelemetryServiceClient<Channel>> {
        let channel = self.connect_channel().await?;
        Ok(
            pb::telemetry_service_client::TelemetryServiceClient::new(channel)
                .max_decoding_message_size(MAX_GRPC_RECV_MSG_SIZE_BYTES),
        )
    }

    async fn command_client(
        &self,
    ) -> Result<pb::command_service_client::CommandServiceClient<Channel>> {
        let channel = self.connect_channel().await?;
        Ok(
            pb::command_service_client::CommandServiceClient::new(channel)
                .max_decoding_message_size(MAX_GRPC_RECV_MSG_SIZE_BYTES),
        )
    }

    async fn compliance_client(
        &self,
    ) -> Result<pb::compliance_service_client::ComplianceServiceClient<Channel>> {
        let channel = self.connect_channel().await?;
        Ok(
            pb::compliance_service_client::ComplianceServiceClient::new(channel)
                .max_decoding_message_size(MAX_GRPC_RECV_MSG_SIZE_BYTES),
        )
    }

    async fn response_client(
        &self,
    ) -> Result<pb::response_service_client::ResponseServiceClient<Channel>> {
        let channel = self.connect_channel().await?;
        Ok(
            pb::response_service_client::ResponseServiceClient::new(channel)
                .max_decoding_message_size(MAX_GRPC_RECV_MSG_SIZE_BYTES),
        )
    }

    async fn agent_control_client(
        &self,
    ) -> Result<pb::agent_control_service_client::AgentControlServiceClient<Channel>> {
        let channel = self.connect_channel().await?;
        Ok(
            pb::agent_control_service_client::AgentControlServiceClient::new(channel)
                .max_decoding_message_size(MAX_GRPC_RECV_MSG_SIZE_BYTES),
        )
    }

    async fn agent_service_client(
        &self,
    ) -> Result<pb::agent_service_client::AgentServiceClient<Channel>> {
        let channel = self.connect_channel().await?;
        Ok(pb::agent_service_client::AgentServiceClient::new(channel)
            .max_decoding_message_size(MAX_GRPC_RECV_MSG_SIZE_BYTES))
    }
}

fn map_threat_intel_response(res: pb::ThreatIntelVersion) -> Option<ThreatIntelVersionEnvelope> {
    if res.version.is_empty() {
        return None;
    }

    Some(ThreatIntelVersionEnvelope {
        version: res.version,
        bundle_path: res.bundle_path,
        published_at_unix: res.published_at_unix,
        sigma_count: res.sigma_count,
        yara_count: res.yara_count,
        ioc_count: res.ioc_count,
        cve_count: res.cve_count,
        custom_rule_count: res.custom_rule_count,
        custom_rule_version_hash: res.custom_rule_version_hash,
        bundle_signature_path: res.bundle_signature_path,
        bundle_sha256: res.bundle_sha256,
    })
}

fn map_check_status(raw: &str) -> pb::CheckStatus {
    match raw.trim().to_ascii_lowercase().as_str() {
        "pass" | "ok" | "compliant" => pb::CheckStatus::Pass,
        "fail" | "non_compliant" | "non-compliant" => pb::CheckStatus::Fail,
        "not_applicable" | "na" | "n/a" => pb::CheckStatus::NotApplicable,
        "in_grace" | "grace" => pb::CheckStatus::InGrace,
        _ => pb::CheckStatus::CheckError,
    }
}

fn map_overall_status(overall: &str, fallback: &str) -> pb::ComplianceStatus {
    let candidate = if overall.trim().is_empty() {
        fallback
    } else {
        overall
    };
    match candidate.trim().to_ascii_lowercase().as_str() {
        "pass" | "compliant" | "in_grace" | "grace" => pb::ComplianceStatus::Compliant,
        "fail" | "non_compliant" | "non-compliant" => pb::ComplianceStatus::NonCompliant,
        _ => pb::ComplianceStatus::Error,
    }
}
