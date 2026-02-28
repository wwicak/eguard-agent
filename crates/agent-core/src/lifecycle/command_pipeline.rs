use std::time::Duration;

use anyhow::{anyhow, Result};
use grpc_client::{CommandEnvelope, ResponseEnvelope};
use response::{
    execute_server_command_with_state, parse_server_command, CommandOutcome, ServerCommand,
};
use tokio::time::timeout;
use tracing::{info, warn};

use crate::detection_state::EmergencyRule;

use super::{parse_emergency_rule_type, AgentRuntime, EmergencyRulePayload};

mod app_management;
mod command_utils;
mod handlers;
mod paths;
mod payloads;
mod sanitize;
#[cfg(test)]
mod tests;
#[cfg(target_os = "windows")]
mod windows_network_profile;

const COMPLETED_COMMAND_CURSOR_CAP: usize = 256;
const COMMAND_ACK_TIMEOUT_MS: u64 = 250;
const COMMAND_REPORT_TIMEOUT_MS: u64 = 250;

impl AgentRuntime {
    pub(super) fn completed_command_cursor(&self) -> Vec<String> {
        self.completed_command_ids.iter().cloned().collect()
    }

    pub(super) fn track_completed_command(&mut self, command_id: &str) {
        if command_id.is_empty() {
            return;
        }

        self.completed_command_ids.push_back(command_id.to_string());
        while self.completed_command_ids.len() > COMPLETED_COMMAND_CURSOR_CAP {
            self.completed_command_ids.pop_front();
        }
    }

    pub(super) async fn handle_command(&mut self, command: CommandEnvelope, now_unix: i64) {
        let command_id = command.command_id.clone();
        let parsed = parse_server_command(&command.command_type);
        let mut exec = execute_server_command_with_state(parsed, now_unix, &mut self.host_control);

        if parsed == ServerCommand::EmergencyRulePush {
            self.apply_emergency_rule_push(&command.payload_json, &mut exec);
        }

        if parsed == ServerCommand::ConfigChange {
            self.apply_config_change(&command.payload_json, &mut exec);
        }

        match parsed {
            ServerCommand::Isolate => self.apply_host_isolate(&command.payload_json, &mut exec),
            ServerCommand::Unisolate => self.apply_host_unisolate(&mut exec),
            ServerCommand::RestoreQuarantine => {
                self.apply_quarantine_restore(&command.payload_json, &mut exec)
            }
            ServerCommand::Forensics => {
                self.apply_forensics_collection(&command.payload_json, &mut exec)
            }
            ServerCommand::LockDevice => self.apply_device_lock(&command.payload_json, &mut exec),
            ServerCommand::WipeDevice => self.apply_device_wipe(&command.payload_json, &mut exec),
            ServerCommand::RetireDevice => {
                self.apply_device_retire(&command.payload_json, &mut exec)
            }
            ServerCommand::RestartDevice => {
                self.apply_device_restart(&command.payload_json, &mut exec)
            }
            ServerCommand::LostMode => self.apply_lost_mode(&command.payload_json, &mut exec),
            ServerCommand::LocateDevice => {
                self.apply_device_locate(&command.payload_json, &mut exec)
            }
            ServerCommand::InstallApp => self.apply_app_install(&command.payload_json, &mut exec),
            ServerCommand::RemoveApp => self.apply_app_remove(&command.payload_json, &mut exec),
            ServerCommand::UpdateApp => self.apply_app_update(&command.payload_json, &mut exec),
            ServerCommand::ApplyProfile => {
                self.apply_config_profile(&command.payload_json, &mut exec)
            }
            _ => {}
        }

        info!(
            command_id = %command.command_id,
            command_type = %command.command_type,
            payload = %command.payload_json,
            parsed = ?parsed,
            outcome = ?exec.outcome,
            detail = %exec.detail,
            "received command"
        );

        self.ack_command_result(&command_id, exec.status).await;
        self.report_command_result(&command, exec.status, &exec.detail)
            .await;

        self.track_completed_command(&command_id);
    }

    pub(super) fn apply_emergency_rule_from_payload(&self, payload_json: &str) -> Result<String> {
        let payload: EmergencyRulePayload = serde_json::from_str(payload_json)
            .map_err(|err| anyhow!("invalid emergency payload: {}", err))?;

        let rule_type = parse_emergency_rule_type(&payload.rule_type)?;

        let severity = payload.severity.trim().to_ascii_lowercase();
        if !severity.is_empty()
            && !matches!(
                severity.as_str(),
                "info" | "low" | "medium" | "high" | "critical"
            )
        {
            return Err(anyhow!("unsupported emergency severity: {}", severity));
        }

        let rule_content = if payload.rule_content.trim().is_empty() {
            payload.content.trim()
        } else {
            payload.rule_content.trim()
        };
        if rule_content.is_empty() {
            return Err(anyhow!("missing emergency rule content"));
        }

        let rule_name = if payload.rule_name.trim().is_empty() {
            format!(
                "emergency-{}-rule",
                payload.rule_type.trim().to_ascii_lowercase()
            )
        } else {
            payload.rule_name.trim().to_string()
        };

        let rule = EmergencyRule {
            name: rule_name.clone(),
            rule_type,
            rule_content: rule_content.to_string(),
        };

        self.detection_state.apply_emergency_rule(rule)?;
        Ok(rule_name)
    }

    pub(super) fn apply_emergency_rule_push(
        &self,
        payload_json: &str,
        exec: &mut response::CommandExecution,
    ) {
        match self.apply_emergency_rule_from_payload(payload_json) {
            Ok(rule_name) => {
                exec.detail = format!("emergency rule applied: {}", rule_name);
            }
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("emergency rule push rejected: {}", err);
            }
        }
    }

    async fn ack_command_result(&self, command_id: &str, status: &str) {
        let ack = self
            .client
            .ack_command(&self.config.agent_id, command_id, status);
        match timeout(Duration::from_millis(COMMAND_ACK_TIMEOUT_MS), ack).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                warn!(error = %err, command_id = %command_id, "failed to ack command");
            }
            Err(_) => {
                warn!(
                    command_id = %command_id,
                    timeout_ms = COMMAND_ACK_TIMEOUT_MS,
                    "timed out while acking command"
                );
            }
        }
    }

    async fn report_command_result(&self, command: &CommandEnvelope, status: &str, detail: &str) {
        let report = ResponseEnvelope {
            agent_id: self.config.agent_id.clone(),
            action_type: format!("command:{}", command.command_type),
            confidence: "high".to_string(),
            success: status == "completed",
            error_message: if status == "completed" {
                String::new()
            } else {
                detail.to_string()
            },
            detection_layers: Vec::new(),
            target_process: String::new(),
            target_pid: 0,
            rule_name: String::new(),
            threat_category: String::new(),
            file_path: None,
        };

        let send = self.client.send_response(&report);
        match timeout(Duration::from_millis(COMMAND_REPORT_TIMEOUT_MS), send).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                warn!(
                    error = %err,
                    command_id = %command.command_id,
                    "failed to send command response report"
                );
            }
            Err(_) => {
                warn!(
                    command_id = %command.command_id,
                    timeout_ms = COMMAND_REPORT_TIMEOUT_MS,
                    "timed out while reporting command result"
                );
            }
        }
    }
}
