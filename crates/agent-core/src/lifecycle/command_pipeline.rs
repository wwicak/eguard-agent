use anyhow::{anyhow, Result};
use grpc_client::{CommandEnvelope, ResponseEnvelope};
use response::{
    execute_server_command_with_state, parse_server_command, CommandOutcome, ServerCommand,
};
use tracing::{info, warn};

use crate::detection_state::EmergencyRule;

use super::{parse_emergency_rule_type, AgentRuntime, EmergencyRulePayload};

const COMPLETED_COMMAND_CURSOR_CAP: usize = 256;

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

    fn apply_emergency_rule_push(&self, payload_json: &str, exec: &mut response::CommandExecution) {
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
        if let Err(err) = self.client.ack_command(command_id, status).await {
            warn!(error = %err, command_id = %command_id, "failed to ack command");
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
        };

        if let Err(err) = self.client.send_response(&report).await {
            warn!(
                error = %err,
                command_id = %command.command_id,
                "failed to send command response report"
            );
        }
    }
}
