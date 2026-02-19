use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Result};
use grpc_client::{CommandEnvelope, ResponseEnvelope};
use nac::apply_network_profile_config_change;
use response::{
    execute_server_command_with_state, parse_server_command, CommandExecution, CommandOutcome,
    ServerCommand,
};
use serde::Deserialize;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::detection_state::EmergencyRule;

use super::{parse_emergency_rule_type, AgentRuntime, EmergencyRulePayload};

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

    pub(super) fn apply_config_change(
        &self,
        payload_json: &str,
        exec: &mut response::CommandExecution,
    ) {
        let profile_dir = resolve_network_profile_dir();
        match apply_network_profile_config_change(payload_json, &profile_dir) {
            Ok(Some(report)) => {
                exec.detail = format!(
                    "network profile applied: {} ({})",
                    report.profile_id,
                    report.connection_path.display()
                );
            }
            Ok(None) => {
                // Non-network config payloads remain backward-compatible no-ops.
            }
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("config_change rejected: {}", err);
            }
        }
    }

    fn apply_device_lock(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload = parse_device_action_payload(payload_json);
        let context = format_device_action_context(&payload);

        if !mdm_action_allowed("lock") {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("device lock blocked by policy ({})", context);
            return;
        }
        if let Err(err) = run_command_sequence(&[
            ("loginctl", &["lock-session"]),
            ("xdg-screensaver", &["lock"]),
        ]) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("device lock failed ({}): {}", context, err);
        } else {
            exec.detail = format!("device lock command issued ({})", context);
        }
    }

    fn apply_device_wipe(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload = parse_device_action_payload(payload_json);
        let context = format_device_action_context(&payload);

        if !mdm_action_allowed("wipe") {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("device wipe blocked by policy ({})", context);
            return;
        }
        let mut removed = Vec::new();
        for path in [
            &self.config.offline_buffer_path,
            "/var/lib/eguard-agent/quarantine",
            "/var/lib/eguard-agent/baselines.bin",
        ] {
            if let Err(err) = remove_path(path) {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("wipe failed ({}): {}", context, err);
                return;
            }
            removed.push(path.to_string());
        }
        exec.detail = format!("wipe completed for {} ({})", removed.join(", "), context);
    }

    fn apply_device_retire(&mut self, payload_json: &str, exec: &mut CommandExecution) {
        let payload = parse_device_action_payload(payload_json);
        let context = format_device_action_context(&payload);

        if !mdm_action_allowed("retire") {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("device retire blocked by policy ({})", context);
            return;
        }
        if let Err(err) = write_marker("/var/lib/eguard-agent/retired") {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("retire marker failed ({}): {}", context, err);
            return;
        }
        self.enrolled = false;
        exec.detail = format!("device retired ({})", context);
    }

    fn apply_device_restart(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload = parse_device_action_payload(payload_json);
        let context = format_device_action_context(&payload);

        if !mdm_action_allowed("restart") {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("device restart blocked by policy ({})", context);
            return;
        }
        if let Err(err) = run_command_sequence(&[("systemctl", &["reboot"])]) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("restart failed ({}): {}", context, err);
        } else {
            exec.detail = format!("restart requested ({})", context);
        }
    }

    fn apply_lost_mode(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload = parse_device_action_payload(payload_json);
        let context = format_device_action_context(&payload);

        if let Err(err) = write_marker("/var/lib/eguard-agent/lost_mode") {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("lost mode marker failed ({}): {}", context, err);
        } else {
            exec.detail = format!("lost mode enabled ({})", context);
        }
    }

    fn apply_device_locate(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload = parse_locate_payload(payload_json);
        let ip = super::inventory::resolve_primary_ip().unwrap_or_default();
        exec.detail = if ip.is_empty() {
            format!(
                "device locate requested (no ip, high_accuracy={})",
                payload.high_accuracy
            )
        } else {
            format!(
                "device ip: {} (high_accuracy={})",
                ip, payload.high_accuracy
            )
        };
    }

    fn apply_app_install(&self, payload_json: &str, exec: &mut CommandExecution) {
        apply_app_command("install", payload_json, exec);
    }

    fn apply_app_remove(&self, payload_json: &str, exec: &mut CommandExecution) {
        apply_app_command("remove", payload_json, exec);
    }

    fn apply_app_update(&self, payload_json: &str, exec: &mut CommandExecution) {
        apply_app_command("update", payload_json, exec);
    }

    fn apply_config_profile(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload: ProfilePayload = match serde_json::from_str(payload_json) {
            Ok(payload) => payload,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid profile payload: {}", err);
                return;
            }
        };
        if payload.profile_id.trim().is_empty() {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = "profile_id required".to_string();
            return;
        }
        let path = format!("/var/lib/eguard-agent/profiles/{}.json", payload.profile_id);
        if let Err(err) = std::fs::create_dir_all("/var/lib/eguard-agent/profiles") {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("profile dir create failed: {}", err);
            return;
        }
        if let Err(err) = std::fs::write(&path, payload.profile_json.as_bytes()) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("profile write failed: {}", err);
            return;
        }
        exec.detail = format!("profile stored: {}", path);
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

fn resolve_network_profile_dir() -> PathBuf {
    let raw = std::env::var("EGUARD_NETWORK_PROFILE_DIR").unwrap_or_default();
    if raw.trim().is_empty() {
        PathBuf::from("/etc/NetworkManager/system-connections")
    } else {
        PathBuf::from(raw.trim())
    }
}

#[derive(Debug, Deserialize, Default)]
struct DeviceActionPayload {
    #[serde(default)]
    force: bool,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Deserialize, Default)]
struct LocatePayload {
    #[serde(default)]
    high_accuracy: bool,
}

#[derive(Debug, Deserialize, Default)]
struct AppPayload {
    #[serde(default)]
    package_name: String,
    #[serde(default)]
    version: String,
}

#[derive(Debug, Deserialize, Default)]
struct ProfilePayload {
    #[serde(default)]
    profile_id: String,
    #[serde(default)]
    profile_json: String,
}

fn parse_device_action_payload(payload_json: &str) -> DeviceActionPayload {
    serde_json::from_str(payload_json).unwrap_or_default()
}

fn parse_locate_payload(payload_json: &str) -> LocatePayload {
    serde_json::from_str(payload_json).unwrap_or_default()
}

fn format_device_action_context(payload: &DeviceActionPayload) -> String {
    let reason = payload.reason.trim();
    if reason.is_empty() {
        format!("force={}", payload.force)
    } else {
        format!("force={}, reason={}", payload.force, reason)
    }
}

fn mdm_action_allowed(action: &str) -> bool {
    let normalized = action.trim().to_ascii_lowercase();
    if normalized == "lock" || normalized == "locate" || normalized == "lost_mode" {
        return true;
    }

    if std::env::var("EGUARD_MDM_ALLOW_ALL")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return true;
    }

    let allow_env = format!("EGUARD_MDM_ALLOW_{}", normalized.to_ascii_uppercase());
    if std::env::var(allow_env)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return true;
    }

    if matches!(normalized.as_str(), "wipe" | "retire" | "restart") {
        return std::env::var("EGUARD_MDM_ALLOW_DESTRUCTIVE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    }

    if normalized.starts_with("app_") || normalized == "app" {
        return std::env::var("EGUARD_MDM_ALLOW_APP_MANAGEMENT")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    }

    false
}

fn run_command_sequence(commands: &[(&str, &[&str])]) -> Result<(), String> {
    for (cmd, args) in commands {
        match std::process::Command::new(cmd).args(*args).status() {
            Ok(status) if status.success() => return Ok(()),
            Ok(_) => continue,
            Err(err) => {
                return Err(format!("{}: {}", cmd, err));
            }
        }
    }
    Err("all command attempts failed".to_string())
}

fn remove_path(path: &str) -> Result<(), String> {
    let path = std::path::Path::new(path);
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        std::fs::remove_dir_all(path)
            .map_err(|err| format!("remove dir {}: {}", path.display(), err))
    } else {
        std::fs::remove_file(path).map_err(|err| format!("remove file {}: {}", path.display(), err))
    }
}

fn write_marker(path: &str) -> Result<(), String> {
    let content = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string());
    std::fs::create_dir_all("/var/lib/eguard-agent")
        .map_err(|err| format!("create marker dir: {}", err))?;
    std::fs::write(path, content.as_bytes())
        .map_err(|err| format!("write marker {}: {}", path, err))
}

fn apply_app_command(action: &str, payload_json: &str, exec: &mut CommandExecution) {
    if !mdm_action_allowed("app") {
        exec.outcome = CommandOutcome::Ignored;
        exec.status = "failed";
        exec.detail = "app management blocked by policy".to_string();
        return;
    }

    let payload: AppPayload = match serde_json::from_str(payload_json) {
        Ok(payload) => payload,
        Err(err) => {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("invalid app payload: {}", err);
            return;
        }
    };

    if payload.package_name.trim().is_empty() {
        exec.outcome = CommandOutcome::Ignored;
        exec.status = "failed";
        exec.detail = "package_name required".to_string();
        return;
    }

    let package = if payload.version.trim().is_empty() {
        payload.package_name.clone()
    } else {
        format!("{}={}", payload.package_name, payload.version)
    };

    let args = match action {
        "install" => vec!["install", "-y", package.as_str()],
        "remove" => vec!["remove", "-y", payload.package_name.as_str()],
        "update" => vec!["install", "-y", package.as_str()],
        _ => vec!["install", "-y", package.as_str()],
    };

    let cmd_args = args.iter().map(|s| *s).collect::<Vec<_>>();
    if let Err(err) = run_command_sequence(&[("apt-get", &cmd_args)]) {
        exec.outcome = CommandOutcome::Ignored;
        exec.status = "failed";
        exec.detail = format!("app {} failed: {}", action, err);
    } else {
        exec.detail = format!("app {} executed for {}", action, payload.package_name);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        format_device_action_context, parse_device_action_payload, parse_locate_payload,
        DeviceActionPayload,
    };

    #[test]
    fn device_action_payload_parser_extracts_force_and_reason() {
        let payload = parse_device_action_payload(r#"{"force":true,"reason":"incident-42"}"#);
        assert!(payload.force);
        assert_eq!(payload.reason, "incident-42");
    }

    #[test]
    fn device_action_payload_parser_defaults_on_invalid_json() {
        let payload = parse_device_action_payload("{not-json");
        assert!(!payload.force);
        assert!(payload.reason.is_empty());
    }

    #[test]
    fn format_device_action_context_omits_empty_reason() {
        let payload = DeviceActionPayload {
            force: false,
            reason: "  ".to_string(),
        };
        assert_eq!(format_device_action_context(&payload), "force=false");
    }

    #[test]
    fn locate_payload_parser_reads_high_accuracy_flag() {
        let payload = parse_locate_payload(r#"{"high_accuracy":true}"#);
        assert!(payload.high_accuracy);
    }
}
