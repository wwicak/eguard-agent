use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, Result};
use grpc_client::{CommandEnvelope, ResponseEnvelope};
#[cfg(not(target_os = "windows"))]
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

    pub(super) fn apply_config_change(
        &self,
        payload_json: &str,
        exec: &mut response::CommandExecution,
    ) {
        let profile_dir = resolve_network_profile_dir();

        #[cfg(target_os = "windows")]
        {
            match apply_windows_network_profile_config_change(payload_json, &profile_dir) {
                Ok(Some(path)) => {
                    exec.detail = format!("network profile applied ({})", path.display());
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
            return;
        }

        #[cfg(not(target_os = "windows"))]
        {
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
    }

    fn apply_host_isolate(&self, payload_json: &str, exec: &mut CommandExecution) {
        #[derive(Debug, Deserialize, Default)]
        struct IsolatePayload {
            #[serde(default)]
            allow_server_ips: Vec<String>,
        }

        let payload: IsolatePayload = serde_json::from_str(payload_json).unwrap_or_default();
        let allowed =
            resolve_allowed_server_ips(&self.config.server_addr, &payload.allow_server_ips);

        #[cfg(target_os = "windows")]
        {
            if allowed.is_empty() {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = "isolation rejected: no routable server IPs provided".to_string();
                return;
            }

            let refs: Vec<&str> = allowed.iter().map(|value| value.as_str()).collect();
            match platform_windows::response::isolate_host(&refs) {
                Ok(()) => {
                    exec.detail = format!(
                        "host isolation enforced via Windows Firewall (allowing: {})",
                        allowed.join(",")
                    );
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("host isolation failed: {}", err);
                }
            }
            return;
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (allowed, exec);
        }
    }

    fn apply_host_unisolate(&self, exec: &mut CommandExecution) {
        #[cfg(target_os = "windows")]
        {
            match platform_windows::response::remove_isolation() {
                Ok(()) => {
                    exec.detail = "host isolation removed via Windows Firewall".to_string();
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("failed removing host isolation: {}", err);
                }
            }
            return;
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = exec;
        }
    }

    fn apply_quarantine_restore(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload: RestoreQuarantinePayload = match serde_json::from_str(payload_json) {
            Ok(payload) => payload,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid restore_quarantine payload: {}", err);
                return;
            }
        };

        if payload.quarantine_path.trim().is_empty() || payload.original_path.trim().is_empty() {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail =
                "invalid restore_quarantine payload: quarantine_path and original_path are required"
                    .to_string();
            return;
        }

        #[cfg(target_os = "windows")]
        {
            match platform_windows::response::quarantine::restore_file(
                payload.quarantine_path.trim(),
                payload.original_path.trim(),
            ) {
                Ok(()) => {
                    exec.detail = format!(
                        "quarantine restored: {} -> {}",
                        payload.quarantine_path.trim(),
                        payload.original_path.trim()
                    );
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("restore_quarantine failed: {}", err);
                }
            }
            return;
        }

        #[cfg(not(target_os = "windows"))]
        {
            match response::restore_quarantined(
                Path::new(payload.quarantine_path.trim()),
                Path::new(payload.original_path.trim()),
                0o600,
            ) {
                Ok(report) => {
                    exec.detail =
                        format!("quarantine restored: {}", report.restored_path.display());
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("restore_quarantine failed: {}", err);
                }
            }
        }
    }

    fn apply_forensics_collection(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload: ForensicsPayload = serde_json::from_str(payload_json).unwrap_or_default();

        #[cfg(target_os = "windows")]
        {
            if payload.pid == 0 {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = "forensics payload requires pid".to_string();
                return;
            }

            let output_path = if payload.output_path.trim().is_empty() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default();
                resolve_agent_data_dir()
                    .join("forensics")
                    .join(format!("pid-{}-{}.dmp", payload.pid, now))
                    .to_string_lossy()
                    .to_string()
            } else {
                payload.output_path.trim().to_string()
            };

            if let Some(parent) = Path::new(&output_path).parent() {
                if let Err(err) = std::fs::create_dir_all(parent) {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("forensics output directory failed: {}", err);
                    return;
                }
            }

            let collector = platform_windows::response::ForensicsCollector::new();
            match collector.create_minidump(payload.pid, &output_path) {
                Ok(()) => {
                    exec.detail = format!("forensics minidump captured: {}", output_path);
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("forensics capture failed: {}", err);
                }
            }
            return;
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (payload, exec);
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

        let lock_result = {
            #[cfg(target_os = "windows")]
            {
                run_command_sequence(&[("rundll32.exe", &["user32.dll,LockWorkStation"])])
            }

            #[cfg(target_os = "macos")]
            {
                run_command_sequence(&[("pmset", &["displaysleepnow"])])
            }

            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
            {
                run_command_sequence(&[
                    ("loginctl", &["lock-session"]),
                    ("xdg-screensaver", &["lock"]),
                ])
            }
        };

        if let Err(err) = lock_result {
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
        let data_dir = resolve_agent_data_dir();
        let wipe_targets = [
            PathBuf::from(&self.config.offline_buffer_path),
            data_dir.join("quarantine"),
            data_dir.join("baselines.bin"),
        ];

        for path in wipe_targets {
            let display = path.to_string_lossy().to_string();
            if let Err(err) = remove_path(&display) {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("wipe failed ({}): {}", context, err);
                return;
            }
            removed.push(display);
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
        let retire_marker = resolve_agent_data_dir().join("retired");
        if let Err(err) = write_marker(retire_marker.to_string_lossy().as_ref()) {
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

        let restart_result = {
            #[cfg(target_os = "windows")]
            {
                run_command_sequence(&[("shutdown", &["/r", "/t", "0", "/f"])])
            }

            #[cfg(target_os = "macos")]
            {
                run_command_sequence(&[("shutdown", &["-r", "now"])])
            }

            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
            {
                run_command_sequence(&[("systemctl", &["reboot"]), ("shutdown", &["-r", "now"])])
            }
        };

        if let Err(err) = restart_result {
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
        let marker_path = resolve_agent_data_dir().join("lost_mode");

        if let Err(err) = write_marker(marker_path.to_string_lossy().as_ref()) {
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
        let profile_id = match sanitize_profile_id(&payload.profile_id) {
            Ok(profile_id) => profile_id,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid profile_id: {}", err);
                return;
            }
        };

        let profile_dir = resolve_agent_data_dir().join("profiles");
        let profile_path = profile_dir.join(format!("{}.json", profile_id));

        if let Err(err) = std::fs::create_dir_all(&profile_dir) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("profile dir create failed: {}", err);
            return;
        }
        if let Err(err) = std::fs::write(&profile_path, payload.profile_json.as_bytes()) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("profile write failed: {}", err);
            return;
        }
        exec.detail = format!("profile stored: {}", profile_path.display());
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

fn resolve_network_profile_dir() -> PathBuf {
    let raw = std::env::var("EGUARD_NETWORK_PROFILE_DIR").unwrap_or_default();
    if !raw.trim().is_empty() {
        return PathBuf::from(raw.trim());
    }

    #[cfg(target_os = "windows")]
    {
        return PathBuf::from(r"C:\ProgramData\eGuard\network-profiles");
    }

    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Library/Application Support/eGuard/network-profiles");
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        PathBuf::from("/etc/NetworkManager/system-connections")
    }
}

fn resolve_agent_data_dir() -> PathBuf {
    if let Ok(raw) = std::env::var("EGUARD_AGENT_DATA_DIR") {
        if !raw.trim().is_empty() {
            return PathBuf::from(raw.trim());
        }
    }

    #[cfg(target_os = "windows")]
    {
        return PathBuf::from(r"C:\ProgramData\eGuard");
    }

    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Library/Application Support/eGuard");
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        PathBuf::from("/var/lib/eguard-agent")
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
struct RestoreQuarantinePayload {
    #[serde(default)]
    quarantine_path: String,
    #[serde(default)]
    original_path: String,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Deserialize, Default)]
struct ForensicsPayload {
    #[serde(default)]
    pid: u32,
    #[serde(default)]
    output_path: String,
}

#[derive(Debug, Deserialize, Default)]
struct ProfilePayload {
    #[serde(default)]
    profile_id: String,
    #[serde(default)]
    profile_json: String,
}

fn sanitize_profile_id(raw: &str) -> Result<String, &'static str> {
    let profile_id = raw.trim();
    if profile_id.is_empty() {
        return Err("profile_id required");
    }
    if profile_id.len() > 128 {
        return Err("profile_id too long");
    }
    if profile_id.contains("..") {
        return Err("path traversal segments are not allowed");
    }
    if profile_id.contains('/') || profile_id.contains('\\') {
        return Err("path separators are not allowed");
    }
    if !profile_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("profile_id contains unsupported characters");
    }

    Ok(profile_id.to_string())
}

#[cfg(any(test, not(target_os = "windows")))]
fn sanitize_apt_package_name(raw: &str) -> Result<String, &'static str> {
    let package_name = raw.trim();
    if package_name.is_empty() {
        return Err("package_name required");
    }
    if package_name.len() > 128 {
        return Err("package_name too long");
    }
    if package_name.starts_with('-') {
        return Err("package_name must not start with '-'");
    }
    if !package_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
    {
        return Err("package_name contains unsupported characters");
    }
    Ok(package_name.to_string())
}

#[cfg(any(test, not(target_os = "windows")))]
fn sanitize_apt_package_version(raw: &str) -> Result<String, &'static str> {
    let version = raw.trim();
    if version.is_empty() {
        return Ok(String::new());
    }
    if version.len() > 128 {
        return Err("version too long");
    }
    if version.starts_with('-') {
        return Err("version must not start with '-'");
    }
    if !version.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b':' | b'~' | b'_')
    }) {
        return Err("version contains unsupported characters");
    }
    Ok(version.to_string())
}

#[cfg(any(test, target_os = "windows"))]
fn sanitize_windows_package_name(raw: &str) -> Result<String, &'static str> {
    let package_name = raw.trim();
    if package_name.is_empty() {
        return Err("package_name required");
    }
    if package_name.len() > 128 {
        return Err("package_name too long");
    }
    if package_name.starts_with('-') {
        return Err("package_name must not start with '-'");
    }
    if !package_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("package_name contains unsupported characters");
    }

    Ok(package_name.to_string())
}

#[cfg(any(test, target_os = "windows"))]
fn sanitize_windows_package_version(raw: &str) -> Result<String, &'static str> {
    let version = raw.trim();
    if version.is_empty() {
        return Ok(String::new());
    }
    if version.len() > 128 {
        return Err("version too long");
    }
    if version.starts_with('-') {
        return Err("version must not start with '-'");
    }
    if !version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("version contains unsupported characters");
    }

    Ok(version.to_string())
}

fn resolve_allowed_server_ips(server_addr: &str, payload_ips: &[String]) -> Vec<String> {
    let mut ips = Vec::new();

    for raw in payload_ips {
        let ip = raw.trim();
        if ip.is_empty() {
            continue;
        }
        if parse_ip_literal(ip).is_some() && !ips.iter().any(|entry| entry == ip) {
            ips.push(ip.to_string());
        }
    }

    let host = extract_server_host(server_addr);
    if let Some(ip) = parse_ip_literal(&host) {
        let value = ip.to_string();
        if !ips.iter().any(|entry| entry == &value) {
            ips.push(value);
        }
    }

    ips
}

fn extract_server_host(server_addr: &str) -> String {
    let raw = server_addr.trim();
    if raw.is_empty() {
        return String::new();
    }

    if let Some(stripped) = raw.strip_prefix('[') {
        if let Some((host, _rest)) = stripped.split_once(']') {
            return host.to_string();
        }
    }

    if let Some((host, port)) = raw.rsplit_once(':') {
        if !host.contains(':') && port.parse::<u16>().is_ok() {
            return host.to_string();
        }
    }

    raw.to_string()
}

fn parse_ip_literal(raw: &str) -> Option<IpAddr> {
    raw.trim().parse::<IpAddr>().ok()
}

#[cfg(target_os = "windows")]
#[derive(Debug, Deserialize, Default)]
struct WindowsNetworkProfile {
    #[serde(default)]
    profile_id: String,
    #[serde(default)]
    ssid: String,
    #[serde(default)]
    security: String,
    #[serde(default = "default_true")]
    auto_connect: bool,
    #[serde(default)]
    psk: String,
}

#[cfg(target_os = "windows")]
fn apply_windows_network_profile_config_change(
    payload_json: &str,
    profile_dir: &Path,
) -> Result<Option<PathBuf>, String> {
    let payload: serde_json::Value = serde_json::from_str(payload_json)
        .map_err(|err| format!("invalid config_change payload JSON: {err}"))?;

    let config_raw = payload
        .get("config_json")
        .ok_or_else(|| "config_json is required in config_change payload".to_string())?;

    let config_json = match config_raw {
        serde_json::Value::String(raw) => serde_json::from_str::<serde_json::Value>(raw)
            .map_err(|err| format!("config_json must be valid JSON: {err}"))?,
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => config_raw.clone(),
        _ => {
            return Err("config_json must be JSON object/array/string".to_string());
        }
    };

    let config_obj = config_json
        .as_object()
        .ok_or_else(|| "config_json must be a JSON object".to_string())?;

    let config_type = config_obj
        .get("config_type")
        .or_else(|| config_obj.get("type"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    if config_type != "network_profile" {
        return Ok(None);
    }

    let profile_value = config_obj
        .get("profile")
        .cloned()
        .unwrap_or_else(|| config_json.clone());
    let mut profile: WindowsNetworkProfile = serde_json::from_value(profile_value)
        .map_err(|err| format!("invalid network_profile payload: {err}"))?;

    profile.ssid = profile.ssid.trim().to_string();
    if profile.ssid.is_empty() {
        return Err("network profile ssid is required".to_string());
    }

    profile.profile_id = if profile.profile_id.trim().is_empty() {
        sanitize_profile_id(&profile.ssid).map_err(ToString::to_string)?
    } else {
        sanitize_profile_id(&profile.profile_id).map_err(ToString::to_string)?
    };

    let security = profile.security.trim().to_ascii_lowercase();
    let auto_connect = profile.auto_connect;

    let xml = match security.as_str() {
        "open" => render_windows_wlan_open_profile_xml(&profile.ssid, auto_connect),
        "wpa2_psk" => {
            let psk = profile.psk.trim();
            if psk.len() < 8 || psk.len() > 63 {
                return Err("network profile psk must be 8-63 characters".to_string());
            }
            render_windows_wlan_wpa2_psk_profile_xml(&profile.ssid, psk, auto_connect)
        }
        other => {
            return Err(format!(
                "unsupported Windows network profile security mode: {}",
                other
            ));
        }
    };

    std::fs::create_dir_all(profile_dir).map_err(|err| {
        format!(
            "failed creating profile directory {}: {err}",
            profile_dir.display()
        )
    })?;

    let profile_path = profile_dir.join(format!("{}.xml", profile.profile_id));
    std::fs::write(&profile_path, xml).map_err(|err| {
        format!(
            "failed writing profile XML {}: {err}",
            profile_path.display()
        )
    })?;

    let filename_arg = format!("filename={}", profile_path.display());
    run_command(
        "netsh",
        &[
            "wlan".to_string(),
            "add".to_string(),
            "profile".to_string(),
            filename_arg,
            "user=all".to_string(),
        ],
    )
    .map_err(|err| format!("failed adding WLAN profile via netsh: {err}"))?;

    if auto_connect {
        let name_arg = format!("name={}", profile.ssid);
        let _ = run_command(
            "netsh",
            &[
                "wlan".to_string(),
                "set".to_string(),
                "profileparameter".to_string(),
                name_arg,
                "connectionmode=auto".to_string(),
            ],
        );
    }

    Ok(Some(profile_path))
}

#[cfg(target_os = "windows")]
fn render_windows_wlan_open_profile_xml(ssid: &str, auto_connect: bool) -> String {
    let ssid = escape_xml(ssid);
    let mode = if auto_connect { "auto" } else { "manual" };
    format!(
        r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>{mode}</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
"#
    )
}

#[cfg(target_os = "windows")]
fn render_windows_wlan_wpa2_psk_profile_xml(ssid: &str, psk: &str, auto_connect: bool) -> String {
    let ssid = escape_xml(ssid);
    let psk = escape_xml(psk);
    let mode = if auto_connect { "auto" } else { "manual" };
    format!(
        r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>{mode}</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{psk}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"#
    )
}

#[cfg(target_os = "windows")]
fn escape_xml(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "windows")]
const fn default_true() -> bool {
    true
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
    let mut last_error = String::new();

    for (cmd, args) in commands {
        let owned = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        match run_command(cmd, &owned) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_error = format!("{}: {}", cmd, err);
            }
        }
    }

    if last_error.is_empty() {
        Err("all command attempts failed".to_string())
    } else {
        Err(last_error)
    }
}

fn run_command(cmd: &str, args: &[String]) -> Result<(), String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|err| format!("spawn failed: {err}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };

    if detail.is_empty() {
        Err(format!("command exited with status {}", output.status))
    } else {
        Err(detail)
    }
}

fn remove_path(path: &str) -> Result<(), String> {
    let path = Path::new(path);
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
    let marker_path = Path::new(path);
    let content = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string());

    if let Some(parent) = marker_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create marker dir {}: {}", parent.display(), err))?;
    }

    std::fs::write(marker_path, content.as_bytes())
        .map_err(|err| format!("write marker {}: {}", marker_path.display(), err))
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

    #[cfg(target_os = "windows")]
    {
        let package_name = match sanitize_windows_package_name(&payload.package_name) {
            Ok(value) => value,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid package_name: {}", err);
                return;
            }
        };

        let version = match sanitize_windows_package_version(&payload.version) {
            Ok(value) => value,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid version: {}", err);
                return;
            }
        };

        let mut args = match action {
            "install" => vec![
                "install".to_string(),
                "--id".to_string(),
                package_name.clone(),
                "--exact".to_string(),
                "--accept-package-agreements".to_string(),
                "--accept-source-agreements".to_string(),
            ],
            "remove" => vec![
                "uninstall".to_string(),
                "--id".to_string(),
                package_name.clone(),
                "--exact".to_string(),
            ],
            "update" => vec![
                "upgrade".to_string(),
                "--id".to_string(),
                package_name.clone(),
                "--exact".to_string(),
            ],
            _ => vec![
                "install".to_string(),
                "--id".to_string(),
                package_name.clone(),
                "--exact".to_string(),
                "--accept-package-agreements".to_string(),
                "--accept-source-agreements".to_string(),
            ],
        };

        if action == "install" && !version.is_empty() {
            args.push("--version".to_string());
            args.push(version);
        }

        if let Err(err) = run_command("winget", &args) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("app {} failed: {}", action, err);
        } else {
            exec.detail = format!("app {} executed for {}", action, package_name);
        }

        return;
    }

    #[cfg(not(target_os = "windows"))]
    {
        let package_name = match sanitize_apt_package_name(&payload.package_name) {
            Ok(value) => value,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid package_name: {}", err);
                return;
            }
        };

        let version = match sanitize_apt_package_version(&payload.version) {
            Ok(value) => value,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid version: {}", err);
                return;
            }
        };

        let package = if version.is_empty() {
            package_name.clone()
        } else {
            format!("{}={}", package_name, version)
        };

        let args = match action {
            "install" => vec!["install", "-y", package.as_str()],
            "remove" => vec!["remove", "-y", package_name.as_str()],
            "update" => vec!["install", "-y", package.as_str()],
            _ => vec!["install", "-y", package.as_str()],
        };

        let cmd_args = args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        if let Err(err) = run_command("apt-get", &cmd_args) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("app {} failed: {}", action, err);
        } else {
            exec.detail = format!("app {} executed for {}", action, package_name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_server_host, format_device_action_context, parse_device_action_payload,
        parse_locate_payload, resolve_allowed_server_ips, sanitize_apt_package_name,
        sanitize_apt_package_version, sanitize_profile_id, DeviceActionPayload,
    };

    #[cfg(any(test, target_os = "windows"))]
    use super::{sanitize_windows_package_name, sanitize_windows_package_version};

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

    #[test]
    fn sanitize_profile_id_rejects_path_traversal_sequences() {
        assert!(sanitize_profile_id("../../etc/cron.d/backdoor").is_err());
        assert!(sanitize_profile_id("corp/../default").is_err());
        assert!(sanitize_profile_id("corp\\..\\default").is_err());
    }

    #[test]
    fn sanitize_profile_id_accepts_safe_identifier() {
        let profile_id = sanitize_profile_id("corp-prod_01.v2").expect("safe profile id");
        assert_eq!(profile_id, "corp-prod_01.v2");
    }

    #[test]
    fn sanitize_apt_package_name_rejects_option_injection_tokens() {
        assert!(sanitize_apt_package_name("pkg -o APT::Update").is_err());
        assert!(sanitize_apt_package_name("pkg;touch /tmp/x").is_err());
    }

    #[test]
    fn sanitize_apt_package_version_rejects_option_injection_tokens() {
        assert!(sanitize_apt_package_version("1.0 -o Acquire::http::Proxy").is_err());
        assert!(sanitize_apt_package_version("1.0;rm -rf /").is_err());
    }

    #[test]
    fn sanitize_apt_package_fields_accept_valid_values() {
        assert_eq!(
            sanitize_apt_package_name("libssl3").expect("valid package"),
            "libssl3"
        );
        assert_eq!(
            sanitize_apt_package_version("1:3.0.2-0ubuntu1~22.04.1").expect("valid version"),
            "1:3.0.2-0ubuntu1~22.04.1"
        );
    }

    #[test]
    fn extract_server_host_parses_host_port_and_ipv6_forms() {
        assert_eq!(extract_server_host("127.0.0.1:50052"), "127.0.0.1");
        assert_eq!(extract_server_host("[2001:db8::1]:50052"), "2001:db8::1");
        assert_eq!(extract_server_host("eguard-server"), "eguard-server");
    }

    #[test]
    fn resolve_allowed_server_ips_merges_payload_and_server_literal_ip() {
        let allowed = resolve_allowed_server_ips(
            "[2001:db8::10]:50052",
            &["203.0.113.4".to_string(), "not-an-ip".to_string()],
        );

        assert_eq!(
            allowed,
            vec!["203.0.113.4".to_string(), "2001:db8::10".to_string()]
        );
    }

    #[test]
    fn sanitize_windows_package_fields_reject_injection_and_accept_safe_values() {
        assert!(sanitize_windows_package_name("winget;calc").is_err());
        assert!(sanitize_windows_package_version("1.0 && whoami").is_err());

        assert_eq!(
            sanitize_windows_package_name("Microsoft.Edge").expect("valid package id"),
            "Microsoft.Edge"
        );
        assert_eq!(
            sanitize_windows_package_version("124.0.2478.67").expect("valid package version"),
            "124.0.2478.67"
        );
    }
}
