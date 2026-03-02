use std::path::PathBuf;

use response::{CommandExecution, CommandOutcome};

use super::command_utils::{mdm_action_allowed, remove_path, run_command_sequence, write_marker};
use super::paths::resolve_agent_data_dir;
use super::payloads::{
    format_device_action_context, parse_device_action_payload, parse_locate_payload,
};
use super::AgentRuntime;

impl AgentRuntime {
    pub(super) fn apply_device_lock(&self, payload_json: &str, exec: &mut CommandExecution) {
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

    pub(super) fn apply_device_wipe(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload = parse_device_action_payload(payload_json);
        let context = format_device_action_context(&payload);

        if !mdm_action_allowed("wipe") {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("device wipe blocked by policy ({})", context);
            return;
        }
        let mut removed = Vec::new();
        let mut errors = Vec::new();
        let data_dir = resolve_agent_data_dir();
        let wipe_targets = [
            PathBuf::from(&self.config.offline_buffer_path),
            data_dir.join("quarantine"),
            data_dir.join("baselines.bin"),
            data_dir.join("baselines.journal"),
            data_dir.join("baselines.journal.meta"),
        ];

        for path in &wipe_targets {
            let display = path.to_string_lossy().to_string();
            match remove_path(&display) {
                Ok(()) => removed.push(display),
                Err(err) => errors.push(format!("{}: {}", display, err)),
            }
        }
        if errors.is_empty() {
            exec.detail = format!("wipe completed for {} ({})", removed.join(", "), context);
        } else if removed.is_empty() {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("wipe failed ({}): {}", context, errors.join("; "));
        } else {
            exec.detail = format!(
                "wipe partially completed ({}) removed=[{}] errors=[{}]",
                context,
                removed.join(", "),
                errors.join("; ")
            );
        }
    }

    pub(super) fn apply_device_retire(&mut self, payload_json: &str, exec: &mut CommandExecution) {
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

    pub(super) fn apply_device_restart(&self, payload_json: &str, exec: &mut CommandExecution) {
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

    pub(super) fn apply_lost_mode(&self, payload_json: &str, exec: &mut CommandExecution) {
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

    pub(super) fn apply_device_locate(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload = parse_locate_payload(payload_json);
        let ip = super::super::inventory::resolve_primary_ip().unwrap_or_default();
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
}
