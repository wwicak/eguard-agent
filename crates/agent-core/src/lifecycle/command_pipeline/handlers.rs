use std::path::{Path, PathBuf};

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use nac::apply_network_profile_config_change;
use response::{CommandExecution, CommandOutcome};

use super::app_management::apply_app_command;
#[cfg(target_os = "macos")]
use super::command_utils::run_command;
use super::command_utils::{
    mdm_action_allowed, remove_path, resolve_allowed_server_ips, run_command_sequence, write_marker,
};
use super::paths::{resolve_agent_data_dir, resolve_network_profile_dir};
use super::payloads::{
    format_device_action_context, parse_device_action_payload, parse_locate_payload,
    ForensicsPayload, ProfilePayload, RestoreQuarantinePayload,
};
use super::sanitize::sanitize_profile_id;
#[cfg(target_os = "windows")]
use super::windows_network_profile::{
    apply_wifi_profile_from_mdm, apply_windows_network_profile_config_change,
};
use super::AgentRuntime;

impl AgentRuntime {
    pub(super) fn apply_config_change(&self, payload_json: &str, exec: &mut CommandExecution) {
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

        #[cfg(target_os = "macos")]
        {
            match platform_macos::response::apply_network_profile_config_change(
                payload_json,
                &profile_dir,
            ) {
                Ok(Some(report)) => {
                    exec.detail = format!(
                        "network profile applied: {} ({})",
                        report.profile_id,
                        report.profile_path.display()
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
            return;
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
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

    pub(super) fn apply_host_isolate(&self, payload_json: &str, exec: &mut CommandExecution) {
        #[derive(Debug, serde::Deserialize, Default)]
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

        #[cfg(target_os = "macos")]
        {
            if allowed.is_empty() {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = "isolation rejected: no routable server IPs provided".to_string();
                return;
            }

            let refs: Vec<&str> = allowed.iter().map(|value| value.as_str()).collect();
            match platform_macos::response::isolate_host(&refs) {
                Ok(()) => {
                    exec.detail = format!(
                        "host isolation enforced via pf (allowing: {})",
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

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = (allowed, exec);
        }
    }

    pub(super) fn apply_host_unisolate(&self, exec: &mut CommandExecution) {
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

        #[cfg(target_os = "macos")]
        {
            match platform_macos::response::remove_isolation() {
                Ok(()) => {
                    exec.detail = "host isolation removed via pf".to_string();
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("failed removing host isolation: {}", err);
                }
            }
            return;
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = exec;
        }
    }

    pub(super) fn apply_quarantine_restore(&self, payload_json: &str, exec: &mut CommandExecution) {
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

        #[cfg(target_os = "macos")]
        {
            match platform_macos::response::restore_file(
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

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
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

    pub(super) fn apply_forensics_collection(
        &self,
        payload_json: &str,
        exec: &mut CommandExecution,
    ) {
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

        #[cfg(target_os = "macos")]
        {
            let output_path = if payload.output_path.trim().is_empty() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default();
                resolve_agent_data_dir()
                    .join("forensics")
                    .join(format!("snapshot-{}.txt", now))
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

            let collector = platform_macos::response::ForensicsCollector::new();
            let snapshot = collector.collect_full_snapshot();
            let body = format!(
                "=== processes ===\n{}\n\n=== network ===\n{}\n\n=== launchctl ===\n{}\n",
                snapshot.processes, snapshot.network, snapshot.launchctl
            );

            match std::fs::write(&output_path, body.as_bytes()) {
                Ok(()) => {
                    exec.detail = format!("forensics snapshot captured: {}", output_path);
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("forensics capture failed: {}", err);
                }
            }
            return;
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = (payload, exec);
        }
    }

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

    pub(super) fn apply_app_install(&self, payload_json: &str, exec: &mut CommandExecution) {
        apply_app_command("install", payload_json, exec);
    }

    pub(super) fn apply_app_remove(&self, payload_json: &str, exec: &mut CommandExecution) {
        apply_app_command("remove", payload_json, exec);
    }

    pub(super) fn apply_app_update(&self, payload_json: &str, exec: &mut CommandExecution) {
        apply_app_command("update", payload_json, exec);
    }

    pub(super) fn apply_config_profile(&self, payload_json: &str, exec: &mut CommandExecution) {
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

        #[cfg(target_os = "macos")]
        let looks_like_mobileconfig = {
            let trimmed_profile = payload.profile_json.trim_start();
            trimmed_profile.starts_with("<?xml")
                || trimmed_profile.contains("<plist")
                || trimmed_profile.contains("<dict>")
        };

        #[cfg(target_os = "macos")]
        let profile_path = if looks_like_mobileconfig {
            profile_dir.join(format!("{}.mobileconfig", profile_id))
        } else {
            profile_dir.join(format!("{}.json", profile_id))
        };

        #[cfg(not(target_os = "macos"))]
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

        #[cfg(target_os = "windows")]
        {
            match apply_wifi_profile_from_mdm(&payload.profile_json, &profile_dir) {
                Ok(Some(wifi_path)) => {
                    exec.detail = format!(
                        "WiFi profile applied: {} (json: {})",
                        wifi_path.display(),
                        profile_path.display()
                    );
                    return;
                }
                Ok(None) => {
                    // Not a WiFi profile, fall through to generic storage.
                }
                Err(err) => {
                    // WiFi application failed, but JSON was already stored.
                    exec.detail = format!(
                        "profile stored: {} (WiFi apply failed: {})",
                        profile_path.display(),
                        err
                    );
                    return;
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            if looks_like_mobileconfig {
                let args = vec![
                    "install".to_string(),
                    "-type".to_string(),
                    "configuration".to_string(),
                    "-path".to_string(),
                    profile_path.to_string_lossy().to_string(),
                ];
                if let Err(err) = run_command("profiles", &args) {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("profile install failed: {}", err);
                    return;
                }

                exec.detail = format!("profile installed: {}", profile_path.display());
                return;
            }
        }

        exec.detail = format!("profile stored: {}", profile_path.display());
    }
}
