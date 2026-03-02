use response::{CommandExecution, CommandOutcome};

#[cfg(target_os = "macos")]
use super::command_utils::run_command;
use super::paths::resolve_agent_data_dir;
use super::payloads::ProfilePayload;
use super::sanitize::sanitize_profile_id;
#[cfg(target_os = "windows")]
use super::windows_network_profile::apply_wifi_profile_from_mdm;
use super::AgentRuntime;

impl AgentRuntime {
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
