#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use nac::apply_network_profile_config_change;
use response::{CommandExecution, CommandOutcome};
use serde_json::Value;

use super::paths::resolve_network_profile_dir;
#[cfg(target_os = "windows")]
use super::windows_network_profile::apply_windows_network_profile_config_change;
use super::AgentRuntime;

impl AgentRuntime {
    pub(in crate::lifecycle) fn apply_config_change(
        &self,
        payload_json: &str,
        exec: &mut CommandExecution,
    ) {
        match extract_agent_control_restart_reason(payload_json) {
            Ok(Some(reason)) => match schedule_agent_service_restart(Some(reason.as_str())) {
                Ok(detail) => {
                    exec.detail = detail;
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("config_change rejected: {}", err);
                }
            },
            Ok(None) => {}
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("config_change rejected: {}", err);
                return;
            }
        }

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
}

fn extract_agent_control_restart_reason(payload_json: &str) -> Result<Option<String>, String> {
    let config_json = decode_config_change_config_json(payload_json)?;
    let Some(config) = config_json.as_object() else {
        return Ok(None);
    };

    let config_type = config
        .get("config_type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !config_type.is_empty() && config_type != "agent_control" {
        return Ok(None);
    }

    let nested_control = config.get("agent_control").and_then(Value::as_object);
    let restart_service = nested_control
        .and_then(|control| control.get("restart_service"))
        .and_then(config_value_as_bool)
        .or_else(|| config.get("restart_service").and_then(config_value_as_bool))
        .unwrap_or(false);
    if !restart_service {
        return Ok(None);
    }

    let reason = nested_control
        .and_then(|control| control.get("reason"))
        .and_then(Value::as_str)
        .or_else(|| config.get("reason").and_then(Value::as_str))
        .unwrap_or_default()
        .trim()
        .to_string();

    Ok(Some(reason))
}

fn decode_config_change_config_json(payload_json: &str) -> Result<Value, String> {
    let payload: Value = serde_json::from_str(payload_json)
        .map_err(|err| format!("invalid config_change payload JSON: {err}"))?;
    let config_json = payload
        .get("config_json")
        .ok_or_else(|| "config_json is required in config_change payload".to_string())?;

    match config_json {
        Value::String(raw) => serde_json::from_str(raw)
            .map_err(|err| format!("invalid config_json JSON string: {err}")),
        Value::Object(_) | Value::Array(_) => Ok(config_json.clone()),
        _ => Err("config_json must be a JSON object, array, or JSON string".to_string()),
    }
}

fn config_value_as_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(boolean) => Some(*boolean),
        Value::String(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn format_restart_schedule_detail(platform_label: &str, reason: Option<&str>) -> String {
    let reason = reason.unwrap_or_default().trim();
    if reason.is_empty() {
        format!("agent service restart scheduled ({platform_label})")
    } else {
        format!("agent service restart scheduled ({platform_label}; reason={reason})")
    }
}

#[cfg(target_os = "windows")]
fn schedule_agent_service_restart(reason: Option<&str>) -> Result<String, String> {
    use std::process::{Command, Stdio};

    let script = "Start-Sleep -Seconds 2; Restart-Service -Name eGuardAgent -Force";
    Command::new("cmd")
        .args([
            "/C",
            "start",
            "",
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-Command",
            script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("spawn windows agent service restart: {err}"))?;

    Ok(format_restart_schedule_detail("windows-service", reason))
}

#[cfg(target_os = "macos")]
fn schedule_agent_service_restart(reason: Option<&str>) -> Result<String, String> {
    use std::process::{Command, Stdio};

    let restart_script = "sleep 2; launchctl kickstart -k system/com.eguard.agent >/tmp/eguard-agent-self-restart.log 2>&1";
    Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "nohup /bin/sh -c '{}' >/dev/null 2>&1 &",
            restart_script
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("spawn macos agent service restart: {err}"))?;

    Ok(format_restart_schedule_detail("launchd", reason))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn schedule_agent_service_restart(reason: Option<&str>) -> Result<String, String> {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let unit_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let unit_name = format!("eguard-agent-self-restart-{}", unit_suffix);
    let restart_script =
        "sleep 2; systemctl restart eguard-agent.service || systemctl restart eguard-agent";

    let output = Command::new("systemd-run")
        .arg("--unit")
        .arg(&unit_name)
        .arg("/bin/sh")
        .arg("-lc")
        .arg(restart_script)
        .output()
        .map_err(|err| format!("systemd-run unavailable: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        if detail.is_empty() {
            return Err(format!(
                "systemd-run restart scheduling failed with status {}",
                output.status
            ));
        }
        return Err(format!("systemd-run restart scheduling failed: {detail}"));
    }

    Ok(format_restart_schedule_detail(&unit_name, reason))
}
