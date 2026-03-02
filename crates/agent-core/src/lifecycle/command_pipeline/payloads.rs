use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub(super) struct DeviceActionPayload {
    #[serde(default)]
    pub(super) force: bool,
    #[serde(default)]
    pub(super) reason: String,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct LocatePayload {
    #[serde(default)]
    pub(super) high_accuracy: bool,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct AppPayload {
    #[serde(default)]
    pub(super) package_name: String,
    #[serde(default)]
    pub(super) version: String,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct UpdatePayload {
    #[serde(default, alias = "target_version")]
    pub(super) version: String,
    #[serde(default, alias = "download_url")]
    pub(super) package_url: String,
    #[serde(default, alias = "checksum")]
    pub(super) checksum_sha256: String,
    #[serde(default)]
    pub(super) package_format: String,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RestoreQuarantinePayload {
    #[serde(default)]
    pub(super) quarantine_path: String,
    #[serde(default)]
    pub(super) original_path: String,
}

#[cfg_attr(not(any(target_os = "windows", target_os = "macos")), allow(dead_code))]
#[derive(Debug, Deserialize, Default)]
pub(super) struct ForensicsPayload {
    #[serde(default)]
    pub(super) memory_dump: bool,
    #[serde(default)]
    pub(super) process_list: bool,
    #[serde(default)]
    pub(super) network_connections: bool,
    #[serde(default)]
    pub(super) open_files: bool,
    #[serde(default)]
    pub(super) loaded_modules: bool,
    #[serde(default)]
    pub(super) target_pids: Vec<u32>,
    #[serde(default)]
    pub(super) pid: u32,
    #[serde(default)]
    pub(super) output_path: String,
}

impl ForensicsPayload {
    pub(super) fn wants_snapshot(&self) -> bool {
        self.process_list || self.network_connections || self.open_files || self.loaded_modules
    }

    pub(super) fn effective_target_pids(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for pid in &self.target_pids {
            if *pid == 0 || out.iter().any(|value| value == pid) {
                continue;
            }
            out.push(*pid);
        }
        if self.pid != 0 && !out.iter().any(|value| *value == self.pid) {
            out.push(self.pid);
        }
        out
    }
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct ProfilePayload {
    #[serde(default)]
    pub(super) profile_id: String,
    #[serde(default, deserialize_with = "string_or_object")]
    pub(super) profile_json: String,
}

/// Accept `profile_json` as either a JSON string or a raw JSON object.
/// When the GUI sends `"profile_json": {"ssid": ...}` (object) instead of
/// `"profile_json": "{\"ssid\": ...}"` (string), this converts it to a string.
fn string_or_object<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(s) => Ok(s),
        other => Ok(other.to_string()),
    }
}

pub(super) fn parse_device_action_payload(payload_json: &str) -> DeviceActionPayload {
    serde_json::from_str(payload_json).unwrap_or_default()
}

pub(super) fn parse_locate_payload(payload_json: &str) -> LocatePayload {
    serde_json::from_str(payload_json).unwrap_or_default()
}

pub(super) fn format_device_action_context(payload: &DeviceActionPayload) -> String {
    let reason = payload.reason.trim();
    if reason.is_empty() {
        format!("force={}", payload.force)
    } else {
        format!("force={}, reason={}", payload.force, reason)
    }
}

pub(super) fn parse_update_payload(payload_json: &str) -> UpdatePayload {
    serde_json::from_str(payload_json).unwrap_or_default()
}
