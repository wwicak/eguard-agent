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
pub(super) struct RestoreQuarantinePayload {
    #[serde(default)]
    pub(super) quarantine_path: String,
    #[serde(default)]
    pub(super) original_path: String,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Deserialize, Default)]
pub(super) struct ForensicsPayload {
    #[serde(default)]
    pub(super) pid: u32,
    #[serde(default)]
    pub(super) output_path: String,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct ProfilePayload {
    #[serde(default)]
    pub(super) profile_id: String,
    #[serde(default)]
    pub(super) profile_json: String,
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
