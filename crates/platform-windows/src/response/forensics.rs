//! Forensic collection: MiniDump creation and handle enumeration.

#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

/// Forensics data collector.
pub struct ForensicsCollector;

impl ForensicsCollector {
    pub fn new() -> Self {
        Self
    }

    /// Create a MiniDump of the given process.
    pub fn create_minidump(
        &self,
        pid: u32,
        output_path: &str,
    ) -> Result<(), super::process::ResponseError> {
        #[cfg(target_os = "windows")]
        {
            if pid == 0 {
                return Err(super::process::ResponseError::OperationFailed(
                    "refusing to dump PID 0".to_string(),
                ));
            }
            if output_path.trim().is_empty() {
                return Err(super::process::ResponseError::OperationFailed(
                    "output path cannot be empty".to_string(),
                ));
            }

            let output = Command::new("rundll32.exe")
                .args([
                    "C:\\Windows\\System32\\comsvcs.dll,MiniDump",
                    &pid.to_string(),
                    output_path,
                    "full",
                ])
                .output()
                .map_err(|err| {
                    super::process::ResponseError::OperationFailed(format!(
                        "failed spawning rundll32 MiniDump: {err}"
                    ))
                })?;

            if output.status.success() {
                return Ok(());
            }

            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let detail = if stderr.trim().is_empty() {
                stdout
            } else {
                stderr
            };
            Err(super::process::ResponseError::OperationFailed(detail))
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (pid, output_path);
            Ok(())
        }
    }

    /// Enumerate open handles for a process.
    pub fn enumerate_handles(&self, pid: u32) -> Vec<HandleInfo> {
        #[cfg(target_os = "windows")]
        {
            let cmd = format!(
                "Get-Process -Id {} | Select-Object -First 1 Handles,ProcessName,Path | ConvertTo-Json -Compress",
                pid
            );
            let output = match Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &cmd])
                .output()
            {
                Ok(out) => out,
                Err(_) => return Vec::new(),
            };
            if !output.status.success() {
                return Vec::new();
            }

            let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
            parse_handle_summary_json(&raw)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = pid;
            Vec::new()
        }
    }
}

impl Default for ForensicsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about an open handle.
#[derive(Debug, Clone)]
pub struct HandleInfo {
    pub handle_value: u64,
    pub object_type: String,
    pub object_name: Option<String>,
}

#[cfg(any(test, target_os = "windows"))]
fn parse_handle_summary_json(raw: &str) -> Vec<HandleInfo> {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };

    let handle_count = value
        .get("Handles")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let process_name = value
        .get("ProcessName")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let path = value
        .get("Path")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if handle_count == 0 {
        return Vec::new();
    }

    vec![HandleInfo {
        handle_value: handle_count,
        object_type: "ProcessHandleCount".to_string(),
        object_name: Some(format!("{process_name}:{path}")),
    }]
}

#[cfg(test)]
mod tests {
    use super::parse_handle_summary_json;

    #[test]
    fn parses_process_handle_summary_json() {
        let raw = r#"{"Handles":154,"ProcessName":"powershell","Path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}"#;
        let handles = parse_handle_summary_json(raw);

        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].handle_value, 154);
        assert_eq!(handles[0].object_type, "ProcessHandleCount");
    }
}
