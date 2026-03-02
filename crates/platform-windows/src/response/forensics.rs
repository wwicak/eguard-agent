//! Forensic collection: MiniDump creation and handle enumeration.

#[cfg(target_os = "windows")]
use crate::windows_cmd::{POWERSHELL_EXE, RUNDLL32_EXE};
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

            let output = Command::new(RUNDLL32_EXE)
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
            let output = match Command::new(POWERSHELL_EXE)
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

    /// Collect endpoint snapshot data for incident triage.
    pub fn collect_full_snapshot(
        &self,
        include_processes: bool,
        include_network: bool,
        include_open_files: bool,
        include_loaded_modules: bool,
    ) -> ForensicSnapshot {
        #[cfg(target_os = "windows")]
        {
            let processes = if include_processes {
                run_powershell_capture(
                    "Get-Process | Select-Object Id,ProcessName,Path,CPU,WS,StartTime | ConvertTo-Json -Depth 4",
                )
            } else {
                String::new()
            };

            let network = if include_network {
                run_powershell_capture(
                    "Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Depth 4",
                )
            } else {
                String::new()
            };

            let open_files = if include_open_files {
                run_powershell_capture(
                    "Get-Process | Select-Object Id,ProcessName,Handles,Path | ConvertTo-Json -Depth 4",
                )
            } else {
                String::new()
            };

            let loaded_modules = if include_loaded_modules {
                run_powershell_capture("driverquery /FO CSV /NH | Out-String")
            } else {
                String::new()
            };

            return ForensicSnapshot {
                processes,
                network,
                open_files,
                loaded_modules,
            };
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (
                include_processes,
                include_network,
                include_open_files,
                include_loaded_modules,
            );
            ForensicSnapshot::default()
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

/// Collected forensic snapshot sections.
#[derive(Debug, Clone, Default)]
pub struct ForensicSnapshot {
    pub processes: String,
    pub network: String,
    pub open_files: String,
    pub loaded_modules: String,
}

#[cfg(target_os = "windows")]
const FORENSICS_OUTPUT_MAX_BYTES: usize = 1_048_576;

#[cfg(target_os = "windows")]
fn run_powershell_capture(command: &str) -> String {
    let output = match Command::new(POWERSHELL_EXE)
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
    {
        Ok(output) => output,
        Err(err) => return format!("spawn failed: {}", err),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let primary = if !stdout.trim().is_empty() {
        stdout
    } else if !stderr.trim().is_empty() {
        stderr
    } else {
        format!("command produced no output: {}", command)
    };

    truncate_forensics_output(primary, FORENSICS_OUTPUT_MAX_BYTES)
}

#[cfg(target_os = "windows")]
fn truncate_forensics_output(text: String, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text;
    }

    let truncated = text.chars().take(max_bytes).collect::<String>();
    format!(
        "{}\n...[truncated, {} bytes omitted]",
        truncated,
        text.len() - max_bytes
    )
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
