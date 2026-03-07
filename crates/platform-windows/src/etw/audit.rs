//! Windows audit-policy prerequisites for high-fidelity telemetry.
//!
//! We rely on Security Auditing process-creation events (4688) for stronger
//! parent/command-line truth than kernel ETW alone can provide. On many hosts
//! these audit settings are disabled by default, so the agent opportunistically
//! enables the minimal required knobs at runtime.

#[cfg(target_os = "windows")]
use crate::windows_cmd::{AUDITPOL_EXE, REG_EXE};
#[cfg(target_os = "windows")]
use std::process::Command;

const PROCESS_CREATION_SUBCATEGORY: &str = "Process Creation";
#[cfg(target_os = "windows")]
const PROCESS_CREATION_CMDLINE_REG_PATH: &str =
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
const PROCESS_CREATION_CMDLINE_REG_VALUE: &str = "ProcessCreationIncludeCmdLine_Enabled";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditPolicyStatus {
    pub process_creation_success_enabled: bool,
    pub process_creation_cmdline_enabled: bool,
    pub changed: bool,
}

pub fn ensure_process_creation_auditing() -> Result<AuditPolicyStatus, String> {
    #[cfg(target_os = "windows")]
    {
        let mut status = AuditPolicyStatus {
            process_creation_success_enabled: query_process_creation_auditing_enabled()?,
            process_creation_cmdline_enabled: query_process_creation_cmdline_enabled()?,
            changed: false,
        };

        if !status.process_creation_success_enabled {
            enable_process_creation_auditing()?;
            status.process_creation_success_enabled = query_process_creation_auditing_enabled()?;
            status.changed = true;
        }

        if !status.process_creation_cmdline_enabled {
            enable_process_creation_cmdline()?;
            status.process_creation_cmdline_enabled = query_process_creation_cmdline_enabled()?;
            status.changed = true;
        }

        Ok(status)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(AuditPolicyStatus::default())
    }
}

#[cfg(target_os = "windows")]
fn query_process_creation_auditing_enabled() -> Result<bool, String> {
    let output = Command::new(AUDITPOL_EXE)
        .args(["/get", "/subcategory:Process Creation"])
        .output()
        .map_err(|err| format!("spawn auditpol.exe query: {err}"))?;

    if !output.status.success() {
        return Err(command_error("auditpol query process creation", &output));
    }

    Ok(parse_process_creation_auditpol_enabled(
        &String::from_utf8_lossy(&output.stdout),
    ))
}

#[cfg(target_os = "windows")]
fn enable_process_creation_auditing() -> Result<(), String> {
    let output = Command::new(AUDITPOL_EXE)
        .args(["/set", "/subcategory:Process Creation", "/success:enable"])
        .output()
        .map_err(|err| format!("spawn auditpol.exe set: {err}"))?;

    if output.status.success() {
        return Ok(());
    }

    Err(command_error("auditpol enable process creation", &output))
}

#[cfg(target_os = "windows")]
fn query_process_creation_cmdline_enabled() -> Result<bool, String> {
    let output = Command::new(REG_EXE)
        .args([
            "query",
            PROCESS_CREATION_CMDLINE_REG_PATH,
            "/v",
            PROCESS_CREATION_CMDLINE_REG_VALUE,
        ])
        .output()
        .map_err(|err| format!("spawn reg.exe query: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            stderr.trim().to_string()
        };

        if detail.to_ascii_lowercase().contains("unable to find") {
            return Ok(false);
        }

        return Err(command_error("reg query process creation cmdline", &output));
    }

    Ok(parse_process_creation_cmdline_enabled(
        &String::from_utf8_lossy(&output.stdout),
    ))
}

#[cfg(target_os = "windows")]
fn enable_process_creation_cmdline() -> Result<(), String> {
    let output = Command::new(REG_EXE)
        .args([
            "add",
            PROCESS_CREATION_CMDLINE_REG_PATH,
            "/v",
            PROCESS_CREATION_CMDLINE_REG_VALUE,
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ])
        .output()
        .map_err(|err| format!("spawn reg.exe add: {err}"))?;

    if output.status.success() {
        return Ok(());
    }

    Err(command_error(
        "reg enable process creation cmdline",
        &output,
    ))
}

fn parse_process_creation_auditpol_enabled(output: &str) -> bool {
    output.lines().any(|line| {
        let lowered = line.trim().to_ascii_lowercase();
        lowered.contains(&PROCESS_CREATION_SUBCATEGORY.to_ascii_lowercase())
            && (lowered.contains("success") || lowered.contains("success and failure"))
            && !lowered.contains("no auditing")
    })
}

fn parse_process_creation_cmdline_enabled(output: &str) -> bool {
    output.lines().any(|line| {
        let lowered = line.to_ascii_lowercase();
        if !lowered.contains(&PROCESS_CREATION_CMDLINE_REG_VALUE.to_ascii_lowercase()) {
            return false;
        }

        line.split_whitespace()
            .any(|token| matches!(token.trim(), "0x1" | "0x00000001" | "1" | "0x0001"))
    })
}

#[cfg(target_os = "windows")]
fn command_error(context: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        stderr.trim().to_string()
    };
    format!("{context} failed: {detail}")
}

#[cfg(test)]
mod tests {
    use super::{parse_process_creation_auditpol_enabled, parse_process_creation_cmdline_enabled};

    #[test]
    fn parses_process_creation_auditpol_success_enabled() {
        let sample = r#"System audit policy
Category/Subcategory                      Setting
Detailed Tracking
  Process Creation                        Success
"#;
        assert!(parse_process_creation_auditpol_enabled(sample));
    }

    #[test]
    fn parses_process_creation_auditpol_no_auditing() {
        let sample = r#"System audit policy
Category/Subcategory                      Setting
Detailed Tracking
  Process Creation                        No Auditing
"#;
        assert!(!parse_process_creation_auditpol_enabled(sample));
    }

    #[test]
    fn parses_process_creation_cmdline_registry_enabled() {
        let sample = r#"
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
    ProcessCreationIncludeCmdLine_Enabled    REG_DWORD    0x1
"#;
        assert!(parse_process_creation_cmdline_enabled(sample));
    }

    #[test]
    fn parses_process_creation_cmdline_registry_disabled() {
        let sample = r#"
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
    ProcessCreationIncludeCmdLine_Enabled    REG_DWORD    0x0
"#;
        assert!(!parse_process_creation_cmdline_enabled(sample));
    }
}
