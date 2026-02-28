//! Process termination helpers for Windows response actions.

#[cfg(target_os = "windows")]
use crate::windows_cmd::TASKKILL_EXE;
#[cfg(target_os = "windows")]
use std::process::Command;

/// Terminate a process by PID.
pub fn terminate_process(pid: u32) -> Result<(), ResponseError> {
    #[cfg(target_os = "windows")]
    {
        if pid == 0 {
            return Err(ResponseError::OperationFailed(
                "refusing to terminate PID 0".to_string(),
            ));
        }
        run_taskkill(pid, false).map(|_| ())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        tracing::warn!(pid, "terminate_process is a stub on non-Windows");
        Ok(())
    }
}

/// Terminate a process tree (process and all descendants).
pub fn terminate_process_tree(pid: u32) -> Result<u32, ResponseError> {
    #[cfg(target_os = "windows")]
    {
        if pid == 0 {
            return Err(ResponseError::OperationFailed(
                "refusing to terminate PID 0".to_string(),
            ));
        }
        run_taskkill(pid, true)?;
        Ok(1)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        tracing::warn!(pid, "terminate_process_tree is a stub on non-Windows");
        Ok(0)
    }
}

#[cfg(target_os = "windows")]
fn taskkill_args(pid: u32, include_tree: bool) -> Vec<String> {
    let mut args = vec!["/PID".to_string(), pid.to_string()];
    if include_tree {
        args.push("/T".to_string());
    }
    args.push("/F".to_string());
    args
}

#[cfg(target_os = "windows")]
fn run_taskkill(pid: u32, include_tree: bool) -> Result<(), ResponseError> {
    let output = Command::new(TASKKILL_EXE)
        .args(taskkill_args(pid, include_tree))
        .output()
        .map_err(|err| ResponseError::OperationFailed(format!("taskkill spawn failed: {err}")))?;

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
    let lower = detail.to_ascii_lowercase();

    if lower.contains("not found") || lower.contains("no running instance") {
        return Err(ResponseError::ProcessNotFound(pid));
    }
    if lower.contains("access is denied") {
        return Err(ResponseError::AccessDenied(detail));
    }

    Err(ResponseError::OperationFailed(detail))
}

/// Errors from response actions.
#[derive(Debug)]
pub enum ResponseError {
    AccessDenied(String),
    ProcessNotFound(u32),
    OperationFailed(String),
}

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessDenied(msg) => write!(f, "access denied: {msg}"),
            Self::ProcessNotFound(pid) => write!(f, "process {pid} not found"),
            Self::OperationFailed(msg) => write!(f, "operation failed: {msg}"),
        }
    }
}

impl std::error::Error for ResponseError {}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::taskkill_args;

    #[test]
    fn taskkill_args_include_force_and_optional_tree() {
        assert_eq!(taskkill_args(42, false), vec!["/PID", "42", "/F"]);
        assert_eq!(taskkill_args(42, true), vec!["/PID", "42", "/T", "/F"]);
    }
}
