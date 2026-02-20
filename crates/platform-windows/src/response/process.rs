//! Process termination via TerminateProcess.

/// Terminate a process by PID.
pub fn terminate_process(pid: u32) -> Result<(), ResponseError> {
    #[cfg(target_os = "windows")]
    {
        // TODO: OpenProcess(PROCESS_TERMINATE, pid) + TerminateProcess
        let _ = pid;
        Ok(())
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
        // TODO: NtQueryInformationProcess to enumerate children, then terminate
        let _ = pid;
        Ok(0)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        tracing::warn!(pid, "terminate_process_tree is a stub on non-Windows");
        Ok(0)
    }
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
