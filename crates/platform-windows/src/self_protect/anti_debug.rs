//! Anti-debugging measures.
//!
//! Detects if a debugger is attached to the agent process.

/// Check whether a debugger is attached to the current process.
pub fn detect_debugger() -> bool {
    #[cfg(target_os = "windows")]
    {
        detect_debugger_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("detect_debugger is a stub on non-Windows");
        false
    }
}

#[cfg(target_os = "windows")]
fn detect_debugger_windows() -> bool {
    // TODO: IsDebuggerPresent() || CheckRemoteDebuggerPresent()
    // TODO: NtQueryInformationProcess(ProcessDebugPort)
    false
}
