//! Forensic collection: MiniDump creation and handle enumeration.

/// Forensics data collector.
pub struct ForensicsCollector;

impl ForensicsCollector {
    pub fn new() -> Self {
        Self
    }

    /// Create a MiniDump of the given process.
    pub fn create_minidump(&self, pid: u32, output_path: &str) -> Result<(), super::process::ResponseError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: MiniDumpWriteDump(OpenProcess(pid), output_path)
            let _ = (pid, output_path);
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (pid, output_path);
            tracing::warn!(pid, "create_minidump is a stub on non-Windows");
            Ok(())
        }
    }

    /// Enumerate open handles for a process.
    pub fn enumerate_handles(&self, pid: u32) -> Vec<HandleInfo> {
        #[cfg(target_os = "windows")]
        {
            // TODO: NtQuerySystemInformation(SystemHandleInformation)
            let _ = pid;
            Vec::new()
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = pid;
            tracing::warn!(pid, "enumerate_handles is a stub on non-Windows");
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
