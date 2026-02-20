//! Network connection enrichment.
//!
//! On Windows, uses GetExtendedTcpTable / GetExtendedUdpTable to map
//! connections back to owning PIDs.

/// Resolved network connection context.
#[derive(Debug, Clone)]
pub struct NetworkContext {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
}

/// Look up the network context for a given PID.
pub fn resolve_network_context(pid: u32) -> Option<NetworkContext> {
    #[cfg(target_os = "windows")]
    {
        resolve_network_context_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        tracing::warn!(pid, "resolve_network_context is a stub on non-Windows");
        None
    }
}

#[cfg(target_os = "windows")]
fn resolve_network_context_windows(pid: u32) -> Option<NetworkContext> {
    // TODO: GetExtendedTcpTable with TCP_TABLE_OWNER_PID_ALL
    let _ = pid;
    None
}
