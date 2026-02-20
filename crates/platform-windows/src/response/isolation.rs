//! Network isolation response action via WFP.

/// Isolate a host from the network, allowing only the specified server IPs.
pub fn isolate_host(allowed_server_ips: &[&str]) -> Result<(), super::process::ResponseError> {
    #[cfg(target_os = "windows")]
    {
        // TODO: use crate::wfp::HostIsolation to install block-all + permit rules
        let _ = allowed_server_ips;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = allowed_server_ips;
        tracing::warn!("isolate_host is a stub on non-Windows");
        Ok(())
    }
}

/// Remove host network isolation.
pub fn remove_isolation() -> Result<(), super::process::ResponseError> {
    #[cfg(target_os = "windows")]
    {
        // TODO: use crate::wfp::HostIsolation::deactivate
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("remove_isolation is a stub on non-Windows");
        Ok(())
    }
}
