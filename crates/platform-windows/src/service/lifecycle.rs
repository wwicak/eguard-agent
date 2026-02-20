//! Service start/stop/recovery lifecycle management.

/// Manages the agent's Windows service lifecycle.
pub struct ServiceLifecycle {
    service_name: String,
}

impl ServiceLifecycle {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }

    /// Register the agent as a Windows service.
    pub fn install(&self) -> Result<(), ServiceError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: OpenSCManager + CreateServiceW
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!(service = %self.service_name, "service install is a stub on non-Windows");
            Ok(())
        }
    }

    /// Unregister the Windows service.
    pub fn uninstall(&self) -> Result<(), ServiceError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: OpenSCManager + OpenService + DeleteService
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!(service = %self.service_name, "service uninstall is a stub on non-Windows");
            Ok(())
        }
    }

    /// Start the service.
    pub fn start(&self) -> Result<(), ServiceError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: StartServiceW
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!(service = %self.service_name, "service start is a stub on non-Windows");
            Ok(())
        }
    }

    /// Stop the service.
    pub fn stop(&self) -> Result<(), ServiceError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: ControlService(SERVICE_CONTROL_STOP)
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!(service = %self.service_name, "service stop is a stub on non-Windows");
            Ok(())
        }
    }

    /// Configure automatic restart on failure.
    pub fn configure_recovery(&self) -> Result<(), ServiceError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: ChangeServiceConfig2(SERVICE_CONFIG_FAILURE_ACTIONS)
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!(service = %self.service_name, "configure_recovery is a stub on non-Windows");
            Ok(())
        }
    }

    /// Service name.
    pub fn name(&self) -> &str {
        &self.service_name
    }
}

/// Errors from service operations.
#[derive(Debug)]
pub enum ServiceError {
    InstallFailed(String),
    StartFailed(String),
    StopFailed(String),
    AccessDenied(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InstallFailed(msg) => write!(f, "service install failed: {msg}"),
            Self::StartFailed(msg) => write!(f, "service start failed: {msg}"),
            Self::StopFailed(msg) => write!(f, "service stop failed: {msg}"),
            Self::AccessDenied(msg) => write!(f, "service access denied: {msg}"),
        }
    }
}

impl std::error::Error for ServiceError {}
