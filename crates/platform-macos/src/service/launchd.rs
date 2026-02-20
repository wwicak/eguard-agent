//! LaunchDaemon lifecycle management via launchctl.

#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::thread::sleep;
#[cfg(target_os = "macos")]
use std::time::Duration;

const DEFAULT_BINARY_PATH: &str = "/usr/local/bin/eguard-agent";

#[allow(dead_code)]
const DEFAULT_LABEL: &str = "com.eguard.agent";

#[cfg(target_os = "macos")]
const DOMAIN_TARGET: &str = "system";
#[cfg(target_os = "macos")]
const SERVICE_STATE_POLL_ATTEMPTS: u32 = 10;
#[cfg(target_os = "macos")]
const SERVICE_STATE_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Manages the agent's macOS LaunchDaemon lifecycle.
pub struct ServiceLifecycle {
    label: String,
    binary_path: String,
}

impl ServiceLifecycle {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            binary_path: DEFAULT_BINARY_PATH.to_string(),
        }
    }

    pub fn with_binary_path(label: impl Into<String>, binary_path: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            binary_path: binary_path.into(),
        }
    }

    /// Install the LaunchDaemon plist and bootstrap it.
    pub fn install(&self) -> Result<(), ServiceError> {
        #[cfg(target_os = "macos")]
        {
            let plist_path = format!("/Library/LaunchDaemons/{}.plist", self.label);
            let plist_content = super::plist::generate_plist(&self.label, &self.binary_path);

            std::fs::write(&plist_path, plist_content).map_err(|err| {
                ServiceError::InstallFailed(format!("failed writing plist {plist_path}: {err}"))
            })?;

            // Bootstrap (load) the service.
            run_launchctl(&["bootstrap", DOMAIN_TARGET, &plist_path])
                .map_err(|err| ServiceError::InstallFailed(err))?;

            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            tracing::warn!(label = %self.label, "service install is a stub on non-macOS");
            Ok(())
        }
    }

    /// Uninstall the LaunchDaemon.
    pub fn uninstall(&self) -> Result<(), ServiceError> {
        #[cfg(target_os = "macos")]
        {
            let _ = self.stop();
            let service_target = format!("{DOMAIN_TARGET}/{}", self.label);
            let _ = run_launchctl(&["bootout", &service_target]);
            let plist_path = format!("/Library/LaunchDaemons/{}.plist", self.label);
            let _ = std::fs::remove_file(&plist_path);
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            tracing::warn!(label = %self.label, "service uninstall is a stub on non-macOS");
            Ok(())
        }
    }

    /// Start the service via launchctl kickstart.
    pub fn start(&self) -> Result<(), ServiceError> {
        #[cfg(target_os = "macos")]
        {
            let service_target = format!("{DOMAIN_TARGET}/{}", self.label);
            run_launchctl(&["kickstart", "-k", &service_target])
                .map_err(|err| ServiceError::StartFailed(err))?;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            tracing::warn!(label = %self.label, "service start is a stub on non-macOS");
            Ok(())
        }
    }

    /// Stop the service.
    pub fn stop(&self) -> Result<(), ServiceError> {
        #[cfg(target_os = "macos")]
        {
            let service_target = format!("{DOMAIN_TARGET}/{}", self.label);
            run_launchctl(&["kill", "SIGTERM", &service_target])
                .map_err(|err| ServiceError::StopFailed(err))?;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            tracing::warn!(label = %self.label, "service stop is a stub on non-macOS");
            Ok(())
        }
    }

    /// Service label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Configured binary path.
    pub fn binary_path(&self) -> &str {
        &self.binary_path
    }
}

#[cfg(target_os = "macos")]
fn run_launchctl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("launchctl")
        .args(args)
        .output()
        .map_err(|err| format!("failed spawning launchctl: {err}"))?;

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    if output.status.success() {
        return Ok(());
    }

    let detail = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    Err(format!("launchctl {:?} failed: {}", args, detail.trim()))
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

#[cfg(test)]
mod tests {
    use super::ServiceLifecycle;

    #[test]
    fn lifecycle_supports_binary_path_override() {
        let lifecycle = ServiceLifecycle::with_binary_path("com.eguard.agent", "/opt/eguard/agent");
        assert_eq!(lifecycle.label(), "com.eguard.agent");
        assert_eq!(lifecycle.binary_path(), "/opt/eguard/agent");
    }

    #[test]
    fn lifecycle_default_label() {
        let lifecycle = ServiceLifecycle::new("com.eguard.agent");
        assert_eq!(lifecycle.label(), "com.eguard.agent");
        assert_eq!(lifecycle.binary_path(), "/usr/local/bin/eguard-agent");
    }
}
