//! Service start/stop/recovery lifecycle management.

#[cfg(target_os = "windows")]
use crate::windows_cmd::SC_EXE;
#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
use std::thread::sleep;
#[cfg(target_os = "windows")]
use std::time::Duration;

const DEFAULT_BINARY_PATH: &str = r"C:\Program Files\eGuard\eguard-agent.exe";

#[cfg(target_os = "windows")]
const SERVICE_STATE_POLL_ATTEMPTS: u32 = 10;
#[cfg(target_os = "windows")]
const SERVICE_STATE_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Manages the agent's Windows service lifecycle.
pub struct ServiceLifecycle {
    service_name: String,
    binary_path: String,
}

impl ServiceLifecycle {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            binary_path: DEFAULT_BINARY_PATH.to_string(),
        }
    }

    pub fn with_binary_path(
        service_name: impl Into<String>,
        binary_path: impl Into<String>,
    ) -> Self {
        Self {
            service_name: service_name.into(),
            binary_path: binary_path.into(),
        }
    }

    /// Register the agent as a Windows service.
    ///
    /// Idempotent: if the service already exists, updates its configuration
    /// via `sc.exe config` instead of failing on `sc.exe create`.
    pub fn install(&self) -> Result<(), ServiceError> {
        #[cfg(target_os = "windows")]
        {
            validate_service_name(&self.service_name)?;
            validate_binary_path(&self.binary_path)?;

            let already_exists = service_exists(&self.service_name)?;

            if already_exists {
                let config_args = vec![
                    "config".to_string(),
                    self.service_name.clone(),
                    format!("binPath= \"{}\"", self.binary_path),
                    "start= auto".to_string(),
                ];
                run_sc(&config_args).map_err(|err| map_sc_error("install", &err))?;
            } else {
                let create_args = vec![
                    "create".to_string(),
                    self.service_name.clone(),
                    format!("binPath= \"{}\"", self.binary_path),
                    "start= auto".to_string(),
                ];
                run_sc(&create_args).map_err(|err| map_sc_error("install", &err))?;
            }

            let description_args = vec![
                "description".to_string(),
                self.service_name.clone(),
                "eGuard endpoint security agent".to_string(),
            ];
            let _ = run_sc(&description_args);

            self.configure_recovery()?;
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
            validate_service_name(&self.service_name)?;

            let _ = self.stop();
            run_sc(&["delete".to_string(), self.service_name.clone()])
                .map_err(|err| map_sc_error("uninstall", &err))?;
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
            validate_service_name(&self.service_name)?;

            run_sc(&["start".to_string(), self.service_name.clone()])
                .map_err(|err| map_sc_error("start", &err))?;
            wait_for_state(&self.service_name, "RUNNING")
                .map_err(|err| ServiceError::StartFailed(err.to_string()))?;
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
            validate_service_name(&self.service_name)?;

            run_sc(&["stop".to_string(), self.service_name.clone()])
                .map_err(|err| map_sc_error("stop", &err))?;
            wait_for_state(&self.service_name, "STOPPED")
                .map_err(|err| ServiceError::StopFailed(err.to_string()))?;
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
            validate_service_name(&self.service_name)?;

            let failure_args = vec![
                "failure".to_string(),
                self.service_name.clone(),
                "reset= 300".to_string(),
                "actions= restart/5000/restart/30000/restart/60000".to_string(),
            ];
            run_sc(&failure_args).map_err(|err| map_sc_error("configure recovery", &err))?;

            let failure_flag_args = vec![
                "failureflag".to_string(),
                self.service_name.clone(),
                "1".to_string(),
            ];
            run_sc(&failure_flag_args).map_err(|err| map_sc_error("configure recovery", &err))?;

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

    /// Configured service binary path.
    pub fn binary_path(&self) -> &str {
        &self.binary_path
    }
}

#[cfg(target_os = "windows")]
fn run_sc(args: &[String]) -> Result<String, String> {
    let output = Command::new(SC_EXE)
        .args(args)
        .output()
        .map_err(|err| format!("failed spawning sc.exe: {err}"))?;

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    if output.status.success() {
        return Ok(stdout);
    }

    let detail = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    Err(format!("sc.exe {:?} failed: {}", args, detail.trim()))
}

#[cfg(target_os = "windows")]
fn query_service_state(service_name: &str) -> Result<Option<String>, String> {
    let output = run_sc(&["query".to_string(), service_name.to_string()])?;
    Ok(parse_sc_state(&output))
}

#[cfg(target_os = "windows")]
fn service_exists(service_name: &str) -> Result<bool, ServiceError> {
    match query_service_state(service_name) {
        Ok(_) => Ok(true),
        Err(err) if is_service_not_found_error(&err) => Ok(false),
        Err(err) => Err(map_sc_error("install", &err)),
    }
}

#[cfg(target_os = "windows")]
fn wait_for_state(service_name: &str, target: &str) -> Result<(), String> {
    for _ in 0..SERVICE_STATE_POLL_ATTEMPTS {
        if let Some(state) = query_service_state(service_name)? {
            if state.eq_ignore_ascii_case(target) {
                return Ok(());
            }
        }
        sleep(SERVICE_STATE_POLL_INTERVAL);
    }

    Err(format!(
        "service '{service_name}' did not reach state '{target}' in time"
    ))
}

#[cfg(any(test, target_os = "windows"))]
fn validate_service_name(service_name: &str) -> Result<(), ServiceError> {
    let trimmed = service_name.trim();
    if trimmed.is_empty() {
        return Err(ServiceError::InstallFailed(
            "service name cannot be empty".to_string(),
        ));
    }

    if trimmed
        .chars()
        .any(|ch| matches!(ch, '\r' | '\n' | '\0' | '"'))
    {
        return Err(ServiceError::InstallFailed(
            "service name contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

#[cfg(any(test, target_os = "windows"))]
fn validate_binary_path(binary_path: &str) -> Result<(), ServiceError> {
    let trimmed = binary_path.trim();
    if trimmed.is_empty() {
        return Err(ServiceError::InstallFailed(
            "service binary path cannot be empty".to_string(),
        ));
    }

    if trimmed
        .chars()
        .any(|ch| matches!(ch, '\r' | '\n' | '\0' | '"'))
    {
        return Err(ServiceError::InstallFailed(
            "service binary path contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

#[cfg(any(test, target_os = "windows"))]
fn is_service_not_found_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("does not exist as an installed service")
        || lower.contains("specified service does not exist")
        || lower.contains("failed 1060")
}

#[cfg(any(test, target_os = "windows"))]
fn parse_sc_state(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if !trimmed.to_ascii_uppercase().starts_with("STATE") {
            continue;
        }

        let (_, right) = trimmed.split_once(':')?;
        let tokens: Vec<&str> = right.split_whitespace().collect();
        if tokens.is_empty() {
            return None;
        }

        // Typical format: "4  RUNNING"
        if tokens[0].chars().all(|ch| ch.is_ascii_digit()) {
            return tokens.get(1).map(|s| s.to_string());
        }
        return Some(tokens[0].to_string());
    }

    None
}

#[cfg(any(test, target_os = "windows"))]
fn map_sc_error(operation: &str, message: &str) -> ServiceError {
    let lower = message.to_ascii_lowercase();
    if lower.contains("access is denied") {
        return ServiceError::AccessDenied(message.to_string());
    }

    match operation {
        "start" => ServiceError::StartFailed(message.to_string()),
        "stop" => ServiceError::StopFailed(message.to_string()),
        _ => ServiceError::InstallFailed(message.to_string()),
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

#[cfg(test)]
mod tests {
    use super::{
        is_service_not_found_error, map_sc_error, parse_sc_state, validate_binary_path,
        validate_service_name, ServiceError, ServiceLifecycle,
    };

    #[test]
    fn parse_sc_state_extracts_running() {
        let sample = "\nSERVICE_NAME: eGuardAgent\n        STATE              : 4  RUNNING\n";
        assert_eq!(parse_sc_state(sample).as_deref(), Some("RUNNING"));
    }

    #[test]
    fn parse_sc_state_extracts_stopped() {
        let sample = "STATE              : 1  STOPPED";
        assert_eq!(parse_sc_state(sample).as_deref(), Some("STOPPED"));
    }

    #[test]
    fn map_sc_error_detects_access_denied() {
        let err = map_sc_error("start", "OpenService FAILED 5: Access is denied.");
        assert!(matches!(err, ServiceError::AccessDenied(_)));
    }

    #[test]
    fn lifecycle_supports_binary_path_override() {
        let lifecycle = ServiceLifecycle::with_binary_path("eGuardAgent", r"C:\eGuard\agent.exe");
        assert_eq!(lifecycle.name(), "eGuardAgent");
        assert_eq!(lifecycle.binary_path(), r"C:\eGuard\agent.exe");
    }

    #[test]
    fn validate_service_name_rejects_empty_or_quoted_values() {
        assert!(validate_service_name("").is_err());
        assert!(validate_service_name("\"quoted\"").is_err());
        assert!(validate_service_name("eGuardAgent").is_ok());
    }

    #[test]
    fn validate_binary_path_rejects_quotes() {
        assert!(validate_binary_path("").is_err());
        assert!(validate_binary_path("C:\\Path\\evil\\\".exe").is_err());
        assert!(validate_binary_path(r"C:\Program Files\eGuard\eguard-agent.exe").is_ok());
    }

    #[test]
    fn service_not_found_detection_matches_sc_output_patterns() {
        assert!(is_service_not_found_error(
            "[SC] OpenService FAILED 1060: The specified service does not exist as an installed service."
        ));
        assert!(!is_service_not_found_error("Access is denied"));
    }
}
