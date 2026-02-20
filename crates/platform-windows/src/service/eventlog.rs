//! Windows Event Log integration.

#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "windows")]
const EVENT_ID_INFO: u32 = 1001;
#[cfg(target_os = "windows")]
const EVENT_ID_WARNING: u32 = 2001;
#[cfg(target_os = "windows")]
const EVENT_ID_ERROR: u32 = 3001;

/// Writes structured events to the Windows Event Log.
pub struct EventLogger {
    source_name: String,
}

impl EventLogger {
    pub fn new(source_name: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
        }
    }

    /// Register the event source with the Windows Event Log.
    pub fn register(&self) -> Result<(), EventLogError> {
        #[cfg(target_os = "windows")]
        {
            // `eventcreate` implicitly registers source when invoked with /SO.
            self.run_eventcreate(
                "INFORMATION",
                1000,
                "eGuard event source registration completed",
            )
            .map_err(EventLogError::RegisterFailed)?;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!(source = %self.source_name, "EventLogger::register is a stub on non-Windows");
            Ok(())
        }
    }

    /// Write an informational event.
    pub fn log_info(&self, message: &str) {
        #[cfg(target_os = "windows")]
        {
            let _ = self.run_eventcreate("INFORMATION", EVENT_ID_INFO, message);
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::info!(source = %self.source_name, message, "EventLog info (stub)");
        }
    }

    /// Write a warning event.
    pub fn log_warning(&self, message: &str) {
        #[cfg(target_os = "windows")]
        {
            let _ = self.run_eventcreate("WARNING", EVENT_ID_WARNING, message);
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!(source = %self.source_name, message, "EventLog warning (stub)");
        }
    }

    /// Write an error event.
    pub fn log_error(&self, message: &str) {
        #[cfg(target_os = "windows")]
        {
            let _ = self.run_eventcreate("ERROR", EVENT_ID_ERROR, message);
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::error!(source = %self.source_name, message, "EventLog error (stub)");
        }
    }

    /// Log a critical detection event (4000-4099 range).
    pub fn log_critical_detection(&self, detection_code: u32, message: &str) {
        let event_id = normalize_detection_event_id(detection_code);

        #[cfg(target_os = "windows")]
        {
            let _ = self.run_eventcreate("ERROR", event_id, message);
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::error!(
                source = %self.source_name,
                event_id,
                message,
                "EventLog critical detection (stub)"
            );
        }
    }

    /// Source name.
    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    #[cfg(target_os = "windows")]
    fn run_eventcreate(
        &self,
        event_type: &str,
        event_id: u32,
        message: &str,
    ) -> Result<(), String> {
        let output = Command::new("eventcreate")
            .args([
                "/L",
                "APPLICATION",
                "/T",
                event_type,
                "/SO",
                &self.source_name,
                "/ID",
                &event_id.to_string(),
                "/D",
                message,
            ])
            .output()
            .map_err(|err| format!("failed spawning eventcreate: {err}"))?;

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
        Err(detail.trim().to_string())
    }
}

fn normalize_detection_event_id(detection_code: u32) -> u32 {
    4000 + (detection_code % 100)
}

/// Errors from Event Log operations.
#[derive(Debug)]
pub enum EventLogError {
    RegisterFailed(String),
    WriteFailed(String),
}

impl std::fmt::Display for EventLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegisterFailed(msg) => write!(f, "event log register failed: {msg}"),
            Self::WriteFailed(msg) => write!(f, "event log write failed: {msg}"),
        }
    }
}

impl std::error::Error for EventLogError {}

#[cfg(test)]
mod tests {
    use super::normalize_detection_event_id;

    #[test]
    fn detection_event_ids_are_mapped_to_critical_range() {
        assert_eq!(normalize_detection_event_id(0), 4000);
        assert_eq!(normalize_detection_event_id(17), 4017);
        assert_eq!(normalize_detection_event_id(123), 4023);
        assert_eq!(normalize_detection_event_id(9999), 4099);
    }
}
