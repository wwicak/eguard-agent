//! Windows Event Log integration.

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
            // TODO: RegisterEventSourceW
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
            // TODO: ReportEventW(EVENTLOG_INFORMATION_TYPE)
            let _ = message;
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
            // TODO: ReportEventW(EVENTLOG_WARNING_TYPE)
            let _ = message;
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
            // TODO: ReportEventW(EVENTLOG_ERROR_TYPE)
            let _ = message;
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::error!(source = %self.source_name, message, "EventLog error (stub)");
        }
    }

    /// Source name.
    pub fn source_name(&self) -> &str {
        &self.source_name
    }
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
