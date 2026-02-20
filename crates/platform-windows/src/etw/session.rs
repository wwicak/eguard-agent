//! ETW session lifecycle management.
//!
//! Manages creation, configuration, and teardown of ETW trace sessions.

/// Represents a named ETW trace session.
pub struct EtwSession {
    name: String,
    handle: u64,
    active: bool,
}

impl EtwSession {
    /// Create a new session descriptor (does not start tracing).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            handle: 0,
            active: false,
        }
    }

    /// Start the trace session via `StartTraceW`.
    pub fn start(&mut self) -> Result<(), super::EtwError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: StartTraceW(&self.name, ...)
            self.active = true;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!(session = %self.name, "EtwSession::start is a stub on non-Windows");
            self.active = true;
            Ok(())
        }
    }

    /// Enable a provider on this session.
    pub fn enable_provider(&self, provider_guid: &str) -> Result<(), super::EtwError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: EnableTraceEx2(self.handle, provider_guid, ...)
            let _ = provider_guid;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!(
                session = %self.name,
                provider = provider_guid,
                "EtwSession::enable_provider is a stub on non-Windows"
            );
            Ok(())
        }
    }

    /// Stop the session and release resources.
    pub fn stop(&mut self) -> Result<(), super::EtwError> {
        if self.active {
            tracing::info!(session = %self.name, "stopping ETW session");
            self.active = false;
        }
        Ok(())
    }

    /// Session name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Session handle (0 if not started).
    pub fn handle(&self) -> u64 {
        self.handle
    }

    /// Whether the session is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        if self.active {
            let _ = self.stop();
        }
    }
}
