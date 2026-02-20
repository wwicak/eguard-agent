//! ETW session lifecycle management.
//!
//! Manages creation, configuration, and teardown of ETW trace sessions.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SESSION_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Represents a named ETW trace session.
pub struct EtwSession {
    name: String,
    handle: u64,
    active: bool,
    enabled_providers: HashSet<String>,
}

impl EtwSession {
    /// Create a new session descriptor (does not start tracing).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            handle: 0,
            active: false,
            enabled_providers: HashSet::new(),
        }
    }

    /// Start the trace session.
    pub fn start(&mut self) -> Result<(), super::EtwError> {
        if self.active {
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        {
            self.active = true;
            self.handle = NEXT_SESSION_HANDLE.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.active = true;
            self.handle = NEXT_SESSION_HANDLE.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    /// Enable a provider on this session.
    pub fn enable_provider(&mut self, provider_guid: &str) -> Result<(), super::EtwError> {
        if !self.active {
            return Err(super::EtwError::InvalidState(format!(
                "session '{}' is not active",
                self.name
            )));
        }

        let provider = provider_guid.trim();
        if provider.is_empty() {
            return Err(super::EtwError::ProviderEnable(
                "provider guid cannot be empty".to_string(),
            ));
        }

        self.enabled_providers.insert(provider.to_ascii_lowercase());
        Ok(())
    }

    /// Stop the session and release resources.
    pub fn stop(&mut self) -> Result<(), super::EtwError> {
        if self.active {
            tracing::info!(session = %self.name, "stopping ETW session");
            self.active = false;
            self.handle = 0;
            self.enabled_providers.clear();
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

    /// Number of enabled providers.
    pub fn provider_count(&self) -> usize {
        self.enabled_providers.len()
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        if self.active {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EtwSession;

    #[test]
    fn enable_provider_deduplicates_entries() {
        let mut session = EtwSession::new("test");
        session.start().expect("session start");
        session
            .enable_provider("Microsoft-Windows-Kernel-Process")
            .expect("provider 1");
        session
            .enable_provider("microsoft-windows-kernel-process")
            .expect("provider 2");

        assert_eq!(session.provider_count(), 1);
    }
}
