//! Host isolation via WFP.
//!
//! Blocks all network traffic except allowed destinations (e.g. the
//! management server) by installing WFP filters.

/// Manages host network isolation state.
pub struct HostIsolation {
    active: bool,
    filter_ids: Vec<u64>,
}

impl HostIsolation {
    pub fn new() -> Self {
        Self {
            active: false,
            filter_ids: Vec::new(),
        }
    }

    /// Activate host isolation, blocking all traffic except `allowed_ips`.
    pub fn activate(
        &mut self,
        engine: &super::WfpEngine,
        allowed_ips: &[&str],
    ) -> Result<(), super::WfpError> {
        if self.active {
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        {
            // TODO: Add block-all filter, then permit filters for allowed_ips
            let _ = (engine, allowed_ips);
            self.active = true;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (engine, allowed_ips);
            tracing::warn!("HostIsolation::activate is a stub on non-Windows");
            self.active = true;
            Ok(())
        }
    }

    /// Deactivate host isolation, removing all installed filters.
    pub fn deactivate(&mut self, engine: &super::WfpEngine) -> Result<(), super::WfpError> {
        if !self.active {
            return Ok(());
        }

        for filter_id in self.filter_ids.drain(..) {
            super::filters::remove_filter(engine, filter_id)?;
        }
        self.active = false;
        Ok(())
    }

    /// Whether isolation is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for HostIsolation {
    fn default() -> Self {
        Self::new()
    }
}
