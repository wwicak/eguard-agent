//! WFP network filtering rules.

/// A WFP filter definition.
#[derive(Debug, Clone)]
pub struct WfpFilter {
    pub name: String,
    pub description: String,
    pub layer: WfpLayer,
    pub action: WfpAction,
}

/// WFP filtering layers.
#[derive(Debug, Clone, Copy)]
pub enum WfpLayer {
    InboundTransportV4,
    OutboundTransportV4,
    InboundTransportV6,
    OutboundTransportV6,
}

/// Filter action (permit or block).
#[derive(Debug, Clone, Copy)]
pub enum WfpAction {
    Permit,
    Block,
}

/// Add a filter to the WFP engine.
pub fn add_filter(engine: &super::WfpEngine, filter: &WfpFilter) -> Result<u64, super::WfpError> {
    #[cfg(target_os = "windows")]
    {
        // TODO: FwpmFilterAdd0(engine.handle(), ...)
        let _ = (engine, filter);
        Ok(0)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (engine, filter);
        tracing::warn!("wfp::add_filter is a stub on non-Windows");
        Ok(0)
    }
}

/// Remove a filter by its ID.
pub fn remove_filter(engine: &super::WfpEngine, filter_id: u64) -> Result<(), super::WfpError> {
    #[cfg(target_os = "windows")]
    {
        // TODO: FwpmFilterDeleteById0(engine.handle(), filter_id)
        let _ = (engine, filter_id);
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (engine, filter_id);
        tracing::warn!("wfp::remove_filter is a stub on non-Windows");
        Ok(())
    }
}
