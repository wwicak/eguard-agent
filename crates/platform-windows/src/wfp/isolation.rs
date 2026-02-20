//! Host isolation via WFP.
//!
//! Blocks all network traffic except allowed destinations (e.g. the
//! management server) by installing WFP filters.

use super::filters::{self, WfpAction, WfpFilter, WfpLayer};

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

        let mut created_filter_ids = Vec::new();

        let block_filters = [
            WfpFilter {
                name: "block-inbound-ipv4".to_string(),
                description: "Block all inbound IPv4 while host isolation is active".to_string(),
                layer: WfpLayer::InboundTransportV4,
                action: WfpAction::Block,
                remote_ip: None,
            },
            WfpFilter {
                name: "block-outbound-ipv4".to_string(),
                description: "Block all outbound IPv4 while host isolation is active".to_string(),
                layer: WfpLayer::OutboundTransportV4,
                action: WfpAction::Block,
                remote_ip: None,
            },
            WfpFilter {
                name: "block-inbound-ipv6".to_string(),
                description: "Block all inbound IPv6 while host isolation is active".to_string(),
                layer: WfpLayer::InboundTransportV6,
                action: WfpAction::Block,
                remote_ip: None,
            },
            WfpFilter {
                name: "block-outbound-ipv6".to_string(),
                description: "Block all outbound IPv6 while host isolation is active".to_string(),
                layer: WfpLayer::OutboundTransportV6,
                action: WfpAction::Block,
                remote_ip: None,
            },
        ];

        for filter in block_filters {
            match filters::add_filter(engine, &filter) {
                Ok(filter_id) => created_filter_ids.push(filter_id),
                Err(err) => {
                    rollback_filters(engine, &mut created_filter_ids);
                    return Err(err);
                }
            }
        }

        for ip in allowed_ips
            .iter()
            .copied()
            .map(str::trim)
            .filter(|ip| !ip.is_empty())
        {
            let (in_layer, out_layer) = if ip.contains(':') {
                (WfpLayer::InboundTransportV6, WfpLayer::OutboundTransportV6)
            } else {
                (WfpLayer::InboundTransportV4, WfpLayer::OutboundTransportV4)
            };

            let allow_in = WfpFilter {
                name: format!("allow-inbound-{ip}"),
                description: format!("Allow inbound traffic for {ip}"),
                layer: in_layer,
                action: WfpAction::Permit,
                remote_ip: Some(ip.to_string()),
            };
            let allow_out = WfpFilter {
                name: format!("allow-outbound-{ip}"),
                description: format!("Allow outbound traffic for {ip}"),
                layer: out_layer,
                action: WfpAction::Permit,
                remote_ip: Some(ip.to_string()),
            };

            for filter in [allow_in, allow_out] {
                match filters::add_filter(engine, &filter) {
                    Ok(filter_id) => created_filter_ids.push(filter_id),
                    Err(err) => {
                        rollback_filters(engine, &mut created_filter_ids);
                        return Err(err);
                    }
                }
            }
        }

        self.filter_ids = created_filter_ids;
        self.active = true;
        Ok(())
    }

    /// Deactivate host isolation, removing all installed filters.
    pub fn deactivate(&mut self, engine: &super::WfpEngine) -> Result<(), super::WfpError> {
        if !self.active {
            return Ok(());
        }

        for filter_id in self.filter_ids.drain(..).rev() {
            filters::remove_filter(engine, filter_id)?;
        }
        self.active = false;
        Ok(())
    }

    /// Whether isolation is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Number of active isolation filters.
    pub fn filter_count(&self) -> usize {
        self.filter_ids.len()
    }
}

impl Default for HostIsolation {
    fn default() -> Self {
        Self::new()
    }
}

fn rollback_filters(engine: &super::WfpEngine, created_filter_ids: &mut Vec<u64>) {
    for filter_id in created_filter_ids.drain(..).rev() {
        let _ = filters::remove_filter(engine, filter_id);
    }
}

#[cfg(test)]
mod tests {
    use super::HostIsolation;

    #[test]
    fn host_isolation_installs_and_removes_filters() {
        let engine = crate::wfp::WfpEngine::open().expect("engine opens");
        let mut isolation = HostIsolation::new();

        isolation
            .activate(&engine, &["203.0.113.10", "2001:db8::1"])
            .expect("activate succeeds");
        assert!(isolation.is_active());
        assert!(isolation.filter_count() >= 8);

        isolation.deactivate(&engine).expect("deactivate succeeds");
        assert!(!isolation.is_active());
        assert_eq!(isolation.filter_count(), 0);
    }
}
