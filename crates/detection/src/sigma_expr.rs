// RAFIX shared: retain pack semantics alongside core grading and schema.
use std::net::IpAddr;

use regex::Regex;

use crate::types::TelemetryEvent;

/// Same-event Sigma logic, separate from temporal sequence correlation.
#[derive(Debug, Clone)]
pub enum SigmaExpr {
    All(Vec<SigmaExpr>),
    Any(Vec<SigmaExpr>),
    Not(Box<SigmaExpr>),
    Text(SigmaField, Regex),
    Number(SigmaField, u32),
    Cidr(IpAddr, u8),
}

#[derive(Debug, Clone, Copy)]
pub enum SigmaField {
    Process,
    ProcessPath,
    Parent,
    CommandLine,
    FilePath,
    Domain,
    Ip,
    Port,
    Uid,
}

impl SigmaExpr {
    /// Evaluation borrows telemetry and precompiled matchers; no heap allocation.
    pub fn matches(&self, event: &TelemetryEvent) -> bool {
        match self {
            Self::All(children) => children.iter().all(|child| child.matches(event)),
            Self::Any(children) => children.iter().any(|child| child.matches(event)),
            Self::Not(child) => !child.matches(event),
            Self::Text(field, pattern) => field.text(event).is_some_and(|v| pattern.is_match(v)),
            Self::Number(SigmaField::Uid, n) => event.uid == *n,
            Self::Number(SigmaField::Port, n) => event.dst_port.map(u32::from) == Some(*n),
            Self::Number(_, _) => false,
            Self::Cidr(network, prefix) => event
                .dst_ip
                .as_deref()
                .and_then(|ip| ip.parse::<IpAddr>().ok())
                .is_some_and(|ip| match (network, ip) {
                    (IpAddr::V4(net), IpAddr::V4(addr)) => {
                        let mask = u32::MAX.checked_shl(32 - u32::from(*prefix)).unwrap_or(0);
                        u32::from(*net) & mask == u32::from(addr) & mask
                    }
                    (IpAddr::V6(net), IpAddr::V6(addr)) => {
                        let mask = u128::MAX.checked_shl(128 - u32::from(*prefix)).unwrap_or(0);
                        u128::from(*net) & mask == u128::from(addr) & mask
                    }
                    _ => false,
                }),
        }
    }
}

impl SigmaField {
    fn text(self, event: &TelemetryEvent) -> Option<&str> {
        match self {
            Self::Process => Some(&event.process),
            Self::ProcessPath => event.file_path.as_deref(),
            Self::Parent => Some(&event.parent_process),
            Self::CommandLine => event.command_line.as_deref(),
            Self::FilePath => event.file_path.as_deref(),
            Self::Domain => event.dst_domain.as_deref(),
            Self::Ip => event.dst_ip.as_deref(),
            Self::Port | Self::Uid => None,
        }
    }
}
