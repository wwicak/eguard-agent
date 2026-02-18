mod buffer;
mod client;
#[cfg(test)]
mod proto_tests;
mod retry;
mod types;

pub mod pb {
    tonic::include_proto!("eguard.v1");
}

pub use buffer::{
    estimate_event_size, EventBuffer, OfflineBuffer, SqliteBuffer, DEFAULT_BUFFER_CAP_BYTES,
};
pub use client::Client;
pub use retry::RetryPolicy;
pub use types::{
    CertificatePolicyEnvelope, CommandEnvelope, ComplianceCheckEnvelope, ComplianceEnvelope,
    EnrollmentEnvelope, EnrollmentResultEnvelope, EventEnvelope, FleetBaselineEnvelope,
    InventoryEnvelope, PolicyEnvelope, ResponseEnvelope, ServerState, ThreatIntelVersionEnvelope,
    TlsConfig, TransportMode,
};
