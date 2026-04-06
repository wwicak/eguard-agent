mod client;
mod listener;
mod tunnel;
mod types;

pub use client::{TunnelClient, TunnelClientConfig};
pub use listener::{LocalForwardHandle, LocalForwardManager};
pub use tunnel::{resolve_or_create_wireguard_identity, WireguardIdentity};
pub use types::{TunnelDecision, TunnelGrant, TunnelRequest};
