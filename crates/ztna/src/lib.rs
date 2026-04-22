mod client;
mod listener;
mod tunnel;
mod types;
#[cfg(target_os = "windows")]
mod windows_tunnel;

pub use client::{TunnelClient, TunnelClientConfig};
pub use listener::{LocalForwardHandle, LocalForwardManager};
pub use tunnel::{resolve_or_create_wireguard_identity, WireguardIdentity};
pub use types::{TunnelDecision, TunnelGrant, TunnelRequest, TunnelSession};
#[cfg(target_os = "windows")]
pub use windows_tunnel::{apply_windows_tunnel_grant, remove_windows_tunnel};
