//! LaunchDaemon service management for macOS.
//!
//! Manages the agent as a macOS LaunchDaemon and generates the
//! corresponding plist configuration.

pub mod launchd;
pub mod plist;

pub use launchd::ServiceLifecycle;
pub use plist::generate_plist;
