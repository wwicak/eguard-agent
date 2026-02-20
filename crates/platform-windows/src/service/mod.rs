//! Windows Service Control Manager integration.
//!
//! Manages the agent as a Windows service and integrates with the
//! Windows Event Log.

pub mod eventlog;
pub mod lifecycle;

pub use eventlog::EventLogger;
pub use lifecycle::ServiceLifecycle;
