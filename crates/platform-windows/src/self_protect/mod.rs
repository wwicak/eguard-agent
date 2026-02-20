//! Anti-tamper and self-protection orchestrator.
//!
//! Hardens the agent process and its files against tampering via ACLs,
//! integrity checks, and anti-debugging measures.

pub mod acl;
pub mod anti_debug;
pub mod integrity;

pub use acl::harden_acls;
pub use anti_debug::detect_debugger;
pub use integrity::verify_binary_integrity;

/// Enable all self-protection measures.
pub fn enable_self_protection() -> Result<(), SelfProtectError> {
    harden_acls()?;
    if detect_debugger() {
        tracing::warn!("debugger detected during self-protection init");
    }
    verify_binary_integrity()?;
    Ok(())
}

/// Errors from self-protection operations.
#[derive(Debug)]
pub enum SelfProtectError {
    AclFailed(String),
    IntegrityCheckFailed(String),
    DebuggerDetected,
}

impl std::fmt::Display for SelfProtectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AclFailed(msg) => write!(f, "ACL hardening failed: {msg}"),
            Self::IntegrityCheckFailed(msg) => write!(f, "integrity check failed: {msg}"),
            Self::DebuggerDetected => write!(f, "debugger detected"),
        }
    }
}

impl std::error::Error for SelfProtectError {}
