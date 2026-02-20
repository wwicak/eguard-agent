//! Anti-tamper and self-protection orchestrator.
//!
//! Hardens the agent process against tampering via ptrace denial,
//! code signature verification, and binary integrity checks.

pub mod anti_debug;
pub mod codesign;
pub mod integrity;

pub use anti_debug::deny_attach;
pub use codesign::verify_code_signature;
pub use integrity::verify_binary_integrity;

/// Enable all self-protection measures.
pub fn enable_self_protection() -> Result<(), SelfProtectError> {
    deny_attach()?;
    verify_code_signature()?;
    verify_binary_integrity()?;
    Ok(())
}

/// Errors from self-protection operations.
#[derive(Debug)]
pub enum SelfProtectError {
    AntiDebugFailed(String),
    CodeSignFailed(String),
    IntegrityCheckFailed(String),
    DebuggerDetected,
}

impl std::fmt::Display for SelfProtectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AntiDebugFailed(msg) => write!(f, "anti-debug failed: {msg}"),
            Self::CodeSignFailed(msg) => write!(f, "code signature check failed: {msg}"),
            Self::IntegrityCheckFailed(msg) => write!(f, "integrity check failed: {msg}"),
            Self::DebuggerDetected => write!(f, "debugger detected"),
        }
    }
}

impl std::error::Error for SelfProtectError {}
