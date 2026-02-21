//! macOS response action executor.
//!
//! Implements response actions: file quarantine, network isolation,
//! and forensic collection.

pub mod forensics;
pub mod isolation;
pub mod quarantine;

pub use forensics::ForensicsCollector;
pub use isolation::{isolate_host, remove_isolation};
pub use quarantine::quarantine_file;
pub use quarantine::restore_file;

/// Errors from response actions.
#[derive(Debug)]
pub enum ResponseError {
    AccessDenied(String),
    ProcessNotFound(u32),
    OperationFailed(String),
}

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessDenied(msg) => write!(f, "access denied: {msg}"),
            Self::ProcessNotFound(pid) => write!(f, "process {pid} not found"),
            Self::OperationFailed(msg) => write!(f, "operation failed: {msg}"),
        }
    }
}

impl std::error::Error for ResponseError {}
