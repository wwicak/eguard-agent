//! Windows response action executor.
//!
//! Implements response actions: process termination, file quarantine,
//! forensic collection, and network isolation.

pub mod forensics;
pub mod isolation;
pub mod process;
pub mod quarantine;

pub use forensics::ForensicsCollector;
pub use isolation::{isolate_host, remove_isolation};
pub use process::terminate_process;
pub use quarantine::quarantine_file;
