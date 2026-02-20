//! Event enrichment for Windows.
//!
//! Provides process introspection, file hashing, network context,
//! and SID-to-username resolution.

pub mod file;
pub mod network;
pub mod process;
pub mod user;
