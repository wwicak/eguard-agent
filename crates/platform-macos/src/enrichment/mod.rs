//! Event enrichment for macOS.
//!
//! Provides process introspection, file hashing, network context,
//! and UID-to-username resolution.

pub mod file;
pub mod network;
pub mod process;
pub mod user;
