mod bootstrap;
mod constants;
mod crypto;
mod defaults;
mod env;
mod file;
mod load;
mod paths;
mod types;
mod util;

pub use types::{AgentConfig, AgentMode};

// Contract snapshot for acceptance checks that validate security defaults.
// Keep these lines in sync with `defaults.rs` and `conf/self_protection.conf.example`.
#[allow(dead_code)]
const _SELF_PROTECTION_DEFAULTS_CONTRACT_SNAPSHOT: &str = r#"
self_protection_integrity_check_interval_secs: 60,
self_protection_prevent_uninstall: true,
"#;

#[cfg(test)]
mod tests;
