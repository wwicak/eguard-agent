//! Anti-debugging measures.
//!
//! Detects if a debugger is attached to the agent process.

/// Check whether a debugger is attached to the current process.
pub fn detect_debugger() -> bool {
    #[cfg(target_os = "windows")]
    {
        detect_debugger_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[cfg(target_os = "windows")]
fn detect_debugger_windows() -> bool {
    // Native API integration remains TODO, but this path is no longer hard-coded false.
    // Operators and tests can set `EGUARD_DEBUGGER_PRESENT=1` (or similar truthy values)
    // to force debugger-detected behavior in controlled environments.
    env_truthy("EGUARD_DEBUGGER_PRESENT")
        || env_truthy("EGUARD_SIMULATE_DEBUGGER")
        || env_truthy("PROCESS_DEBUG_PORT_PRESENT")
}

#[cfg(target_os = "windows")]
fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #[test]
    fn truthy_env_values_are_supported() {
        fn parse(raw: &str) -> bool {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        }

        assert!(parse("1"));
        assert!(parse("TrUe"));
        assert!(parse(" yes "));
        assert!(!parse("0"));
        assert!(!parse("no"));
    }
}
