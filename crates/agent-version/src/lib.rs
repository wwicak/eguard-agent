pub const BUILD_VERSION_ENV: &str = "EGUARD_AGENT_VERSION";

pub const fn resolve_compiled_agent_version(
    build_override: Option<&'static str>,
    cargo_version: &'static str,
) -> &'static str {
    if let Some(version) = build_override {
        if !version.is_empty() {
            return version;
        }
    }
    cargo_version
}

pub const fn current_agent_version() -> &'static str {
    resolve_compiled_agent_version(
        option_env!("EGUARD_AGENT_VERSION"),
        env!("CARGO_PKG_VERSION"),
    )
}

#[cfg(test)]
mod tests {
    use super::{current_agent_version, resolve_compiled_agent_version};

    #[test]
    fn resolve_compiled_agent_version_prefers_build_override() {
        assert_eq!(
            resolve_compiled_agent_version(Some("0.2.53"), "0.1.1"),
            "0.2.53"
        );
    }

    #[test]
    fn resolve_compiled_agent_version_falls_back_to_cargo_version() {
        assert_eq!(resolve_compiled_agent_version(None, "0.1.1"), "0.1.1");
        assert_eq!(resolve_compiled_agent_version(Some(""), "0.1.1"), "0.1.1");
    }

    #[test]
    fn current_agent_version_is_never_empty() {
        assert!(!current_agent_version().trim().is_empty());
    }
}
