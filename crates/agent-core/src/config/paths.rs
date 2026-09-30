#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(test)]
use anyhow::Context;
use anyhow::Result;

use super::constants::{AGENT_CONFIG_CANDIDATES, BOOTSTRAP_CONFIG_CANDIDATES};

#[cfg(target_os = "linux")]
const DEFAULT_LAST_KNOWN_GOOD_CONFIG_PATH: &str =
    "/var/lib/eguard-agent/agent.last_known_good.toml";
#[cfg(target_os = "macos")]
const DEFAULT_LAST_KNOWN_GOOD_CONFIG_PATH: &str =
    "/Library/Application Support/eGuard/agent.last_known_good.toml";
#[cfg(target_os = "windows")]
const DEFAULT_LAST_KNOWN_GOOD_CONFIG_PATH: &str =
    r"C:\ProgramData\eGuard\agent.last_known_good.toml";

pub(super) fn resolve_config_path() -> Result<Option<PathBuf>> {
    resolve_path_from_env_or_candidates("EGUARD_AGENT_CONFIG", &AGENT_CONFIG_CANDIDATES)
}

pub(super) fn resolve_bootstrap_path() -> Result<Option<PathBuf>> {
    resolve_path_from_env_or_candidates("EGUARD_BOOTSTRAP_CONFIG", &BOOTSTRAP_CONFIG_CANDIDATES)
}

pub(super) fn primary_config_path() -> PathBuf {
    if let Ok(raw) = std::env::var("EGUARD_AGENT_CONFIG") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    PathBuf::from(AGENT_CONFIG_CANDIDATES[0])
}

pub(super) fn resolve_last_known_good_config_path() -> PathBuf {
    if let Ok(raw) = std::env::var("EGUARD_LAST_KNOWN_AGENT_CONFIG") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    PathBuf::from(DEFAULT_LAST_KNOWN_GOOD_CONFIG_PATH)
}

#[cfg(test)]
pub fn remove_bootstrap_config(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("failed removing bootstrap config {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
#[cfg(target_os = "linux")]
pub fn expected_config_files() -> &'static [&'static str] {
    &[
        "/etc/eguard-agent/bootstrap.conf",
        "/etc/eguard-agent/agent.conf",
        "/etc/eguard-agent/certs/agent.crt",
        "/etc/eguard-agent/certs/agent.key",
        "/etc/eguard-agent/certs/ca.crt",
    ]
}

#[cfg(test)]
#[cfg(target_os = "macos")]
pub fn expected_config_files() -> &'static [&'static str] {
    &[
        "/Library/Application Support/eGuard/bootstrap.conf",
        "/Library/Application Support/eGuard/agent.conf",
        "/Library/Application Support/eGuard/certs/agent.crt",
        "/Library/Application Support/eGuard/certs/agent.key",
        "/Library/Application Support/eGuard/certs/ca.crt",
    ]
}

#[cfg(test)]
#[cfg(target_os = "windows")]
pub fn expected_config_files() -> &'static [&'static str] {
    &[
        r"C:\ProgramData\eGuard\bootstrap.conf",
        r"C:\ProgramData\eGuard\agent.conf",
        r"C:\ProgramData\eGuard\certs\agent.crt",
        r"C:\ProgramData\eGuard\certs\agent.key",
        r"C:\ProgramData\eGuard\certs\ca.crt",
    ]
}

#[cfg(test)]
#[cfg(target_os = "linux")]
pub fn expected_data_paths() -> &'static [&'static str] {
    &[
        "/var/lib/eguard-agent/buffer.db",
        "/var/lib/eguard-agent/baselines.bin",
        "/var/lib/eguard-agent/rules/sigma/",
        "/var/lib/eguard-agent/rules/yara/",
        "/var/lib/eguard-agent/rules/ioc/",
        "/var/lib/eguard-agent/quarantine/",
        "/var/lib/eguard-agent/rules-staging/",
    ]
}

#[cfg(test)]
#[cfg(target_os = "macos")]
pub fn expected_data_paths() -> &'static [&'static str] {
    &[
        "/Library/Application Support/eGuard/buffer.db",
        "/Library/Application Support/eGuard/baselines.bin",
        "/Library/Application Support/eGuard/rules/sigma/",
        "/Library/Application Support/eGuard/rules/yara/",
        "/Library/Application Support/eGuard/rules/ioc/",
        "/Library/Application Support/eGuard/quarantine/",
        "/Library/Application Support/eGuard/rules-staging/",
    ]
}

#[cfg(test)]
#[cfg(target_os = "windows")]
pub fn expected_data_paths() -> &'static [&'static str] {
    &[
        r"C:\ProgramData\eGuard\buffer.db",
        r"C:\ProgramData\eGuard\baselines.bin",
        r"C:\ProgramData\eGuard\rules\sigma\",
        r"C:\ProgramData\eGuard\rules\yara\",
        r"C:\ProgramData\eGuard\rules\ioc\",
        r"C:\ProgramData\eGuard\quarantine\",
        r"C:\ProgramData\eGuard\rules-staging\",
    ]
}

#[cfg(unix)]
impl super::types::AgentConfig {
    /// Protect the loader-selected config/bootstrap and the effective TLS paths.
    /// None or a path equal to the platform default counts as default. On macOS
    /// only, each default path also retains its legacy /etc protection. Explicit
    /// non-default paths are exclusive.
    pub(crate) fn sensitive_config_paths(&self) -> Vec<PathBuf> {
        self.sensitive_config_paths_with_defaults(
            AGENT_CONFIG_CANDIDATES[0],
            BOOTSTRAP_CONFIG_CANDIDATES[0],
            cfg!(target_os = "macos"),
        )
    }

    fn sensitive_config_paths_with_defaults(
        &self,
        default_agent: &str,
        default_bootstrap: &str,
        include_legacy_defaults: bool,
    ) -> Vec<PathBuf> {
        let default_agent = Path::new(default_agent);
        let default_bootstrap = Path::new(default_bootstrap);
        let certs = default_agent
            .parent()
            .expect("config default has parent")
            .join("certs");
        let defaults = [
            default_agent.to_path_buf(),
            default_bootstrap.to_path_buf(),
            certs.join("agent.crt"),
            certs.join("agent.key"),
            certs.join("ca.crt"),
        ];
        let configured = [
            self.agent_config_path.clone(),
            self.bootstrap_config_path.clone(),
            self.tls_cert_path.as_ref().map(PathBuf::from),
            self.tls_key_path.as_ref().map(PathBuf::from),
            self.tls_ca_path.as_ref().map(PathBuf::from),
        ];
        let mut paths = Vec::new();
        for (path, default) in configured.into_iter().zip(defaults) {
            let using_default = path.as_ref().is_none_or(|path| path == &default);
            if include_legacy_defaults && using_default {
                let relative = default
                    .strip_prefix(default_agent.parent().unwrap())
                    .unwrap();
                paths.push(Path::new("/etc/eguard-agent").join(relative));
            }
            paths.push(path.unwrap_or(default));
        }
        paths
    }
}

#[cfg(all(test, unix))]
mod permission_path_tests {
    use super::super::constants::{
        MACOS_AGENT_CONFIG_CANDIDATES, MACOS_BOOTSTRAP_CONFIG_CANDIDATES,
    };
    use super::*;
    use crate::config::AgentConfig;

    #[cfg(target_os = "linux")]
    #[test]
    fn default_permission_paths_match_previous_hard_coded_set() {
        let paths = AgentConfig::default().sensitive_config_paths();
        assert_eq!(
            paths,
            [
                "/etc/eguard-agent/agent.conf",
                "/etc/eguard-agent/bootstrap.conf",
                "/etc/eguard-agent/certs/agent.crt",
                "/etc/eguard-agent/certs/agent.key",
                "/etc/eguard-agent/certs/ca.crt",
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn macos_default_permission_paths_include_loader_and_legacy_defaults() {
        let paths = AgentConfig::default().sensitive_config_paths_with_defaults(
            MACOS_AGENT_CONFIG_CANDIDATES[0],
            MACOS_BOOTSTRAP_CONFIG_CANDIDATES[0],
            true,
        );
        let mut expected = [
            "/Library/Application Support/eGuard/agent.conf",
            "/Library/Application Support/eGuard/bootstrap.conf",
            "/Library/Application Support/eGuard/certs/agent.crt",
            "/Library/Application Support/eGuard/certs/agent.key",
            "/Library/Application Support/eGuard/certs/ca.crt",
        ]
        .map(PathBuf::from)
        .to_vec();
        expected.extend(
            [
                "/etc/eguard-agent/agent.conf",
                "/etc/eguard-agent/bootstrap.conf",
                "/etc/eguard-agent/certs/agent.crt",
                "/etc/eguard-agent/certs/agent.key",
                "/etc/eguard-agent/certs/ca.crt",
            ]
            .map(PathBuf::from),
        );
        let mut paths = paths;
        paths.sort();
        expected.sort();
        assert_eq!(paths, expected);
    }

    #[test]
    fn explicitly_configured_permission_paths_are_exclusive_on_every_platform() {
        let config = AgentConfig {
            agent_config_path: Some(PathBuf::from("/custom/agent.toml")),
            bootstrap_config_path: Some(PathBuf::from("/custom/bootstrap.ini")),
            tls_cert_path: Some("/custom/client.pem".into()),
            tls_key_path: Some("/custom/private.pem".into()),
            tls_ca_path: Some("/custom/authority.pem".into()),
            ..Default::default()
        };
        let expected = [
            "/custom/agent.toml",
            "/custom/bootstrap.ini",
            "/custom/client.pem",
            "/custom/private.pem",
            "/custom/authority.pem",
        ]
        .map(PathBuf::from);
        assert_eq!(config.sensitive_config_paths(), expected);
        assert_eq!(
            config.sensitive_config_paths_with_defaults(
                MACOS_AGENT_CONFIG_CANDIDATES[0],
                MACOS_BOOTSTRAP_CONFIG_CANDIDATES[0],
                true,
            ),
            expected
        );
    }

    #[test]
    fn explicit_platform_defaults_retain_macos_legacy_protection() {
        let certs = Path::new(MACOS_AGENT_CONFIG_CANDIDATES[0])
            .parent()
            .unwrap()
            .join("certs");
        let config = AgentConfig {
            agent_config_path: Some(PathBuf::from(MACOS_AGENT_CONFIG_CANDIDATES[0])),
            bootstrap_config_path: Some(PathBuf::from(MACOS_BOOTSTRAP_CONFIG_CANDIDATES[0])),
            tls_cert_path: Some(certs.join("agent.crt").to_str().unwrap().into()),
            tls_key_path: Some(certs.join("agent.key").to_str().unwrap().into()),
            tls_ca_path: Some(certs.join("ca.crt").to_str().unwrap().into()),
            ..Default::default()
        };
        assert_eq!(
            config.sensitive_config_paths_with_defaults(
                MACOS_AGENT_CONFIG_CANDIDATES[0],
                MACOS_BOOTSTRAP_CONFIG_CANDIDATES[0],
                true,
            ),
            AgentConfig::default().sensitive_config_paths_with_defaults(
                MACOS_AGENT_CONFIG_CANDIDATES[0],
                MACOS_BOOTSTRAP_CONFIG_CANDIDATES[0],
                true,
            ),
        );
    }

    #[test]
    fn partial_configuration_retains_only_unset_default_paths() {
        let config = AgentConfig {
            agent_config_path: Some(PathBuf::from("/custom/agent.toml")),
            tls_key_path: Some("/custom/private.pem".into()),
            ..Default::default()
        };
        let paths = config.sensitive_config_paths_with_defaults(
            MACOS_AGENT_CONFIG_CANDIDATES[0],
            MACOS_BOOTSTRAP_CONFIG_CANDIDATES[0],
            true,
        );
        assert_eq!(paths.len(), 8);
        assert!(paths.contains(&PathBuf::from("/custom/agent.toml")));
        assert!(paths.contains(&PathBuf::from("/custom/private.pem")));
        assert!(paths.contains(&PathBuf::from("/etc/eguard-agent/bootstrap.conf")));
        assert!(paths.contains(&PathBuf::from("/etc/eguard-agent/certs/agent.crt")));
        assert!(paths.contains(&PathBuf::from("/etc/eguard-agent/certs/ca.crt")));
        assert!(!paths.contains(&PathBuf::from("/etc/eguard-agent/agent.conf")));
        assert!(!paths.contains(&PathBuf::from("/etc/eguard-agent/certs/agent.key")));
    }
}

fn resolve_path_from_env_or_candidates(
    env_var: &str,
    candidates: &[&str],
) -> Result<Option<PathBuf>> {
    if let Ok(p) = std::env::var(env_var) {
        let p = p.trim();
        if !p.is_empty() {
            let path = PathBuf::from(p);
            if !path.exists() {
                anyhow::bail!("configured {} does not exist: {}", env_var, path.display());
            }
            return Ok(Some(path));
        }
    }

    for candidate in candidates {
        let p = Path::new(candidate);
        if p.exists() {
            return Ok(Some(p.to_path_buf()));
        }
    }

    Ok(None)
}
