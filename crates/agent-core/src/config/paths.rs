use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::constants::{AGENT_CONFIG_CANDIDATES, BOOTSTRAP_CONFIG_CANDIDATES};

pub(super) fn resolve_config_path() -> Result<Option<PathBuf>> {
    resolve_path_from_env_or_candidates("EGUARD_AGENT_CONFIG", &AGENT_CONFIG_CANDIDATES)
}

pub(super) fn resolve_bootstrap_path() -> Result<Option<PathBuf>> {
    resolve_path_from_env_or_candidates("EGUARD_BOOTSTRAP_CONFIG", &BOOTSTRAP_CONFIG_CANDIDATES)
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
