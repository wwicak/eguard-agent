#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(test)]
use anyhow::Context;
use anyhow::Result;

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
#[cfg(not(target_os = "windows"))]
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
#[cfg(not(target_os = "windows"))]
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
