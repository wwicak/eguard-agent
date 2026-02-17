use std::fs;

use anyhow::{Context, Result};

use super::paths::resolve_bootstrap_path;
use super::types::AgentConfig;
use super::util::format_server_addr;

#[derive(Debug, Clone, Default)]
pub(super) struct BootstrapConfig {
    pub(super) address: Option<String>,
    pub(super) grpc_port: Option<u16>,
    pub(super) enrollment_token: Option<String>,
    pub(super) tenant_id: Option<String>,
}

impl AgentConfig {
    pub(super) fn apply_bootstrap_config(&mut self) -> Result<()> {
        let path = resolve_bootstrap_path()?;
        let Some(path) = path else {
            return Ok(());
        };

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed reading bootstrap config {}", path.display()))?;
        let bootstrap = parse_bootstrap_config(&raw).with_context(|| {
            format!(
                "failed parsing bootstrap config {}",
                path.as_path().display()
            )
        })?;

        if let Some(address) = bootstrap.address {
            self.server_addr = format_server_addr(&address, bootstrap.grpc_port);
            self.transport_mode = "grpc".to_string();
        }
        if let Some(token) = bootstrap.enrollment_token {
            self.enrollment_token = Some(token);
        }
        if let Some(tenant_id) = bootstrap.tenant_id {
            self.tenant_id = Some(tenant_id);
        }

        self.bootstrap_config_path = Some(path);
        Ok(())
    }
}

pub(super) fn parse_bootstrap_config(raw: &str) -> Result<BootstrapConfig> {
    let mut cfg = BootstrapConfig::default();
    let mut section = String::new();

    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if is_bootstrap_comment_or_empty(line) {
            continue;
        }

        if let Some(parsed_section) = parse_bootstrap_section_name(line) {
            section = parsed_section;
            continue;
        }

        if section != "server" {
            continue;
        }

        let Some((key, value)) = parse_bootstrap_server_entry(line) else {
            continue;
        };
        apply_bootstrap_server_entry(&mut cfg, &key, &value);
    }

    Ok(cfg)
}

fn is_bootstrap_comment_or_empty(line: &str) -> bool {
    line.is_empty() || line.starts_with('#') || line.starts_with(';')
}

fn parse_bootstrap_section_name(line: &str) -> Option<String> {
    line.strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .map(|section| section.trim().to_ascii_lowercase())
}

fn parse_bootstrap_server_entry(line: &str) -> Option<(String, String)> {
    let line = strip_bootstrap_inline_comment(line).trim();
    if line.is_empty() {
        return None;
    }

    let (raw_key, raw_value) = line.split_once('=')?;
    let key = raw_key.trim().to_ascii_lowercase();
    let value = raw_value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string();
    if value.is_empty() {
        return None;
    }

    Some((key, value))
}

fn strip_bootstrap_inline_comment(line: &str) -> &str {
    let hash_idx = line.find('#');
    let semicolon_idx = line.find(';');
    let cut_at = match (hash_idx, semicolon_idx) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };

    cut_at.map(|idx| &line[..idx]).unwrap_or(line)
}

fn apply_bootstrap_server_entry(cfg: &mut BootstrapConfig, key: &str, value: &str) {
    match key {
        "address" => cfg.address = Some(value.to_string()),
        "grpc_port" => {
            if let Ok(port) = value.parse::<u16>() {
                cfg.grpc_port = Some(port);
            }
        }
        "enrollment_token" => cfg.enrollment_token = Some(value.to_string()),
        "tenant_id" => cfg.tenant_id = Some(value.to_string()),
        _ => {}
    }
}
