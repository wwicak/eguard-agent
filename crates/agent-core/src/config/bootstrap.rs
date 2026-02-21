use std::fs;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tracing::{info, warn};

use super::paths::resolve_bootstrap_path;
use super::types::AgentConfig;
use super::util::format_server_addr;

const SUPPORTED_BOOTSTRAP_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Default)]
pub(super) struct BootstrapConfig {
    pub(super) address: Option<String>,
    pub(super) grpc_port: Option<u16>,
    pub(super) enrollment_token: Option<String>,
    pub(super) tenant_id: Option<String>,
    pub(super) schema_version: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct BootstrapJsonConfig {
    address: Option<String>,
    server_url: Option<String>,
    grpc_port: Option<u16>,
    enrollment_token: Option<String>,
    tenant_id: Option<String>,
    schema_version: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapFormat {
    Ini,
    LegacyJson,
}

#[derive(Debug, Clone)]
struct ParsedBootstrap {
    config: BootstrapConfig,
    format: BootstrapFormat,
}

impl AgentConfig {
    pub(super) fn apply_bootstrap_config(&mut self) -> Result<()> {
        let path = resolve_bootstrap_path()?;
        let Some(path) = path else {
            return Ok(());
        };

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed reading bootstrap config {}", path.display()))?;
        let parsed = parse_bootstrap_config_with_metadata(&raw).with_context(|| {
            format!(
                "failed parsing bootstrap config {}",
                path.as_path().display()
            )
        })?;

        validate_bootstrap_config(&parsed.config)?;

        if parsed.format == BootstrapFormat::LegacyJson {
            warn!(
                path = %path.display(),
                "legacy JSON bootstrap format detected; migrate to canonical [server] schema"
            );

            if let Err(err) = rewrite_legacy_bootstrap_to_canonical(&path, &parsed.config) {
                warn!(
                    path = %path.display(),
                    error = %err,
                    "failed rewriting legacy bootstrap config to canonical format"
                );
            } else {
                info!(
                    path = %path.display(),
                    "rewrote legacy bootstrap config to canonical format"
                );
            }
        }

        if let Some(version) = parsed.config.schema_version {
            info!(
                path = %path.display(),
                schema_version = version,
                "applied bootstrap config"
            );
        }

        let bootstrap = parsed.config;

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

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn parse_bootstrap_config(raw: &str) -> Result<BootstrapConfig> {
    let parsed = parse_bootstrap_config_with_metadata(raw)?;
    validate_bootstrap_config(&parsed.config)?;
    Ok(parsed.config)
}

fn parse_bootstrap_config_with_metadata(raw: &str) -> Result<ParsedBootstrap> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('{') {
        let config = parse_bootstrap_json(trimmed)?;
        return Ok(ParsedBootstrap {
            config,
            format: BootstrapFormat::LegacyJson,
        });
    }

    parse_bootstrap_ini(raw)
}

fn parse_bootstrap_json(raw: &str) -> Result<BootstrapConfig> {
    let parsed: BootstrapJsonConfig =
        serde_json::from_str(raw).context("invalid bootstrap JSON payload")?;

    let address = parsed.address.or_else(|| {
        parsed
            .server_url
            .as_deref()
            .and_then(extract_host_from_server_url)
    });

    let grpc_port = parsed.grpc_port.or_else(|| {
        parsed
            .server_url
            .as_deref()
            .and_then(extract_port_from_server_url)
    });

    Ok(BootstrapConfig {
        address,
        grpc_port,
        enrollment_token: normalize_optional(parsed.enrollment_token),
        tenant_id: normalize_optional(parsed.tenant_id),
        schema_version: parsed.schema_version,
    })
}

fn parse_bootstrap_ini(raw: &str) -> Result<ParsedBootstrap> {
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
        apply_bootstrap_server_entry(&mut cfg, &key, &value)?;
    }

    Ok(ParsedBootstrap {
        config: cfg,
        format: BootstrapFormat::Ini,
    })
}

fn validate_bootstrap_config(cfg: &BootstrapConfig) -> Result<()> {
    if let Some(version) = cfg.schema_version {
        if version != SUPPORTED_BOOTSTRAP_SCHEMA_VERSION {
            bail!(
                "unsupported bootstrap schema_version {} (supported: {})",
                version,
                SUPPORTED_BOOTSTRAP_SCHEMA_VERSION
            );
        }
    }

    let token = cfg
        .enrollment_token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| anyhow::anyhow!("bootstrap config missing enrollment_token"))?;

    if token.contains('\n') || token.contains('\r') {
        bail!("bootstrap enrollment_token contains unsupported control characters");
    }

    if let Some(address) = cfg
        .address
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        if address.contains('\n') || address.contains('\r') {
            bail!("bootstrap address contains unsupported control characters");
        }
    }

    Ok(())
}

fn rewrite_legacy_bootstrap_to_canonical(
    path: &std::path::Path,
    cfg: &BootstrapConfig,
) -> Result<()> {
    let canonical = render_canonical_bootstrap(cfg, Some("legacy_json"));
    fs::write(path, canonical).with_context(|| {
        format!(
            "failed writing canonical bootstrap config {}",
            path.display()
        )
    })
}

fn render_canonical_bootstrap(cfg: &BootstrapConfig, migrated_from: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str("[server]\n");

    if let Some(schema_version) = cfg
        .schema_version
        .or(Some(SUPPORTED_BOOTSTRAP_SCHEMA_VERSION))
    {
        out.push_str(&format!("schema_version = {schema_version}\n"));
    }

    if let Some(source) = migrated_from {
        out.push_str(&format!("migrated_from = {source}\n"));
    }

    if let Some(address) = cfg
        .address
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        out.push_str(&format!("address = {address}\n"));
    }

    if let Some(grpc_port) = cfg.grpc_port {
        out.push_str(&format!("grpc_port = {grpc_port}\n"));
    }

    if let Some(token) = cfg
        .enrollment_token
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        out.push_str(&format!("enrollment_token = {token}\n"));
    }

    if let Some(tenant_id) = cfg
        .tenant_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        out.push_str(&format!("tenant_id = {tenant_id}\n"));
    }

    out
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn extract_host_from_server_url(raw: &str) -> Option<String> {
    let without_scheme = raw
        .trim()
        .strip_prefix("https://")
        .or_else(|| raw.trim().strip_prefix("http://"))
        .unwrap_or(raw.trim());

    let authority = without_scheme.split('/').next()?.trim();
    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') {
        return authority
            .strip_prefix('[')
            .and_then(|v| v.split(']').next())
            .map(|v| v.to_string());
    }

    if authority.matches(':').count() == 1 {
        if let Some((host, port)) = authority.rsplit_once(':') {
            if port.parse::<u16>().is_ok() {
                let host = host.trim();
                if !host.is_empty() {
                    return Some(host.to_string());
                }
            }
        }
    }

    Some(authority.to_string())
}

fn extract_port_from_server_url(raw: &str) -> Option<u16> {
    let without_scheme = raw
        .trim()
        .strip_prefix("https://")
        .or_else(|| raw.trim().strip_prefix("http://"))
        .unwrap_or(raw.trim());

    let authority = without_scheme.split('/').next()?.trim();
    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') {
        return authority
            .split_once("]:")
            .and_then(|(_, p)| p.parse::<u16>().ok());
    }

    if authority.matches(':').count() != 1 {
        return None;
    }

    authority
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
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

fn apply_bootstrap_server_entry(cfg: &mut BootstrapConfig, key: &str, value: &str) -> Result<()> {
    match key {
        "address" => cfg.address = Some(value.to_string()),
        "server_url" => {
            if cfg.address.is_none() {
                cfg.address = extract_host_from_server_url(value);
            }
            if cfg.grpc_port.is_none() {
                cfg.grpc_port = extract_port_from_server_url(value);
            }
        }
        "grpc_port" => {
            let port = value
                .parse::<u16>()
                .with_context(|| format!("invalid grpc_port value: {value}"))?;
            cfg.grpc_port = Some(port);
        }
        "enrollment_token" => cfg.enrollment_token = Some(value.to_string()),
        "tenant_id" => cfg.tenant_id = Some(value.to_string()),
        "schema_version" => {
            let version = value
                .parse::<u16>()
                .with_context(|| format!("invalid schema_version value: {value}"))?;
            cfg.schema_version = Some(version);
        }
        _ => {}
    }

    Ok(())
}
