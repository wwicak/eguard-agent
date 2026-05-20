#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clap::Parser;
use serde::Deserialize;
use std::collections::BTreeMap;

const EMBEDDED_CONFIG_MARKER: &str = "EGUARD_SETUPCFG_V1:";

#[derive(Parser, Debug)]
#[command(name = "eguard-setup", about = "eGuard Windows installer bootstrap")]
struct Args {
    #[arg(long)]
    server_url: Option<String>,

    #[arg(long)]
    enrollment_token: Option<String>,

    #[arg(long)]
    expected_hash: Option<String>,

    #[arg(long)]
    allow_insecure_http: bool,

    #[arg(long)]
    allow_unsigned_msi: bool,

    #[arg(long)]
    keep_bootstrap: bool,
}

#[derive(Debug, Default, Deserialize)]
struct EmbeddedConfig {
    server_url: Option<String>,
    enrollment_token: Option<String>,
    expected_hash: Option<String>,
    profile_id: Option<String>,
    profile_name: Option<String>,
    env_overrides: Option<BTreeMap<String, String>>,
}

#[cfg(target_os = "windows")]
fn main() -> Result<()> {
    run_windows()
}

#[cfg(not(target_os = "windows"))]
fn main() -> Result<()> {
    bail!("windows-bootstrap only supports Windows")
}

#[cfg(target_os = "windows")]
fn run_windows() -> Result<()> {
    use std::env;
    use std::fs;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let args = Args::parse();
    let exe_path = env::current_exe().context("resolve current exe path")?;
    let embedded = read_embedded_config(&exe_path).unwrap_or_default();

    let server_url = args
        .server_url
        .or_else(|| std::env::var("EGUARD_SERVER_URL").ok())
        .or(embedded.server_url)
        .unwrap_or_default()
        .trim()
        .to_string();
    let enrollment_token = args
        .enrollment_token
        .or_else(|| std::env::var("EGUARD_ENROLLMENT_TOKEN").ok())
        .or(embedded.enrollment_token)
        .unwrap_or_default()
        .trim()
        .to_string();
    let expected_hash = args
        .expected_hash
        .or_else(|| std::env::var("EGUARD_EXPECTED_HASH").ok())
        .or(embedded.expected_hash.clone())
        .unwrap_or_default()
        .trim()
        .to_string();

    if server_url.is_empty() {
        bail!("missing installer server_url configuration")
    }
    if enrollment_token.is_empty() {
        bail!("missing installer enrollment_token configuration")
    }

    let script_url = format!("{}/install.ps1", server_url.trim_end_matches('/'));
    let script_path = env::temp_dir().join("eguard-install-bootstrap.ps1");
    download_install_script(&script_url, &script_path)?;

    let mut cmd = Command::new("powershell.exe");
    cmd.env("EGUARD_WINDOWS_INSTALL_MODE", "msi");
    if let Some(profile_id) = embedded
        .profile_id
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        cmd.env("EGUARD_SETUP_PROFILE_ID", profile_id);
    }
    if let Some(profile_name) = embedded
        .profile_name
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        cmd.env("EGUARD_SETUP_PROFILE_NAME", profile_name);
    }
    if let Some(env_overrides) = embedded.env_overrides.as_ref() {
        for (key, value) in env_overrides {
            let trimmed_key = key.trim();
            if !trimmed_key.starts_with("EGUARD_") || trimmed_key.is_empty() {
                continue;
            }
            cmd.env(trimmed_key, value);
        }
    }
    cmd.creation_flags(CREATE_NO_WINDOW)
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-WindowStyle")
        .arg("Hidden")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(&script_path)
        .arg("-ServerUrl")
        .arg(&server_url)
        .arg("-EnrollmentToken")
        .arg(&enrollment_token);

    if !expected_hash.is_empty() {
        cmd.arg("-ExpectedHash").arg(&expected_hash);
    }
    if args.allow_insecure_http {
        cmd.arg("-AllowInsecureHttp");
    }
    if args.allow_unsigned_msi {
        cmd.arg("-AllowUnsignedMsi");
    }
    if args.keep_bootstrap {
        cmd.arg("-KeepBootstrap");
    }

    let status = cmd.status().context("launch install.ps1")?;
    let _ = fs::remove_file(&script_path);
    if !status.success() {
        bail!("installer bootstrap failed with exit status {status}")
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn download_install_script(script_url: &str, destination: &std::path::Path) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;
    let response = client
        .get(script_url)
        .send()
        .with_context(|| format!("download install script from {script_url}"))?
        .error_for_status()
        .with_context(|| format!("install script request failed for {script_url}"))?;
    let body = response
        .bytes()
        .context("read install script response body")?;
    std::fs::write(destination, &body)
        .with_context(|| format!("write install script to {}", destination.display()))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn read_embedded_config(exe_path: &std::path::Path) -> Result<EmbeddedConfig> {
    let raw = std::fs::read(exe_path)
        .with_context(|| format!("read embedded setup config from {}", exe_path.display()))?;
    let marker = EMBEDDED_CONFIG_MARKER.as_bytes();
    let Some(offset) = raw
        .windows(marker.len())
        .rposition(|window| window == marker)
    else {
        return Ok(EmbeddedConfig::default());
    };
    let payload = &raw[offset + marker.len()..];
    if payload.is_empty() {
        return Ok(EmbeddedConfig::default());
    }
    let decoded = BASE64_STANDARD
        .decode(payload)
        .context("decode embedded setup config payload")?;
    let config = serde_json::from_slice::<EmbeddedConfig>(&decoded)
        .context("parse embedded setup config payload")?;
    Ok(config)
}
