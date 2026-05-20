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
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(target_os = "windows")]
const INSTALLER_PROGRESS_UI_SCRIPT: &str = r#"
param(
    [Parameter(Mandatory = $true)]
    [string]$StatusFile
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Installing eGuard'
$form.Size = New-Object System.Drawing.Size(460, 175)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Location = New-Object System.Drawing.Point(18, 18)
$titleLabel.Size = New-Object System.Drawing.Size(410, 22)
$titleLabel.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$titleLabel.Text = 'Installing eGuard...'
$form.Controls.Add($titleLabel)

$detailLabel = New-Object System.Windows.Forms.Label
$detailLabel.Location = New-Object System.Drawing.Point(18, 46)
$detailLabel.Size = New-Object System.Drawing.Size(410, 32)
$detailLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$detailLabel.Text = 'Preparing installer...'
$form.Controls.Add($detailLabel)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(18, 86)
$progressBar.Size = New-Object System.Drawing.Size(410, 22)
$progressBar.Minimum = 0
$progressBar.Maximum = 100
$progressBar.Value = 5
$form.Controls.Add($progressBar)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(18, 116)
$statusLabel.Size = New-Object System.Drawing.Size(410, 20)
$statusLabel.Font = New-Object System.Drawing.Font('Segoe UI', 8)
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(85, 85, 85)
$statusLabel.Text = 'Please wait while eGuard is being installed.'
$form.Controls.Add($statusLabel)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 350
$closeAfter = $null
$errorShown = $false

$timer.Add_Tick({
    if (-not (Test-Path $StatusFile)) {
        return
    }

    try {
        $raw = Get-Content -Path $StatusFile -TotalCount 1 -ErrorAction Stop
    } catch {
        return
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        return
    }

    $parts = $raw -split '\|', 3
    $state = if ($parts.Length -ge 1) { [string]$parts[0] } else { 'RUNNING' }
    $percent = 0
    if ($parts.Length -ge 2) {
        [void][int]::TryParse([string]$parts[1], [ref]$percent)
    }
    $message = if ($parts.Length -ge 3) { [string]$parts[2] } else { 'Installing eGuard...' }
    $percent = [Math]::Max(0, [Math]::Min(100, $percent))

    $detailLabel.Text = $message
    $progressBar.Value = $percent
    $statusLabel.Text = "Progress: $percent%"

    switch ($state.ToUpperInvariant()) {
        'DONE' {
            $titleLabel.Text = 'eGuard installed'
            $statusLabel.Text = 'Installation complete.'
            if (-not $closeAfter) {
                $closeAfter = (Get-Date).AddSeconds(1.5)
            }
            if ((Get-Date) -ge $closeAfter) {
                $timer.Stop()
                $form.Close()
            }
        }
        'ERROR' {
            $titleLabel.Text = 'eGuard installation failed'
            $statusLabel.Text = 'Please review the error and try again.'
            $detailLabel.ForeColor = [System.Drawing.Color]::Firebrick
            if (-not $errorShown) {
                $errorShown = $true
                [System.Windows.Forms.MessageBox]::Show($message, 'eGuard Setup', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            }
        }
        default {
            $titleLabel.Text = 'Installing eGuard...'
        }
    }
})

$form.Add_Shown({ $timer.Start() })
[void]$form.ShowDialog()
"#;

#[cfg(target_os = "windows")]
#[derive(Clone, Debug)]
struct SetupProgress {
    state: &'static str,
    percent: u8,
    message: String,
}

#[cfg(target_os = "windows")]
impl SetupProgress {
    fn running(percent: u8, message: impl Into<String>) -> Self {
        Self {
            state: "RUNNING",
            percent,
            message: message.into(),
        }
    }

    fn done(message: impl Into<String>) -> Self {
        Self {
            state: "DONE",
            percent: 100,
            message: message.into(),
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            state: "ERROR",
            percent: 100,
            message: message.into(),
        }
    }
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
    use std::thread;
    use std::time::Duration;

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
    let script_path = unique_temp_path("eguard-install-bootstrap", "ps1");
    let status_path = unique_temp_path("eguard-install-status", "txt");
    let ui_script_path = unique_temp_path("eguard-install-progress-ui", "ps1");

    write_progress_ui_script(&ui_script_path)?;
    write_setup_status(&status_path, &SetupProgress::running(5, "Preparing installer..."));
    let _progress_ui = launch_progress_ui(&ui_script_path, &status_path);

    write_setup_status(
        &status_path,
        &SetupProgress::running(12, "Downloading secure installer helper..."),
    );
    download_install_script(&script_url, &script_path)?;

    let mut cmd = Command::new("powershell.exe");
    cmd.env("EGUARD_WINDOWS_INSTALL_MODE", "msi");
    cmd.env("EGUARD_SETUP_STATUS_FILE", &status_path);
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

    write_setup_status(
        &status_path,
        &SetupProgress::running(20, "Starting eGuard installation..."),
    );
    let status = cmd.status().context("launch install.ps1")?;
    let _ = fs::remove_file(&script_path);

    if status.success() {
        write_setup_status(
            &status_path,
            &SetupProgress::done("Installation complete. Launching eGuard..."),
        );
        thread::sleep(Duration::from_millis(1800));
        let _ = fs::remove_file(&status_path);
        let _ = fs::remove_file(&ui_script_path);
        return Ok(());
    }

    write_setup_status(
        &status_path,
        &SetupProgress::error(format!(
            "The installer exited with status {status}. Please try again or contact your administrator."
        )),
    );
    thread::sleep(Duration::from_millis(300));
    bail!("installer bootstrap failed with exit status {status}")
}

#[cfg(target_os = "windows")]
fn write_setup_status(path: &std::path::Path, progress: &SetupProgress) {
    let sanitized = progress
        .message
        .replace(['\r', '\n', '|'], " ")
        .trim()
        .to_string();
    let line = format!("{}|{}|{}", progress.state, progress.percent, sanitized);
    let _ = std::fs::write(path, line);
}

#[cfg(target_os = "windows")]
fn write_progress_ui_script(destination: &std::path::Path) -> Result<()> {
    std::fs::write(destination, INSTALLER_PROGRESS_UI_SCRIPT)
        .with_context(|| format!("write progress UI script to {}", destination.display()))
}

#[cfg(target_os = "windows")]
fn launch_progress_ui(
    script_path: &std::path::Path,
    status_path: &std::path::Path,
) -> Result<std::process::Child> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    Command::new("powershell.exe")
        .creation_flags(CREATE_NO_WINDOW)
        .arg("-STA")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-WindowStyle")
        .arg("Hidden")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(script_path)
        .arg("-StatusFile")
        .arg(status_path)
        .spawn()
        .context("launch installer progress UI")
}

#[cfg(target_os = "windows")]
fn unique_temp_path(prefix: &str, extension: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "{}-{}-{}.{}",
        prefix,
        std::process::id(),
        timestamp,
        extension.trim_start_matches('.')
    ))
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
