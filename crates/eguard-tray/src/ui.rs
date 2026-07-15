#![cfg(target_os = "windows")]

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use tracing::{error, info};
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::WindowBuilder;
use wry::{WebView, WebViewBuilder};

use crate::launcher::launch_bookmark;
use crate::state::{
    bookmark_cache_path, clear_launch_request_entry, command_queue_path, launch_request_state_path,
    pam_launch_state_path, session_state_path, tray_heartbeat_path, upsert_launch_request_entry,
    BookmarkEntry, BookmarkState, LaunchRequestEntry, LaunchRequestState, PamLaunchState,
    SessionEntry, SessionState, TrayCommand, TrayCommandQueue,
};

pub fn open_management_window() -> Result<()> {
    let event_loop = EventLoopBuilder::<String>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let window = WindowBuilder::new()
        .with_title("eGuard ZTNA Manager")
        .with_inner_size(tao::dpi::LogicalSize::new(1040.0, 720.0))
        .build(&event_loop)
        .context("create ZTNA manager window")?;

    let webview = WebViewBuilder::new()
        .with_html(manager_html())
        .with_ipc_handler(move |request| {
            let _ = proxy.send_event(request.body().clone());
        })
        .build(&window)
        .context("create ZTNA manager webview")?;

    info!("ZTNA manager window opened");
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::WaitUntil(std::time::Instant::now() + Duration::from_secs(3));
        match event {
            Event::NewEvents(StartCause::Init)
            | Event::NewEvents(StartCause::ResumeTimeReached { .. }) => push_state_to_webview(&webview),
            Event::UserEvent(message) => {
                if let Err(err) = handle_ipc(message) {
                    error!(error = %err, "ZTNA manager IPC failed");
                }
                push_state_to_webview(&webview);
            }
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });
}

fn handle_ipc(message: String) -> Result<()> {
    let request: UiRequest = serde_json::from_str(&message).context("parse UI request")?;
    match request {
        UiRequest::Refresh => {}
        UiRequest::OpenApp { app_id } => queue_open_app(&app_id)?,
        UiRequest::RetryApp { app_id } => retry_open_app(&app_id)?,
        UiRequest::Disconnect { session_id } => queue_command(TrayCommand::Disconnect { session_id })?,
        UiRequest::DisconnectAll => queue_command(TrayCommand::DisconnectAll)?,
    }
    Ok(())
}

fn push_state_to_webview(webview: &WebView) {
    let js = format!("window.__EGUARD_SET_STATE({});", json_for_script(&load_ui_state()));
    if let Err(err) = webview.evaluate_script(&js) {
        error!(error = %err, "refresh ZTNA manager state failed");
    }
}

fn queue_open_app(app_id: &str) -> Result<()> {
    let bookmarks = BookmarkState::load_default()?;
    let bookmark = bookmarks
        .bookmarks
        .iter()
        .find(|bookmark| bookmark.app_id == app_id)
        .with_context(|| format!("find bookmark {app_id}"))?;
    let target = bookmark
        .target_host
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(app_id);
    let _ = upsert_launch_request_entry(LaunchRequestEntry::connecting(app_id, target, None));
    queue_command(TrayCommand::OpenApp {
        app_id: app_id.to_string(),
        forward_host: bookmark.target_host.clone(),
        forward_port: bookmark.target_port.map(|port| port as u16),
    })?;
    match launch_bookmark(bookmark) {
        Ok(()) => Ok(()),
        Err(err) if err.to_string().to_ascii_lowercase().contains("pending approval") => Ok(()),
        Err(err) => Err(err),
    }
}

fn retry_open_app(app_id: &str) -> Result<()> {
    let _ = clear_launch_request_entry(app_id);
    queue_open_app(app_id)
}

fn queue_command(command: TrayCommand) -> Result<()> {
    let mut queue = TrayCommandQueue::load_default()?;
    queue.push(command);
    queue.save_default()
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum UiRequest {
    Refresh,
    OpenApp { app_id: String },
    RetryApp { app_id: String },
    Disconnect { session_id: String },
    DisconnectAll,
}

#[derive(Debug, Serialize)]
struct UiState {
    status: String,
    status_label: String,
    loaded_at_unix: i64,
    degraded: bool,
    errors: Vec<String>,
    diagnostics: Vec<DiagnosticRow>,
    bookmarks: Vec<BookmarkEntry>,
    sessions: Vec<SessionEntry>,
    pending_requests: Vec<LaunchRequestEntry>,
    command_queue_depth: usize,
    logs: Vec<LogFile>,
    device: DeviceInfo,
}

#[derive(Debug, Serialize)]
struct DiagnosticRow {
    name: String,
    path: String,
    ok: bool,
    age_seconds: Option<u64>,
    detail: String,
}

#[derive(Debug, Serialize)]
struct LogFile {
    name: String,
    path: String,
    ok: bool,
    content: String,
}

#[derive(Debug, Serialize)]
struct DeviceInfo {
    hostname: String,
    signed_in_user: String,
    operating_system: String,
    architecture: String,
    agent_id: String,
    agent_mode: String,
    server_address: String,
    agent_service: String,
    agent_config_path: String,
    agent_binary_path: String,
    agent_binary_modified: String,
    tray_version: String,
    tray_process_id: u32,
    posture_summary: String,
    posture_checks: Vec<DevicePostureCheck>,
    applied_policy: Vec<DevicePolicySetting>,
}

#[derive(Debug, Serialize)]
struct DevicePostureCheck {
    name: String,
    status: String,
    detail: String,
}

#[derive(Debug, Serialize)]
struct DevicePolicySetting {
    name: String,
    value: String,
    source: String,
}

fn load_ui_state() -> UiState {
    let now = now_unix();
    let mut errors = Vec::new();
    let bookmarks = load_or_default::<BookmarkState>("bookmarks", &mut errors).bookmarks;
    let mut sessions = load_or_default::<SessionState>("sessions", &mut errors).sessions;
    add_pam_launch_sessions(&mut sessions, &bookmarks, &mut errors);
    let pending_requests = load_or_default::<LaunchRequestState>("launch requests", &mut errors)
        .active_entries()
        .into_iter()
        .filter(|entry| !sessions.iter().any(|session| session.app_id == entry.app_id))
        .filter(|entry| !is_stale_connecting_request(entry, now))
        .cloned()
        .collect::<Vec<_>>();
    let command_queue_depth = load_or_default::<TrayCommandQueue>("command queue", &mut errors)
        .commands
        .len();
    let diagnostics = build_diagnostics();
    let stale = diagnostics.iter().any(|diag| {
        diag.name == "Sessions" && diag.age_seconds.map(|age| age > 300).unwrap_or(false)
    });
    let tray_heartbeat_stale = diagnostics.iter().any(|diag| {
        diag.name == "Tray heartbeat" && diag.age_seconds.map(|age| age > 20).unwrap_or(true)
    });
    if stale {
        errors.push("Agent ZTNA session state looks stale: sessions have not updated for more than 5 minutes".to_string());
    }
    if tray_heartbeat_stale {
        errors.push("Tray heartbeat looks stale; tray watchdog may restart it soon".to_string());
    }

    let waiting = pending_requests
        .iter()
        .any(|entry| entry.status.eq_ignore_ascii_case("waiting_for_approval"));
    let connecting = pending_requests.iter().any(|entry| {
        entry.status.eq_ignore_ascii_case("connecting")
            || entry.status.eq_ignore_ascii_case("connecting_bastion")
    });
    let (status, status_label) = if !errors.is_empty() && bookmarks.is_empty() && sessions.is_empty() {
        ("error", "State load failed")
    } else if !errors.is_empty() || stale {
        ("degraded", "Degraded / stale state")
    } else if waiting {
        ("waiting", "Waiting for approval")
    } else if connecting {
        ("connecting", "Connecting")
    } else if !sessions.is_empty() {
        ("connected", "Connected")
    } else {
        ("not_connected", "Not connected")
    };

    UiState {
        status: status.to_string(),
        status_label: status_label.to_string(),
        loaded_at_unix: now,
        degraded: !errors.is_empty() || stale,
        errors,
        diagnostics,
        bookmarks,
        sessions,
        pending_requests,
        command_queue_depth,
        logs: load_logs(),
        device: load_device_info(),
    }
}

fn add_pam_launch_sessions(
    sessions: &mut Vec<SessionEntry>,
    bookmarks: &[BookmarkEntry],
    errors: &mut Vec<String>,
) {
    let pam_launches = load_or_default::<PamLaunchState>("PAM launches", errors).entries;
    for entry in pam_launches {
        if sessions.iter().any(|session| session.app_id == entry.app_id) {
            continue;
        }
        let bookmark = bookmarks.iter().find(|bookmark| bookmark.app_id == entry.app_id);
        sessions.push(SessionEntry {
            session_id: format!("pam-{}", entry.checkout_id),
            app_id: entry.app_id.clone(),
            app_name: bookmark
                .map(|bookmark| bookmark.name.clone())
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| entry.app_id.clone()),
            transport: format!("pam-{}", entry.launcher_kind.trim().to_ascii_lowercase()),
            status: "active".to_string(),
            started_at: Some(entry.started_at_unix),
            last_activity_at: Some(entry.started_at_unix),
            last_outcome: Some(match entry.process_id {
                Some(pid) => format!("PAM launch active (PID {pid})"),
                None => "PAM launch active".to_string(),
            }),
            local_url: None,
            bytes_tx: None,
            bytes_rx: None,
            active_connections: Some(1),
            tunnel_latency_ms: None,
        });
    }
}

fn is_stale_connecting_request(entry: &LaunchRequestEntry, now: i64) -> bool {
    let status = entry.status.trim().to_ascii_lowercase();
    if status == "waiting_for_approval" {
        return now.saturating_sub(entry.updated_at_unix) > 30 * 60;
    }
    (status == "connecting" || status == "connecting_bastion")
        && now.saturating_sub(entry.updated_at_unix) > 45
}

fn load_or_default<T>(label: &str, errors: &mut Vec<String>) -> T
where
    T: serde::de::DeserializeOwned + Default,
{
    let path = match label {
        "bookmarks" => bookmark_cache_path(),
        "sessions" => session_state_path(),
        "launch requests" => launch_request_state_path(),
        "PAM launches" => pam_launch_state_path(),
        "command queue" => command_queue_path(),
        _ => unreachable!(),
    };
    match path.and_then(|path| {
        if !path.exists() {
            return Ok(T::default());
        }
        let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
    }) {
        Ok(value) => value,
        Err(err) => {
            errors.push(format!("Failed to load {label}: {err}"));
            T::default()
        }
    }
}

fn build_diagnostics() -> Vec<DiagnosticRow> {
    [
        ("Bookmarks", bookmark_cache_path()),
        ("Sessions", session_state_path()),
        ("Launch requests", launch_request_state_path()),
        ("PAM launches", pam_launch_state_path()),
        ("Command queue", command_queue_path()),
        ("Tray heartbeat", tray_heartbeat_path()),
    ]
    .into_iter()
    .map(|(name, path_result)| match path_result {
        Ok(path) => {
            let metadata = fs::metadata(&path).ok();
            let age_seconds = metadata
                .as_ref()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|modified| SystemTime::now().duration_since(modified).ok())
                .map(|age| age.as_secs());
            DiagnosticRow {
                name: name.to_string(),
                path: path.display().to_string(),
                ok: path.exists(),
                age_seconds,
                detail: if path.exists() { "present" } else { "missing" }.to_string(),
            }
        }
        Err(err) => DiagnosticRow {
            name: name.to_string(),
            path: String::new(),
            ok: false,
            age_seconds: None,
            detail: err.to_string(),
        },
    })
    .collect()
}

fn load_device_info() -> DeviceInfo {
    let config_path = Path::new(r"C:\ProgramData\eGuard\agent.conf");
    let agent_binary = Path::new(r"C:\Program Files\eGuard\eguard-agent.exe");
    let agent_binary_modified = fs::metadata(agent_binary)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_secs().to_string())
        .unwrap_or_default();
    let agent_service = windows_service_state("eGuardAgent");
    let wireguard_service = windows_service_state("WireGuardTunnel$wg-pnup");
    let heartbeat_age = file_age_seconds(&tray_heartbeat_path().ok());
    let session_age = file_age_seconds(&session_state_path().ok());
    let ztna_enabled = read_agent_config_value(config_path, "ztna", "enabled").unwrap_or_default();
    let mut posture_checks = vec![
        posture_check("Agent service", agent_service == "RUNNING", &agent_service),
        posture_check("Tray responsiveness", heartbeat_age.map(|age| age <= 20).unwrap_or(false), &heartbeat_age.map(|age| format!("Heartbeat {age}s ago")).unwrap_or_else(|| "Heartbeat missing".to_string())),
        posture_check("Agent configuration", config_path.exists(), if config_path.exists() { "Configuration present" } else { "Configuration missing" }),
        posture_check("ZTNA policy", ztna_enabled.eq_ignore_ascii_case("true"), if ztna_enabled.eq_ignore_ascii_case("true") { "ZTNA enabled" } else { "ZTNA disabled" }),
        posture_check("ZTNA state sync", session_age.map(|age| age <= 300).unwrap_or(false), &session_age.map(|age| format!("Session state updated {age}s ago")).unwrap_or_else(|| "Session state missing".to_string())),
        posture_check("WireGuard tunnel", wireguard_service == "RUNNING", &wireguard_service),
    ];
    let posture_summary = if posture_checks.iter().all(|check| check.status == "pass") {
        "All local posture checks passed"
    } else {
        "One or more local posture checks require attention"
    }.to_string();
    let policy = |name: &str, section: &str, key: &str| DevicePolicySetting {
        name: name.to_string(),
        value: read_agent_config_value(config_path, section, key).unwrap_or_else(|| "Not configured".to_string()),
        source: "Local applied agent.conf".to_string(),
    };
    let applied_policy = vec![
        policy("Agent mode", "agent", "mode"),
        policy("Device ownership", "inventory", "ownership"),
        policy("ZTNA enabled", "ztna", "enabled"),
        policy("ZTNA idle timeout", "ztna", "idle_timeout_secs"),
        policy("Policy refresh interval", "control_plane", "policy_refresh_interval_secs"),
        policy("Compliance check interval", "compliance", "check_interval_secs"),
        policy("Compliance auto-remediation", "compliance", "auto_remediate"),
        policy("Autonomous response", "response", "autonomous_response"),
        policy("Self-protection uninstall prevention", "self_protection", "prevent_uninstall"),
        policy("Scan files on create", "detection", "scan_on_create"),
        policy("Memory scanning", "detection", "memory_scan_enabled"),
        policy("Kernel integrity checks", "detection", "kernel_integrity_enabled"),
    ];
    DeviceInfo {
        hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string()),
        signed_in_user: std::env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string()),
        operating_system: windows_version(),
        architecture: std::env::consts::ARCH.to_string(),
        agent_id: read_agent_config_value(config_path, "agent", "id").unwrap_or_default(),
        agent_mode: read_agent_config_value(config_path, "agent", "mode").unwrap_or_default(),
        server_address: read_agent_config_value(config_path, "agent", "server_addr").unwrap_or_default(),
        agent_service,
        agent_config_path: config_path.display().to_string(),
        agent_binary_path: agent_binary.display().to_string(),
        agent_binary_modified,
        tray_version: env!("CARGO_PKG_VERSION").to_string(),
        tray_process_id: std::process::id(),
        posture_summary,
        posture_checks: std::mem::take(&mut posture_checks),
        applied_policy,
    }
}

fn posture_check(name: &str, passed: bool, detail: &str) -> DevicePostureCheck {
    DevicePostureCheck {
        name: name.to_string(),
        status: if passed { "pass" } else { "attention" }.to_string(),
        detail: detail.to_string(),
    }
}

fn file_age_seconds(path: &Option<std::path::PathBuf>) -> Option<u64> {
    path.as_ref()
        .and_then(|path| fs::metadata(path).ok())
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .map(|age| age.as_secs())
}

fn read_agent_config_value(path: &Path, section: &str, key: &str) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    let mut in_section = false;
    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_section = line[1..line.len() - 1].trim().eq_ignore_ascii_case(section);
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((candidate, value)) = line.split_once('=') else {
            continue;
        };
        if candidate.trim().eq_ignore_ascii_case(key) {
            return Some(value.trim().trim_matches(['"', '\'']).to_string());
        }
    }
    None
}

fn windows_version() -> String {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    std::process::Command::new("cmd.exe")
        .args(["/c", "ver"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Microsoft Windows".to_string())
}

fn windows_service_state(service_name: &str) -> String {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    std::process::Command::new("sc.exe")
        .args(["query", service_name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| {
            output.lines().find_map(|line| {
                let line = line.trim();
                if !line.starts_with("STATE") {
                    return None;
                }
                line.split_whitespace().last().map(str::to_string)
            })
        })
        .unwrap_or_else(|| "Unknown".to_string())
}

fn load_logs() -> Vec<LogFile> {
    [
        ("Tray Log", std::path::PathBuf::from(r"C:\ProgramData\eGuard\logs\tray.log")),
        ("Agent Log", std::path::PathBuf::from(r"C:\ProgramData\eGuard\logs\agent.log")),
    ]
    .into_iter()
    .map(|(name, path)| match tail_log_file(&path, 96 * 1024, 180) {
        Ok(content) => LogFile {
            name: name.to_string(),
            path: path.display().to_string(),
            ok: true,
            content,
        },
        Err(err) => LogFile {
            name: name.to_string(),
            path: path.display().to_string(),
            ok: false,
            content: format!("Failed to read log tail: {err}"),
        },
    })
    .collect()
}

fn tail_log_file(path: &std::path::Path, max_bytes: u64, max_lines: usize) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start))?;
    let mut raw = String::new();
    file.read_to_string(&mut raw)?;
    if start > 0 {
        if let Some((_, rest)) = raw.split_once('\n') {
            raw = rest.to_string();
        }
    }
    let lines = raw.lines().collect::<Vec<_>>();
    let start_line = lines.len().saturating_sub(max_lines);
    Ok(lines[start_line..].join("\n"))
}

fn json_for_script<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn manager_html() -> String {
    r#"<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline' data:; script-src 'unsafe-inline';">
<title>eGuard ZTNA Manager</title>
<style>
:root { font-family: Segoe UI, Arial, sans-serif; font-size:12px; color:#172033; background:#f5f7fb; }
html, body { margin:0; height:100%; overflow:hidden; }
body { display:flex; flex-direction:column; min-height:0; }
header { display:none; }
h1 { font-size:14px; margin:0; }
main { padding:10px 12px 18px; flex:1; min-height:0; overflow:hidden; display:flex; flex-direction:column; }
.tabs { display:flex; align-items:center; gap:6px; margin-bottom:10px; }
.tab-spacer { flex:1; }
.tabbtn { border:1px solid #c9d3e2; background:white; padding:6px 10px; border-radius:6px; cursor:pointer; font-size:11px; }
.tabbtn.active { background:#1769e0; border-color:#1769e0; color:white; }
.tab { display:none; }
.tab.active { display:flex; flex-direction:column; flex:1; min-height:0; overflow:hidden; }
.card { background:white; border:1px solid #dfe5ef; border-radius:8px; box-shadow:0 1px 2px rgba(16,33,63,.06); margin-bottom:8px; overflow:hidden; }
.card h2 { font-size:12px; margin:0; padding:7px 10px; border-bottom:1px solid #edf1f7; background:#fbfcff; }
.content { padding:8px 10px; }
.status { display:inline-flex; align-items:center; gap:6px; padding:4px 8px; border-radius:999px; font-weight:600; }
.status.connected { background:#e7f7ee; color:#08713b; }
.status.not_connected { background:#eef2f7; color:#526070; }
.status.waiting,.status.connecting { background:#fff7de; color:#946100; }
.status.degraded,.status.error { background:#fdecec; color:#b42318; }
.dot { width:9px; height:9px; border-radius:50%; background:currentColor; }
table { width:100%; border-collapse:collapse; font-size:12px; }
th,td { text-align:left; padding:6px 6px; border-bottom:1px solid #eef2f7; vertical-align:middle; }
th { color:#526070; font-weight:600; background:#fbfcff; }
tr.app-active { background:#eefaf2; }
tr.app-pending { background:#fff8df; }
tr.app-down { opacity:.62; }
.badge { display:inline-block; border-radius:999px; padding:2px 7px; font-size:11px; font-weight:600; }
.badge.active { background:#d9f3e3; color:#08713b; }
.badge.pending { background:#fff0bd; color:#946100; }
.badge.down { background:#eef2f7; color:#526070; }
.badge.failed { background:#fdecec; color:#b42318; }
button { border:1px solid #b9c6d8; background:#fff; color:#172033; border-radius:6px; padding:5px 9px; cursor:pointer; font-size:12px; }
button:hover { background:#f2f6fb; }
button.primary { background:#1769e0; color:white; border-color:#1769e0; }
button.danger { color:#b42318; border-color:#f2b8b5; }
button:disabled { opacity:.55; cursor:not-allowed; }
.muted { color:#687588; }
.errorbox { background:#fff2f2; color:#9b1c1c; border:1px solid #ffcaca; border-radius:8px; padding:10px 12px; margin-top:10px; }
pre { white-space:pre-wrap; word-break:break-word; background:#0f172a; color:#dbeafe; border-radius:8px; padding:10px; max-height:220px; overflow:auto; font-size:11px; margin:0 0 14px 0; }
.log-title { margin:12px 0 6px; font-weight:700; }
#logbox { padding-bottom:28px; }
#applications .card:last-child { flex:1; min-height:0; display:flex; flex-direction:column; margin-bottom:0; }
.app-manager { display:grid; grid-template-columns:300px 1fr; flex:1; min-height:0; overflow:hidden; }
.app-list { border-right:1px solid #dfe5ef; overflow-y:auto; overflow-x:hidden; background:#f8fafc; min-height:0; max-height:100%; overscroll-behavior:contain; padding-bottom:16px; }
.app-list-item { padding:8px 10px; border-bottom:1px solid #e8eef6; cursor:pointer; }
.app-list-item:hover { background:#eef5ff; }
.app-list-item.selected { background:#dbeafe; box-shadow:inset 4px 0 #1769e0; }
.app-list-item.active { background:#ecfdf3; }
.app-list-item.pending { background:#fff8df; }
.app-list-item.failed { background:#fff1f0; }
.app-list-item.down { opacity:.62; }
.app-detail { padding:12px; overflow:hidden; background:white; }
.detail-title { display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:8px; }
.detail-title h2 { padding:0; border:0; background:transparent; font-size:17px; }
.detail-grid { display:grid; grid-template-columns:130px 1fr; gap:6px 10px; margin-top:10px; }
.detail-key { color:#687588; }
.device-card { overflow:auto; }
.device-grid { display:grid; grid-template-columns:180px minmax(0,1fr); gap:0; }
.device-grid > div { padding:8px 10px; border-bottom:1px solid #eef2f7; }
.device-grid .detail-key { background:#fbfcff; font-weight:600; }
.device-section { padding:10px; border-top:1px solid #e6ebf3; }
.device-section h3 { margin:0 0 8px; font-size:12px; }
.posture-summary { padding:8px 10px; border-radius:6px; margin-bottom:8px; background:#eef2f7; }
.check-pass { color:#08713b; font-weight:700; }
.check-attention { color:#b42318; font-weight:700; }
@media(max-width: 850px) { .app-manager { grid-template-columns:1fr; grid-template-rows:minmax(120px, min(42vh, 280px)) minmax(120px, 1fr); } .app-list { max-height:none; border-right:0; border-bottom:1px solid #dfe5ef; } }
</style>
</head>
<body>
<header></header>
<main>
  <div class="tabs">
    <button class="tabbtn active" onclick="showTab('applications', this)">Applications</button>
    <button class="tabbtn" onclick="showTab('device', this)">This Device</button>
    <button class="tabbtn" onclick="showTab('diagnostic', this)">Diagnostic</button>
    <button class="tabbtn" onclick="showTab('logs', this)">Logs</button>
    <span class="tab-spacer"></span>
    <button class="tabbtn" onclick="send({type:'refresh'})">Refresh</button>
  </div>

  <section id="applications" class="tab active">
    <section class="card"><h2>Status</h2><div class="content" id="status">Loading ZTNA state...</div></section>
    <section class="card"><h2>Applications</h2><div class="app-manager"><div class="app-list" id="apps">Loading...</div><div class="app-detail" id="appdetail">Select an application...</div></div></section>
  </section>

  <section id="device" class="tab">
    <section class="card device-card"><h2>This Device</h2><div id="deviceinfo">Loading...</div></section>
  </section>

  <section id="diagnostic" class="tab">
    <section class="card"><h2>Diagnostic</h2><div class="content" id="diag">Loading...</div></section>
  </section>

  <section id="logs" class="tab">
    <section class="card"><h2>Logs</h2><div class="content"><label><input id="logAutoRefresh" type="checkbox" checked> Auto refresh</label> <button onclick="copyLogs()">Copy logs</button></div><div class="content" id="logbox">Loading...</div></section>
    <div style="height:24px"></div>
  </section>
  <div style="height:16px"></div>
</main>
<script>
const optimistic = new Map();
const retryUntil = new Map();
function esc(v){ return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function send(msg){ if(msg.type==='open_app') optimistic.set(msg.app_id, Date.now()); window.ipc.postMessage(JSON.stringify(msg)); }
function connectApp(id){ send({type:'open_app', app_id:id}); }
function copyLogs(){ const text = Array.from(document.querySelectorAll('#logbox pre')).map(p => p.innerText).join('\n\n'); navigator.clipboard.writeText(text).catch(() => {}); }
function retryApp(id){ const now=Date.now(); const until=retryUntil.get(id)||0; if(now < until) return; optimistic.delete(id); retryUntil.set(id, now + 10000); send({type:'retry_app', app_id:id}); }
function disconnectSession(id){ send({type:'disconnect', session_id:id}); }
function age(s){ return s == null ? 'n/a' : (s < 60 ? s + 's ago' : Math.round(s/60) + 'm ago'); }
function table(rows, empty){ return rows.length ? '<table>'+rows.join('')+'</table>' : '<div class="muted">'+empty+'</div>'; }
function showTab(id, btn){ document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active')); document.querySelectorAll('.tabbtn').forEach(x=>x.classList.remove('active')); document.getElementById(id).classList.add('active'); btn.classList.add('active'); }
function selectApp(id){ window.__selectedAppId=id; window.__EGUARD_SET_STATE(window.__lastState); }
function statusTextFor(b, sess, pending){
  const opt = optimistic.get(b.app_id);
  if(sess){ optimistic.delete(b.app_id); return ['active','Active']; }
  if(pending){
    const ps = String(pending.status||'').toLowerCase();
    if(ps === 'waiting_for_approval') return ['pending','Pending approval'];
    if(ps === 'connecting' || ps === 'connecting_bastion') return ['pending','Connecting'];
    return ['failed', pending.message || 'Failed'];
  }
  if(opt && Date.now() - opt < 15000){ return ['pending','Queued']; }
  if(opt) optimistic.delete(b.app_id);
  if(String(b.health_status||'').toLowerCase()==='down') return ['down','Down'];
  return ['','Ready'];
}
function renderDetail(b, sess, pending, st){
  const retryLeft = Math.max(0, Math.ceil(((retryUntil.get(b.app_id)||0) - Date.now()) / 1000));
  const action = sess
    ? '<button class="danger" onclick="disconnectSession(this.dataset.session)" data-session="'+esc(sess.session_id)+'">Disconnect</button>'
    : (pending ? '<button '+(retryLeft>0?'disabled ':'')+'onclick="retryApp(this.dataset.appid)" data-appid="'+esc(b.app_id)+'">'+(retryLeft>0?'Retry in '+retryLeft+'s':'Retry')+'</button>' : '<button class="primary" '+(st[0]==='pending'?'disabled ':'')+'onclick="connectApp(this.dataset.appid)" data-appid="'+esc(b.app_id)+'">'+(st[0]==='pending'?'Queued':'Connect')+'</button>');
  return '<div class="detail-title"><h2>'+esc(b.name)+'</h2><span class="badge '+esc(st[0])+'">'+esc(st[1])+'</span></div>'+
    '<div>'+action+'</div><div class="detail-grid">'+
    '<div class="detail-key">Application ID</div><div>'+esc(b.app_id)+'</div>'+
    '<div class="detail-key">Type</div><div>'+esc(b.app_type)+'</div>'+
    '<div class="detail-key">Health</div><div>'+esc(b.health_status)+'</div>'+
    '<div class="detail-key">Target</div><div>'+esc(b.target_host||'')+':'+esc(b.target_port||'')+'</div>'+
    '<div class="detail-key">Description</div><div>'+esc(b.description||'-')+'</div>'+
    (pending?'<div class="detail-key">Last request</div><div><span class="badge '+(st[0]==='failed'?'failed':'pending')+'">'+esc(pending.status)+'</span> · '+esc(pending.message)+'<br><span class="muted">'+(st[0]==='failed'?'The request ended. Retry starts a new request.':'Use Retry if backend approval is stuck.')+'</span></div>':'')+
    (sess?'<div class="detail-key">Session</div><div>'+esc(sess.session_id)+'<br>'+esc(sess.transport)+' · '+esc(sess.status)+'<br>RX '+esc(sess.bytes_rx||0)+' / TX '+esc(sess.bytes_tx||0)+'</div>':'')+
    '</div>';
}
window.__EGUARD_SET_STATE = function(s){
  window.__lastState = s;
  if(!s){ document.getElementById('status').innerHTML='<div class="errorbox">Failed to load state.</div>'; return; }
  document.getElementById('status').innerHTML = '<span class="status '+esc(s.status)+'"><span class="dot"></span>'+esc(s.status_label)+'</span>'+
    '<div class="muted" style="margin-top:8px">Command queue: '+s.command_queue_depth+' · Last refresh: '+new Date(s.loaded_at_unix*1000).toLocaleString()+'</div>'+
    (s.errors && s.errors.length ? '<div class="errorbox">'+s.errors.map(esc).join('<br>')+'</div>' : '');

  const pendingByApp = new Map((s.pending_requests||[]).map(r => [r.app_id, r]));
  const sessionByApp = new Map((s.sessions||[]).map(x => [x.app_id, x]));
  if(!window.__selectedAppId && (s.bookmarks||[]).length) window.__selectedAppId = s.bookmarks[0].app_id;
  const selectedExists = (s.bookmarks||[]).some(b => b.app_id === window.__selectedAppId);
  if(!selectedExists && (s.bookmarks||[]).length) window.__selectedAppId = s.bookmarks[0].app_id;
  document.getElementById('apps').innerHTML = (s.bookmarks||[]).map(b => {
    const pending = pendingByApp.get(b.app_id); const sess = sessionByApp.get(b.app_id); const st = statusTextFor(b, sess, pending);
    const cls = (b.app_id===window.__selectedAppId?' selected':'') + (st[0] ? ' '+st[0] : '');
    return '<div class="app-list-item'+cls+'" data-appid="'+esc(b.app_id)+'" onclick="selectApp(this.dataset.appid)"><b>'+esc(b.name)+'</b><div class="muted">'+esc(b.app_type)+' · '+esc(b.target_host||'')+':'+esc(b.target_port||'')+'</div><div style="margin-top:6px"><span class="badge '+esc(st[0])+'">'+esc(st[1])+'</span></div></div>';
  }).join('') || '<div class="content muted">No applications.</div>';
  const b = (s.bookmarks||[]).find(x => x.app_id === window.__selectedAppId);
  if(!b){ document.getElementById('appdetail').innerHTML = '<div class="muted">No application selected.</div>'; }
  else {
    const pending = pendingByApp.get(b.app_id); const sess = sessionByApp.get(b.app_id); const st = statusTextFor(b, sess, pending);
    document.getElementById('appdetail').innerHTML = renderDetail(b, sess, pending, st);
  }

  const d=s.device||{};
  const deviceRows=[['Computer name',d.hostname],['Signed-in user',d.signed_in_user],['Operating system',d.operating_system],['Architecture',d.architecture],['Agent ID',d.agent_id],['Agent mode',d.agent_mode],['Agent service',d.agent_service],['Management server',d.server_address],['Agent binary',d.agent_binary_path],['Agent binary modified',d.agent_binary_modified ? new Date(Number(d.agent_binary_modified)*1000).toLocaleString() : 'Unknown'],['Agent configuration',d.agent_config_path],['ZTNA Manager version',d.tray_version],['Tray process ID',d.tray_process_id]];
  const postureRows=(d.posture_checks||[]).map(c=>'<tr><td><b>'+esc(c.name)+'</b></td><td class="check-'+esc(c.status)+'">'+(c.status==='pass'?'PASS':'ATTENTION')+'</td><td>'+esc(c.detail)+'</td></tr>');
  const policyRows=(d.applied_policy||[]).map(p=>'<tr><td><b>'+esc(p.name)+'</b></td><td>'+esc(p.value)+'</td><td class="muted">'+esc(p.source)+'</td></tr>');
  document.getElementById('deviceinfo').innerHTML='<div class="device-grid">'+deviceRows.map(r=>'<div class="detail-key">'+esc(r[0])+'</div><div>'+esc(r[1]||'Unknown')+'</div>').join('')+'</div><div class="device-section"><h3>Agent Posture</h3><div class="posture-summary">'+esc(d.posture_summary||'Local posture unavailable')+'</div>'+table(postureRows,'No local posture checks available.')+'<div class="muted" style="margin-top:8px">These are local health checks, not a server compliance attestation.</div></div><div class="device-section"><h3>Applied Policy</h3>'+table(policyRows,'No applied policy settings available.')+'</div>';
  document.getElementById('diag').innerHTML = '<h3>Launch Requests</h3>' + table((s.pending_requests||[]).map(r => '<tr class="'+((String(r.status).toLowerCase()==='launch_failed')?'':'app-pending')+'"><td><b>'+esc(r.app_id)+'</b><div class="muted">'+esc(r.target)+'</div></td><td>'+esc(r.status)+'</td><td>'+esc(r.message)+'</td></tr>'), 'No launch requests.') + '<h3>State Files</h3>' + table((s.diagnostics||[]).map(d => '<tr><td><b>'+esc(d.name)+'</b><div class="muted">'+esc(d.path)+'</div></td><td>'+ (d.ok ? 'OK' : 'Missing/Error') +'</td><td>'+age(d.age_seconds)+'</td><td>'+esc(d.detail)+'</td></tr>'), 'No diagnostics.');
  const oldLogScroll = Array.from(document.querySelectorAll('#logbox pre')).map(p => p.scrollTop);
  document.getElementById('logbox').innerHTML = (s.logs||[]).map((l,i) => '<div class="log-title">'+esc(l.name)+' <span class="muted">'+esc(l.path)+'</span></div><pre data-logidx="'+i+'">'+esc(l.content)+'</pre>').join('');
  Array.from(document.querySelectorAll('#logbox pre')).forEach((p,i) => { if(oldLogScroll[i] != null) p.scrollTop = oldLogScroll[i]; });
}
window.__EGUARD_SET_STATE(null);
setInterval(() => { const auto = document.getElementById('logAutoRefresh'); if(!auto || auto.checked || document.getElementById('logs').classList.contains('active') === false) send({type:'refresh'}); }, 3000);
setInterval(() => { if(window.__lastState) window.__EGUARD_SET_STATE(window.__lastState); }, 1000);
send({type:'refresh'});
</script>
</body>
</html>"#
        .to_string()
}
