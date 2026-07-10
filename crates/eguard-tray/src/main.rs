#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;
mod launcher;
mod protocol;
mod state;
mod tray;
#[cfg(target_os = "windows")]
mod ui;

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Once;
use std::time::Duration;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use tracing::{error, info};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use app::open_admin_ui;
use launcher::{
    cleanup_all_pam_launches, cleanup_pam_launch, launch_bookmark,
    launch_launch_request_with_session_fallback, reconcile_pam_launches_on_startup,
};
use protocol::LaunchRequest;
use state::{
    bookmark_cache_path, command_queue_path, launch_request_state_path, pam_launch_state_path,
    session_state_path, snapshot_bookmark_cache, snapshot_session_cache, tray_heartbeat_path,
    tray_shutdown_marker_path, upsert_launch_request_entry, wait_for_bookmark_cache_update,
    wait_for_session_cache_update, BookmarkState, LaunchRequestEntry, SessionState,
    TrayCommandQueue,
};

#[derive(Parser, Debug)]
#[command(name = "Eguard ZTNA", about = "Eguard ZTNA tray helper")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    RegisterProtocol,
    HandleUrl { url: String },
    List,
    Open { app_id: String },
    ListSessions,
    Disconnect { session_id: String },
    DisconnectAll,
    DisableTransport,
    EnableTransport,
    Refresh,
    OpenAdminUi,
    Manage,
    Paths,
    CleanupPamLaunch { checkout_id: i64 },
    CleanupAllPamLaunches,
    Tray,
    Watchdog { parent_pid: u32 },
}

#[tokio::main]
async fn main() {
    if let Err(err) = real_main().await {
        error!(error = %err, "eguard-tray failed");
        eprintln!("eguard-tray: {err}");
        std::process::exit(1);
    }
}

async fn real_main() -> Result<()> {
    init_logging();
    #[cfg(target_os = "windows")]
    let _ = ensure_start_menu_shortcut();
    let cli = Cli::parse();

    match cli.command.unwrap_or(Command::Tray) {
        Command::RegisterProtocol => protocol::register_protocol_handler(current_exe_string()?),
        Command::HandleUrl { url } => {
            ensure_background_tray()?;
            let request = LaunchRequest::parse(&url)?;
            enqueue_command(state::TrayCommand::OpenApp {
                app_id: request.app_id.clone(),
                forward_host: Some(request.forward_host()),
                forward_port: request.forward_port(),
            })?;
            launch_launch_request_with_session_fallback(&request)
        }
        Command::List => list_bookmarks(),
        Command::Open { app_id } => open_bookmark(&app_id),
        Command::ListSessions => list_sessions(),
        Command::Disconnect { session_id } => {
            enqueue_command(state::TrayCommand::Disconnect { session_id })
        }
        Command::DisconnectAll => enqueue_command(state::TrayCommand::DisconnectAll),
        Command::DisableTransport => enqueue_command(state::TrayCommand::DisableTransport),
        Command::EnableTransport => enqueue_command(state::TrayCommand::EnableTransport),
        Command::Refresh => refresh_state(),
        Command::OpenAdminUi => open_admin_ui(),
        Command::Manage => open_management_ui(),
        Command::Paths => print_paths(),
        Command::CleanupPamLaunch { checkout_id } => cleanup_pam_launch(checkout_id),
        Command::CleanupAllPamLaunches => cleanup_all_pam_launches(),
        Command::Tray => {
            start_tray_watchdog_if_needed()?;
            let _ = std::fs::remove_file(tray_shutdown_marker_path()?);
            reconcile_pam_launches_on_startup()?;
            tray::run_windows_tray()
        }
        Command::Watchdog { parent_pid } => run_tray_watchdog(parent_pid),
    }
}

static TRACING_INIT: Once = Once::new();

fn init_logging() {
    TRACING_INIT.call_once(|| {
        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
            .expect("default tracing filter should be valid");

        if let Some(log_path) = configured_log_path() {
            if let Some(parent) = log_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            match OpenOptions::new().create(true).append(true).open(&log_path) {
                Ok(file) => {
                    let writer = std::sync::Mutex::new(file);
                    tracing_subscriber::fmt()
                        .with_env_filter(env_filter)
                        .with_ansi(false)
                        .with_target(false)
                        .with_writer(writer)
                        .init();
                    return;
                }
                Err(_) => {
                    // Fall back to stderr if the log file can't be opened.
                }
            }
        }

        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(false)
            .with_target(false)
            .init();
    });
}

fn configured_log_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("EGUARD_TRAY_LOG_PATH") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }

    #[cfg(target_os = "windows")]
    {
        return Some(PathBuf::from(r"C:\ProgramData\eGuard\logs\tray.log"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        return Some(PathBuf::from("/var/log/eguard-tray.log"));
    }

    #[allow(unreachable_code)]
    None
}

#[cfg(target_os = "windows")]
fn ensure_start_menu_shortcut() -> Result<()> {
    use std::path::PathBuf;
    use std::process::Command;

    let exe = std::env::current_exe().context("resolve current tray executable path")?;
    let programs_dir = PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs");
    std::fs::create_dir_all(&programs_dir)
        .with_context(|| format!("create start menu directory {}", programs_dir.display()))?;
    let shortcut_path = programs_dir.join("Eguard ZTNA.lnk");

    let ps_script = format!(
        "$WshShell = New-Object -ComObject WScript.Shell; \
         $Shortcut = $WshShell.CreateShortcut('{shortcut}'); \
         $Shortcut.TargetPath = '{target}'; \
         $Shortcut.Arguments = 'tray'; \
         $Shortcut.WorkingDirectory = '{workdir}'; \
         $Shortcut.IconLocation = '{target},0'; \
         $Shortcut.Description = 'Eguard ZTNA'; \
         $Shortcut.Save()",
        shortcut = shortcut_path.display().to_string().replace('\\', "\\\\"),
        target = exe.display().to_string().replace('\\', "\\\\"),
        workdir = exe
            .parent()
            .unwrap_or_else(|| std::path::Path::new(r"C:\Program Files\eGuard"))
            .display()
            .to_string()
            .replace('\\', "\\\\"),
    );

    Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &ps_script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .context("create start menu shortcut")?;

    Ok(())
}

fn list_bookmarks() -> Result<()> {
    let state = BookmarkState::load_default()?;
    for bookmark in state.bookmarks {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            bookmark.app_id,
            bookmark.name,
            bookmark.app_type,
            bookmark.health_status,
            if bookmark.launcher_supported {
                "supported"
            } else {
                "missing-launcher"
            }
        );
    }
    Ok(())
}

fn open_bookmark(app_id: &str) -> Result<()> {
    let state = BookmarkState::load_default()?;
    let bookmark = state
        .bookmarks
        .iter()
        .find(|bookmark| bookmark.app_id == app_id)
        .cloned()
        .ok_or_else(|| anyhow!("bookmark `{app_id}` not found"))?;
    let parsed = protocol::LaunchRequest::parse(&bookmark.launch_uri)
        .with_context(|| format!("parse launch uri for {}", bookmark.app_id))?;
    upsert_launch_request_entry(LaunchRequestEntry::connecting(
        app_id,
        &parsed.target,
        parsed.launcher.as_deref(),
    ))?;
    let session_snapshot = snapshot_session_cache()?;
    enqueue_command(state::TrayCommand::OpenApp {
        app_id: app_id.to_string(),
        forward_host: bookmark.target_host.clone(),
        forward_port: bookmark.target_port.map(|port| port as u16),
    })?;
    let _ = wait_for_session_cache_update(&session_snapshot, Duration::from_secs(8));
    let result = launch_bookmark(&bookmark);
    if let Err(err) = &result {
        if err
            .to_string()
            .to_ascii_lowercase()
            .contains("pending approval")
        {
            return Ok(());
        }
    }
    result
}

fn list_sessions() -> Result<()> {
    let state = SessionState::load_default()?;
    for session in state.sessions {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            session.session_id,
            session.app_id,
            session.transport,
            session.status,
            session.last_outcome.unwrap_or_default()
        );
    }
    Ok(())
}

fn enqueue_command(command: state::TrayCommand) -> Result<()> {
    let mut queue = TrayCommandQueue::load_default()?;
    queue.push(command);
    queue.save_default()?;
    info!(path = %command_queue_path()?.display(), "queued tray command");
    Ok(())
}

fn refresh_state() -> Result<()> {
    let bookmark_snapshot = snapshot_bookmark_cache()?;
    enqueue_command(state::TrayCommand::Refresh)?;
    wait_for_bookmark_cache_update(&bookmark_snapshot, Duration::from_secs(15))?;
    let bookmarks = BookmarkState::load_default()?;
    let sessions = SessionState::load_default()?;
    println!(
        "bookmarks={} sessions={} bookmark_cache={} session_state={}",
        bookmarks.bookmarks.len(),
        sessions.sessions.len(),
        bookmark_cache_path()?.display(),
        session_state_path()?.display()
    );
    Ok(())
}

fn open_management_ui() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        return ui::open_management_window();
    }
    #[cfg(not(target_os = "windows"))]
    {
        open_admin_ui()
    }
}

fn print_paths() -> Result<()> {
    println!("bookmark_cache={}", bookmark_cache_path()?.display());
    println!("session_state={}", session_state_path()?.display());
    println!("command_queue={}", command_queue_path()?.display());
    println!("pam_launch_state={}", pam_launch_state_path()?.display());
    println!(
        "launch_request_state={}",
        launch_request_state_path()?.display()
    );
    Ok(())
}

fn current_exe_string() -> Result<String> {
    let exe = std::env::current_exe().context("resolve current tray executable path")?;
    Ok(exe.to_string_lossy().into_owned())
}

#[cfg(target_os = "windows")]
fn start_tray_watchdog_if_needed() -> Result<()> {
    if std::env::var("EGUARD_TRAY_WATCHDOG_CHILD").ok().as_deref() == Some("1") {
        return Ok(());
    }
    if std::env::var("EGUARD_TRAY_DISABLE_WATCHDOG")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .is_some()
    {
        return Ok(());
    }

    let exe = std::env::current_exe().context("resolve current tray executable path")?;
    std::process::Command::new(exe)
        .args(["watchdog", &std::process::id().to_string()])
        .env("EGUARD_TRAY_WATCHDOG_CHILD", "1")
        .creation_flags(CREATE_NO_WINDOW | 0x0000_0008)
        .spawn()
        .context("start tray watchdog process")?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn start_tray_watchdog_if_needed() -> Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_tray_watchdog(parent_pid: u32) -> Result<()> {
    use std::time::{Duration, SystemTime};

    let heartbeat_path = tray_heartbeat_path()?;
    let shutdown_marker = tray_shutdown_marker_path()?;
    let stale_after = Duration::from_secs(
        std::env::var("EGUARD_TRAY_WATCHDOG_STALE_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value >= 10)
            .unwrap_or(20),
    );

    loop {
        std::thread::sleep(Duration::from_secs(5));
        if shutdown_marker.exists() {
            return Ok(());
        }
        if !windows_process_alive(parent_pid) {
            return Ok(());
        }

        let stale = std::fs::metadata(&heartbeat_path)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .map(|age| age > stale_after)
            .unwrap_or(false);
        if !stale {
            continue;
        }

        let _ = windows_kill_process(parent_pid);
        std::thread::sleep(Duration::from_secs(1));
        let exe = std::env::current_exe().context("resolve current tray executable path")?;
        std::process::Command::new(exe)
            .arg("tray")
            .creation_flags(CREATE_NO_WINDOW | 0x0000_0008)
            .spawn()
            .context("restart stale tray process")?;
        return Ok(());
    }
}

#[cfg(not(target_os = "windows"))]
fn run_tray_watchdog(_parent_pid: u32) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_process_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return false;
    };
    let mut exit_code = 0u32;
    let alive = unsafe { GetExitCodeProcess(handle, &mut exit_code).is_ok() }
        && exit_code == STILL_ACTIVE.0 as u32;
    let _ = unsafe { CloseHandle(handle) };
    alive
}

#[cfg(target_os = "windows")]
fn windows_kill_process(pid: u32) -> Result<()> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }
        .context("open stale tray process for termination")?;
    unsafe { TerminateProcess(handle, 1) }.context("terminate stale tray process")?;
    let _ = unsafe { CloseHandle(handle) };
    Ok(())
}

fn ensure_background_tray() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        if tray::is_tray_running() {
            return Ok(());
        }

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;

        let exe = std::env::current_exe().context("resolve current tray executable path")?;
        std::process::Command::new(exe)
            .arg("tray")
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
            .spawn()
            .context("start tray background process")?;
    }

    Ok(())
}
