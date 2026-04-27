#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;
mod launcher;
mod protocol;
mod state;
mod tray;

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
    bookmark_cache_path, command_queue_path, pam_launch_state_path, session_state_path,
    snapshot_bookmark_cache, snapshot_session_cache, wait_for_bookmark_cache_update,
    wait_for_session_cache_update, BookmarkState, SessionState, TrayCommandQueue,
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
    Paths,
    CleanupPamLaunch { checkout_id: i64 },
    CleanupAllPamLaunches,
    Tray,
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
        Command::Paths => print_paths(),
        Command::CleanupPamLaunch { checkout_id } => cleanup_pam_launch(checkout_id),
        Command::CleanupAllPamLaunches => cleanup_all_pam_launches(),
        Command::Tray => {
            reconcile_pam_launches_on_startup()?;
            tray::run_windows_tray()
        }
    }
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .try_init();
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
    if shortcut_path.exists() {
        return Ok(());
    }

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
    let session_snapshot = snapshot_session_cache()?;
    enqueue_command(state::TrayCommand::OpenApp {
        app_id: app_id.to_string(),
        forward_host: bookmark.target_host.clone(),
        forward_port: bookmark.target_port.map(|port| port as u16),
    })?;
    let _ = wait_for_session_cache_update(&session_snapshot, Duration::from_secs(8));
    launch_bookmark(&bookmark)
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
    wait_for_bookmark_cache_update(&bookmark_snapshot, Duration::from_secs(6))?;
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

fn print_paths() -> Result<()> {
    println!("bookmark_cache={}", bookmark_cache_path()?.display());
    println!("session_state={}", session_state_path()?.display());
    println!("command_queue={}", command_queue_path()?.display());
    println!("pam_launch_state={}", pam_launch_state_path()?.display());
    Ok(())
}

fn current_exe_string() -> Result<String> {
    let exe = std::env::current_exe().context("resolve current tray executable path")?;
    Ok(exe.to_string_lossy().into_owned())
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
