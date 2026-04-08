use anyhow::{anyhow, Result};
use tracing::info;
use ztna::{
    bookmark_by_app_id, default_bookmark_state_path, default_command_queue_dir,
    default_session_state_path, empty_session_state, enqueue_command, launch_uri, next_session_id,
    read_bookmark_state, read_session_state, register_protocol_handler_for_current_exe,
    upsert_session, write_session_state, ActiveSessionRecord, BookmarkState, SessionState,
    TrayCommandKind,
};

pub fn run_cli(args: Vec<String>) -> Result<()> {
    if args.is_empty() {
        return print_status();
    }

    match args[0].as_str() {
        "register-protocol" => {
            let exe = std::env::current_exe()?;
            let path = register_protocol_handler_for_current_exe(&exe)?;
            println!("Registered eguard-ztna protocol via {}", path.display());
            Ok(())
        }
        "list" => print_status(),
        "list-sessions" => print_sessions(),
        "open" => {
            let app_id = args
                .get(1)
                .ok_or_else(|| anyhow!("bookmark_app_id_required"))?;
            open_bookmark(app_id)
        }
        "disconnect" => {
            let session_id = args.get(1).ok_or_else(|| anyhow!("session_id_required"))?;
            disconnect_session(session_id)
        }
        "disconnect-all" => disconnect_all_sessions(),
        "disable-transport" => disable_transport(),
        "enable-transport" => enable_transport(),
        raw if raw.starts_with("eguard-ztna://") => launch_and_track(raw, None, None, None),
        _ => Err(anyhow!("unsupported_tray_command")),
    }
}

pub fn bookmarks_state() -> Result<BookmarkState> {
    read_bookmark_state(&default_bookmark_state_path())
}

pub fn sessions_state() -> Result<SessionState> {
    let path = default_session_state_path();
    match read_session_state(&path) {
        Ok(state) => Ok(state),
        Err(_) => Ok(empty_session_state()),
    }
}

pub fn print_status() -> Result<()> {
    let state = bookmarks_state()?;
    info!(bookmark_count = state.bookmarks.len(), version = %state.version, "eguard-tray loaded bookmark state");
    println!(
        "eGuard Tray bookmarks: {} (version {})",
        state.bookmarks.len(),
        state.version
    );
    for bookmark in state.bookmarks.iter() {
        println!(
            "- {} [{}] {}",
            bookmark.name,
            bookmark.app_type,
            if bookmark.launcher_supported {
                "launchable"
            } else {
                "view only"
            }
        );
    }
    Ok(())
}

pub fn open_bookmark(app_id: &str) -> Result<()> {
    let state = bookmarks_state()?;
    let bookmark =
        bookmark_by_app_id(&state, app_id).ok_or_else(|| anyhow!("bookmark_not_found"))?;
    if bookmark.launch_uri.trim().is_empty() {
        return Err(anyhow!("bookmark_launch_uri_missing"));
    }
    launch_and_track(
        &bookmark.launch_uri,
        Some(bookmark.app_id.clone()),
        Some(bookmark.name.clone()),
        Some(bookmark.app_type.clone()),
    )
}

pub fn print_sessions() -> Result<()> {
    let state = sessions_state()?;
    println!(
        "eGuard Tray active sessions: {} (transport_disabled={})",
        state.sessions.len(),
        state.transport_disabled
    );
    for session in state.sessions.iter() {
        println!(
            "- {} {} [{}] status={} transport={}",
            session.session_id, session.name, session.app_id, session.status, session.transport
        );
    }
    if !state.command_results.is_empty() {
        println!("Recent tray command results:");
        for result in state.command_results.iter().take(5) {
            println!(
                "- {} success={} {}",
                result.command_id, result.success, result.message
            );
        }
    }
    Ok(())
}

pub fn disconnect_session(session_id: &str) -> Result<()> {
    let command = enqueue_command(
        &default_command_queue_dir(),
        TrayCommandKind::DisconnectSession {
            session_id: session_id.to_string(),
        },
    )?;
    println!(
        "Queued disconnect for session {} ({})",
        session_id, command.command_id
    );
    Ok(())
}

pub fn disconnect_all_sessions() -> Result<()> {
    let command = enqueue_command(&default_command_queue_dir(), TrayCommandKind::DisconnectAll)?;
    println!("Queued disconnect-all ({})", command.command_id);
    Ok(())
}

pub fn disable_transport() -> Result<()> {
    let command = enqueue_command(
        &default_command_queue_dir(),
        TrayCommandKind::DisableTransport,
    )?;
    println!("Queued managed transport disable ({})", command.command_id);
    Ok(())
}

pub fn enable_transport() -> Result<()> {
    let command = enqueue_command(
        &default_command_queue_dir(),
        TrayCommandKind::EnableTransport,
    )?;
    println!("Queued transport enable ({})", command.command_id);
    Ok(())
}

pub fn launch_and_track(
    raw_uri: &str,
    app_id: Option<String>,
    name: Option<String>,
    app_type: Option<String>,
) -> Result<()> {
    let request = ztna::parse_launch_uri(raw_uri)?;
    let session_path = default_session_state_path();
    let mut session_state = sessions_state()?;
    if session_state.transport_disabled {
        return Err(anyhow!("transport_disabled"));
    }
    let outcome = launch_uri(raw_uri)?;
    let session = ActiveSessionRecord {
        session_id: next_session_id(app_id.as_deref().unwrap_or(request.app_id.as_str())),
        app_id: app_id.unwrap_or(request.app_id),
        name: name.unwrap_or(request.name),
        app_type: app_type.unwrap_or_else(|| match request.kind {
            ztna::LaunchTargetKind::Ssh => "ssh".to_string(),
            ztna::LaunchTargetKind::Rdp => "rdp".to_string(),
            ztna::LaunchTargetKind::Vnc => "vnc".to_string(),
            ztna::LaunchTargetKind::Web => "web".to_string(),
            ztna::LaunchTargetKind::Tcp => "tcp".to_string(),
        }),
        launch_uri: raw_uri.to_string(),
        transport: "wireguard".to_string(),
        started_at_unix: now_unix(),
        last_activity_at_unix: now_unix(),
        status: "active".to_string(),
    };
    upsert_session(&mut session_state, session.clone());
    write_session_state(&session_path, &session_state)?;
    println!(
        "Launched {} using {} (session {})",
        outcome.target, outcome.launcher, session.session_id
    );
    Ok(())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}
