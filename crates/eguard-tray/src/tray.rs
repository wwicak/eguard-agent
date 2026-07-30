use anyhow::{Context, Result};
use std::fs;
use std::time::{Duration, Instant};
use tracing::{error, info};

use crate::protocol::LaunchRequest;

#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
use std::{os::windows::process::CommandExt, process::Stdio};

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[cfg(target_os = "windows")]
use image::ImageReader;
use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIconBuilder, TrayIconEvent};

use crate::app::open_local_path;
use crate::launcher::{
    launch_bookmark, launch_launch_request_with_session_fallback, reconcile_pending_launch_requests,
};
use crate::state::{
    bookmark_cache_path, clear_launch_request_entry, dlp_state_path, launch_request_state_path,
    pam_launch_state_path, session_state_path, snapshot_session_cache, tray_heartbeat_path,
    tray_preferences_path, tray_shutdown_marker_path, upsert_launch_request_entry,
    wait_for_session_cache_update, BookmarkEntry, BookmarkState, DlpState, LaunchRequestEntry,
    LaunchRequestState, PamLaunchState, RecentLaunchEntry, SessionState, TrayCommand,
    TrayCommandQueue, TrayPreferences,
};

pub fn run_windows_tray() -> Result<()> {
    let event_loop = EventLoopBuilder::<TrayUserEvent>::with_user_event().build();

    let proxy = event_loop.create_proxy();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = event;
        let _ = proxy.send_event(TrayUserEvent::Tray);
    }));

    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(TrayUserEvent::Menu(event));
    }));

    let mut tray_icon = None;
    let mut state = TrayUiState::new()?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_secs(5));

        match event {
            Event::NewEvents(tao::event::StartCause::Init)
            | Event::NewEvents(tao::event::StartCause::ResumeTimeReached { .. }) => {
                if let Err(err) = write_tray_heartbeat() {
                    error!(error = %err, "tray heartbeat update failed");
                }
                if let Err(err) = reconcile_pending_launch_requests() {
                    error!(error = %err, "pending launch reconciliation failed");
                }
                if tray_icon.is_none() {
                    match initialize_tray_icon(&mut state) {
                        Ok(icon) => {
                            tray_icon = Some(icon);
                        }
                        Err(err) => {
                            error!(error = %err, "tray initialization failed; will retry");
                        }
                    }
                }
                refresh_menu(&mut state, tray_icon.as_mut(), false);
                *control_flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_secs(5));
            }
            Event::UserEvent(TrayUserEvent::Menu(event)) => {
                if let Err(err) = handle_menu_event(&mut state, event.id()) {
                    if err.to_string().contains("quit requested") {
                        std::process::exit(0);
                    } else {
                        error!(error = %err, "tray menu action failed");
                    }
                }
                refresh_menu(&mut state, tray_icon.as_mut(), true);
            }
            Event::UserEvent(TrayUserEvent::Tray) => {
                refresh_tray_visuals(&state, tray_icon.as_mut());
            }
            _ => {}
        }
    })
}

fn initialize_tray_icon(state: &mut TrayUiState) -> Result<tray_icon::TrayIcon> {
    let (menu, actions) = build_menu().context("build tray menu")?;
    state.actions = actions;
    let icon = match state.status_icon_for_current_state() {
        Some(icon) => icon,
        None => default_icon().context("build fallback tray icon")?,
    };
    let mut builder = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .with_title("eGuard");
    if let Some(tooltip) = current_tooltip() {
        builder = builder.with_tooltip(tooltip);
    }
    builder.build().context("create tray icon")
}

#[derive(Debug)]
enum TrayUserEvent {
    Tray,
    Menu(MenuEvent),
}

#[derive(Default)]
struct TrayUiState {
    actions: Vec<MenuAction>,
    connected_icon: Option<Icon>,
    disconnected_icon: Option<Icon>,
    last_menu_fingerprint: Option<String>,
}

impl TrayUiState {
    fn new() -> Result<Self> {
        Ok(Self {
            actions: Vec::new(),
            connected_icon: Some(build_status_icon(true)?),
            disconnected_icon: Some(build_status_icon(false)?),
            last_menu_fingerprint: None,
        })
    }
}

#[derive(Clone, Debug)]
enum MenuAction {
    LaunchBookmarkDefault { app_id: String },
    LaunchBookmarkWithLauncher { app_id: String, launcher: String },
    LaunchBookmarkWithTempToken { app_id: String },
    ToggleFavorite { app_id: String },
    DisconnectSession(String),
    CleanupPamLaunch(i64),
    CleanupAllPamLaunches,
    DisconnectAll,
    Refresh,
    OpenManager,
    OpenTrayLog,
    OpenAgentLog,
    OpenLogFolder,
    Quit,
}

impl MenuAction {
    fn id(&self) -> String {
        match self {
            MenuAction::LaunchBookmarkDefault { app_id } => format!("app-launch-default:{app_id}"),
            MenuAction::LaunchBookmarkWithLauncher { app_id, launcher } => {
                format!("app-launch:{app_id}:{launcher}")
            }
            MenuAction::LaunchBookmarkWithTempToken { app_id } => {
                format!("app-launch-temp-token:{app_id}")
            }
            MenuAction::ToggleFavorite { app_id } => format!("app-favorite:{app_id}"),
            MenuAction::DisconnectSession(session_id) => format!("session-disconnect:{session_id}"),
            MenuAction::CleanupPamLaunch(checkout_id) => format!("pam-cleanup:{checkout_id}"),
            MenuAction::CleanupAllPamLaunches => "action-cleanup-all-pam".to_string(),
            MenuAction::DisconnectAll => "action-disconnect-all".to_string(),
            MenuAction::Refresh => "action-refresh".to_string(),
            MenuAction::OpenManager => "action-open-manager".to_string(),
            MenuAction::OpenTrayLog => "action-open-tray-log".to_string(),
            MenuAction::OpenAgentLog => "action-open-agent-log".to_string(),
            MenuAction::OpenLogFolder => "action-open-log-folder".to_string(),
            MenuAction::Quit => "action-quit".to_string(),
        }
    }
}

fn build_menu() -> Result<(Menu, Vec<MenuAction>)> {
    let bookmarks = BookmarkState::load_default().context("load bookmarks for tray")?;
    let sessions = effective_sessions(&bookmarks).context("load effective sessions for tray")?;
    let launch_requests = LaunchRequestState::load_default().unwrap_or_default();
    let pam_launches = PamLaunchState::load_default().unwrap_or_default();
    let preferences = TrayPreferences::load_default().unwrap_or_default();

    let menu = Menu::new();
    let mut actions = Vec::new();

    let pending_entries = launch_requests.active_entries();
    let connection_label = if !pending_entries.is_empty() {
        let waiting = pending_entries
            .iter()
            .filter(|entry| entry.status.eq_ignore_ascii_case("waiting_for_approval"))
            .count();
        if waiting > 0 {
            format!("Status: Waiting for approval · {} pending", waiting)
        } else {
            format!(
                "Status: Connecting · {} launch request(s)",
                pending_entries.len()
            )
        }
    } else if sessions.is_empty() {
        "Status: Not connected".to_string()
    } else if sessions.len() == 1 {
        "Status: Connected · 1 active session".to_string()
    } else {
        format!("Status: Connected · {} active sessions", sessions.len())
    };
    menu.append(&MenuItem::new(&connection_label, false, None))?;
    let dlp = DlpState::load_default().unwrap_or_default();
    menu.append(&MenuItem::new(dlp_menu_label(&dlp), false, None))?;
    menu.append(&PredefinedMenuItem::separator())?;

    if bookmarks.bookmarks.is_empty() {
        menu.append(&MenuItem::new("No applications", false, None))?;
    } else {
        menu.append(&MenuItem::new("Applications", false, None))?;
        for bookmark in &bookmarks.bookmarks {
            let parsed = LaunchRequest::parse(&bookmark.launch_uri).ok();
            let action = MenuAction::LaunchBookmarkDefault {
                app_id: bookmark.app_id.clone(),
            };
            let label = app_label(bookmark, parsed.as_ref());
            let item = MenuItem::with_id(action.id(), label, bookmark.launcher_supported, None);
            actions.push(action);
            menu.append(&item)?;
        }
    }

    menu.append(&PredefinedMenuItem::separator())?;

    if !sessions.is_empty() {
        let disconnect_all =
            MenuItem::with_id(MenuAction::DisconnectAll.id(), "Disconnect All", true, None);
        actions.push(MenuAction::DisconnectAll);
        menu.append(&disconnect_all)?;
    }

    let refresh_action = MenuAction::Refresh;
    let refresh = MenuItem::with_id(refresh_action.id(), "Refresh", true, None);
    actions.push(refresh_action);
    menu.append(&refresh)?;

    let manager_action = MenuAction::OpenManager;
    let manager_item = MenuItem::with_id(manager_action.id(), "Manage ZTNA...", true, None);
    actions.push(manager_action);
    menu.append(&manager_item)?;

    menu.append(&PredefinedMenuItem::separator())?;

    let quit_action = MenuAction::Quit;
    let quit = MenuItem::with_id(quit_action.id(), "Quit", true, None);
    actions.push(quit_action);
    menu.append(&quit)?;

    Ok((menu, actions))
}

fn build_bookmark_submenu(
    bookmark: &BookmarkEntry,
    pam_launches: &PamLaunchState,
    preferences: &TrayPreferences,
    actions: &mut Vec<MenuAction>,
) -> Result<Submenu> {
    let parsed = LaunchRequest::parse(&bookmark.launch_uri).ok();
    let menu = Submenu::new(app_label(bookmark, parsed.as_ref()), true);
    let active_pam_for_app: Vec<_> = pam_launches
        .entries
        .iter()
        .filter(|entry| entry.app_id == bookmark.app_id)
        .collect();
    let pending_launch = LaunchRequestState::load_default().ok().and_then(|state| {
        state
            .entries
            .into_iter()
            .find(|entry| entry.app_id == bookmark.app_id)
    });

    if let Some(request) = parsed.as_ref() {
        menu.append(&MenuItem::new(
            format!("Target: {}", request.target),
            false,
            None,
        ))?;
        if let Some(user) = request
            .user
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            menu.append(&MenuItem::new(format!("User: {user}"), false, None))?;
        }
        if request.credential_id.is_some() {
            menu.append(&MenuItem::new("Auth: PAM credential bound", false, None))?;
        }
    } else if let Some(target_host) = bookmark.target_host.as_deref() {
        menu.append(&MenuItem::new(
            format!("Target: {target_host}"),
            false,
            None,
        ))?;
    }

    menu.append(&MenuItem::new(
        format!(
            "Health: {}",
            blank_fallback(&bookmark.health_status, "unknown")
        ),
        false,
        None,
    ))?;
    menu.append(&MenuItem::new(
        format!(
            "Pinned: {}",
            if preferences.is_favorite(&bookmark.app_id) {
                "Yes"
            } else {
                "No"
            }
        ),
        false,
        None,
    ))?;
    if let Some(pending) = pending_launch.as_ref() {
        menu.append(&MenuItem::new(
            format!("Launch: {}", friendly_launch_status(&pending.status)),
            false,
            None,
        ))?;
    }
    if active_pam_for_app.is_empty() {
        menu.append(&MenuItem::new("PAM: No active local launch", false, None))?;
    } else if active_pam_for_app.len() == 1 {
        let entry = active_pam_for_app[0];
        menu.append(&MenuItem::new(
            format!(
                "PAM: Active via {} (checkout #{})",
                entry.launcher_kind, entry.checkout_id
            ),
            false,
            None,
        ))?;
    } else {
        menu.append(&MenuItem::new(
            format!("PAM: {} active local launches", active_pam_for_app.len()),
            false,
            None,
        ))?;
    }

    menu.append(&PredefinedMenuItem::separator())?;
    let favorite_action = MenuAction::ToggleFavorite {
        app_id: bookmark.app_id.clone(),
    };
    let favorite_item = MenuItem::with_id(
        favorite_action.id(),
        if preferences.is_favorite(&bookmark.app_id) {
            "Unpin Favorite"
        } else {
            "Pin to Favorites"
        },
        true,
        None,
    );
    actions.push(favorite_action);
    menu.append(&favorite_item)?;

    if !bookmark.launcher_supported {
        menu.append(&MenuItem::new(
            "Launcher not available on this endpoint",
            false,
            None,
        ))?;
        return Ok(menu);
    }

    menu.append(&PredefinedMenuItem::separator())?;

    let default_action = MenuAction::LaunchBookmarkDefault {
        app_id: bookmark.app_id.clone(),
    };
    let default_label = default_launch_label(parsed.as_ref(), bookmark);
    let default_item = MenuItem::with_id(default_action.id(), default_label, true, None);
    actions.push(default_action);
    menu.append(&default_item)?;

    if parsed
        .as_ref()
        .and_then(|request| request.credential_id)
        .is_some()
    {
        let token_action = MenuAction::LaunchBookmarkWithTempToken {
            app_id: bookmark.app_id.clone(),
        };
        let token_item = MenuItem::with_id(
            token_action.id(),
            "Connect with Temporary Token...",
            true,
            None,
        );
        actions.push(token_action);
        menu.append(&token_item)?;
    }

    if let Some(request) = parsed.as_ref() {
        append_launch_variants(bookmark, request, &menu, actions)?;
    }

    Ok(menu)
}

fn append_launch_variants(
    bookmark: &BookmarkEntry,
    request: &LaunchRequest,
    menu: &Submenu,
    actions: &mut Vec<MenuAction>,
) -> Result<()> {
    match request.app_type.trim().to_ascii_lowercase().as_str() {
        "ssh" => {
            append_variant_action(
                bookmark,
                menu,
                actions,
                "html5",
                ssh_variant_label("html5", request),
                ssh_variant_enabled("html5", request),
            )?;
            append_variant_action(
                bookmark,
                menu,
                actions,
                "putty",
                ssh_variant_label("putty", request),
                ssh_variant_enabled("putty", request),
            )?;
        }
        "rdp" => {
            append_variant_action(
                bookmark,
                menu,
                actions,
                "rdp",
                launch_label_with_pam("Launch in Remote Desktop", request),
                rdp_available(),
            )?;
        }
        "web" | "http" | "https" => {
            append_variant_action(
                bookmark,
                menu,
                actions,
                "browser",
                launch_label_with_pam("Open in Browser", request),
                true,
            )?;
        }
        "vnc" => {
            append_variant_action(
                bookmark,
                menu,
                actions,
                "vnc",
                launch_label_with_pam("Launch in VNC Viewer", request),
                vnc_available(),
            )?;
        }
        _ => {}
    }
    Ok(())
}

fn append_variant_action(
    bookmark: &BookmarkEntry,
    menu: &Submenu,
    actions: &mut Vec<MenuAction>,
    launcher: &str,
    label: String,
    enabled: bool,
) -> Result<()> {
    let action = MenuAction::LaunchBookmarkWithLauncher {
        app_id: bookmark.app_id.clone(),
        launcher: launcher.to_string(),
    };
    let item = MenuItem::with_id(action.id(), label, enabled, None);
    actions.push(action);
    menu.append(&item)?;
    Ok(())
}

fn normalized_app_type_label(request: Option<&LaunchRequest>, bookmark: &BookmarkEntry) -> String {
    request
        .map(|value| value.app_type.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| blank_fallback(&bookmark.app_type, "APP").to_ascii_uppercase())
}

fn app_label(bookmark: &BookmarkEntry, request: Option<&LaunchRequest>) -> String {
    let app_type = normalized_app_type_label(request, bookmark);
    let badge = app_type_badge(&app_type);
    let pam = if request.and_then(|value| value.credential_id).is_some() {
        " (PAM)"
    } else {
        ""
    };
    format!("{badge} {}{pam}", bookmark.name)
}

fn app_type_badge(app_type: &str) -> &'static str {
    match app_type.trim().to_ascii_lowercase().as_str() {
        "ssh" => "[SSH]",
        "rdp" => "[RDP]",
        "http" | "https" | "web" => "[WEB]",
        "vnc" => "[VNC]",
        _ => "[APP]",
    }
}

fn default_launch_label(request: Option<&LaunchRequest>, bookmark: &BookmarkEntry) -> String {
    let base = match request
        .map(|value| value.app_type.trim().to_ascii_lowercase())
        .unwrap_or_else(|| bookmark.app_type.trim().to_ascii_lowercase())
        .as_str()
    {
        "ssh" => "Launch SSH (Default)",
        "rdp" => "Launch RDP",
        "web" | "http" | "https" => "Open Web App",
        "vnc" => "Launch VNC",
        _ => "Launch",
    };
    if let Some(request) = request {
        launch_label_with_pam(base, request)
    } else {
        base.to_string()
    }
}

fn launch_label_with_pam(base: &str, request: &LaunchRequest) -> String {
    if request.credential_id.is_some() {
        format!("{base} (PAM)")
    } else {
        base.to_string()
    }
}

fn ssh_variant_label(launcher: &str, request: &LaunchRequest) -> String {
    let base = match launcher {
        "html5" => "Launch in Web / HTML5",
        "putty" => "Launch in PuTTY",
        _ => "Launch SSH",
    };
    launch_label_with_pam(base, request)
}

fn ssh_variant_enabled(launcher: &str, request: &LaunchRequest) -> bool {
    let web_target = target_is_web_url(&request.target);
    let browser_terminal_supported = request.credential_id.unwrap_or_default() > 0;
    match launcher {
        "html5" => web_target || browser_terminal_supported,
        "putty" => !web_target && putty_available(),
        _ => false,
    }
}

fn target_is_web_url(target: &str) -> bool {
    let lower = target.trim().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn putty_available() -> bool {
    command_exists_in_path(&["putty.exe"])
        || std::path::Path::new(r"C:\Program Files\PuTTY\putty.exe").is_file()
        || std::path::Path::new(r"C:\Program Files (x86)\PuTTY\putty.exe").is_file()
}

fn rdp_available() -> bool {
    std::path::Path::new(r"C:\Windows\System32\mstsc.exe").is_file()
}

fn vnc_available() -> bool {
    command_exists_in_path(&["vncviewer.exe", "tvnviewer.exe"])
}

fn command_exists_in_path(candidates: &[&str]) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        candidates
            .iter()
            .any(|candidate| dir.join(candidate).is_file())
    })
}

fn recent_launcher_suffix(entry: &RecentLaunchEntry) -> String {
    entry
        .launcher
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!(" via {}", value.to_ascii_uppercase()))
        .unwrap_or_default()
}

fn dlp_status_label(dlp: &DlpState) -> String {
    if !dlp.enabled {
        return "Disabled".to_string();
    }
    if dlp.scanner_loaded && dlp.status.eq_ignore_ascii_case("active") {
        return format!("Active · {} MB", dlp.max_file_scan_size_mb);
    }
    "Degraded".to_string()
}

fn dlp_menu_label(dlp: &DlpState) -> String {
    format!("DLP: {}", dlp_status_label(dlp))
}

fn blank_fallback<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    }
}

fn friendly_launch_status(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "connecting" => "Connecting",
        "connecting_bastion" => "Creating bastion session",
        "waiting_for_approval" => "Waiting for approval",
        "launch_failed" => "Launch failed",
        _ => "Pending",
    }
}

trait LaunchRequestEntryExt {
    fn app_name_or_fallback(&self, bookmarks: &BookmarkState) -> String;
}

impl LaunchRequestEntryExt for LaunchRequestEntry {
    fn app_name_or_fallback(&self, bookmarks: &BookmarkState) -> String {
        bookmarks
            .bookmarks
            .iter()
            .find(|bookmark| bookmark.app_id == self.app_id)
            .map(|bookmark| bookmark.name.clone())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| self.app_id.clone())
    }
}

fn refresh_menu(state: &mut TrayUiState, tray_icon: Option<&mut tray_icon::TrayIcon>, force: bool) {
    let fingerprint = current_menu_fingerprint();
    if !force && state.last_menu_fingerprint.as_deref() == Some(fingerprint.as_str()) {
        refresh_tray_visuals(state, tray_icon);
        return;
    }
    if let Ok((menu, actions)) = build_menu() {
        state.actions = actions;
        state.last_menu_fingerprint = Some(fingerprint);
        if let Some(icon) = tray_icon {
            let _ = icon.set_menu(Some(Box::new(menu)));
            refresh_tray_visuals(state, Some(icon));
        }
    }
}

fn current_menu_fingerprint() -> String {
    [
        bookmark_cache_path().ok(),
        session_state_path().ok(),
        dlp_state_path().ok(),
        launch_request_state_path().ok(),
        pam_launch_state_path().ok(),
        tray_preferences_path().ok(),
    ]
    .into_iter()
    .flatten()
    .map(|path| {
        let meta = fs::metadata(&path).ok();
        let len = meta.as_ref().map(|value| value.len()).unwrap_or_default();
        let modified = meta
            .and_then(|value| value.modified().ok())
            .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|value| value.as_millis())
            .unwrap_or_default();
        format!("{}:{}:{}", path.display(), len, modified)
    })
    .collect::<Vec<_>>()
    .join("|")
}

fn refresh_tray_visuals(state: &TrayUiState, tray_icon: Option<&mut tray_icon::TrayIcon>) {
    if let Some(icon) = tray_icon {
        let _ = icon.set_tooltip(current_tooltip().as_deref());
        let _ = icon.set_icon(Some(
            state
                .status_icon_for_current_state()
                .unwrap_or_else(|| default_icon().expect("build tray icon")),
        ));
    }
}

fn handle_menu_event(state: &mut TrayUiState, menu_id: &MenuId) -> Result<()> {
    let raw: &str = menu_id.as_ref();
    let action = state
        .actions
        .iter()
        .find(|action| action.id() == raw)
        .cloned()
        .context("resolve tray action")?;
    info!(menu_id = raw, action = ?action, "tray menu action selected");
    match action {
        MenuAction::LaunchBookmarkDefault { app_id } => {
            launch_bookmark_from_menu(&app_id, None, None)?;
        }
        MenuAction::LaunchBookmarkWithLauncher { app_id, launcher } => {
            launch_bookmark_from_menu(&app_id, Some(&launcher), None)?;
        }
        MenuAction::LaunchBookmarkWithTempToken { app_id } => {
            if let Some(token) = prompt_for_temp_token()? {
                launch_bookmark_from_menu(&app_id, None, Some(token.as_str()))?;
            }
        }
        MenuAction::ToggleFavorite { app_id } => {
            let mut preferences = TrayPreferences::load_default().unwrap_or_default();
            preferences.toggle_favorite(&app_id);
            preferences.save_default()?;
        }
        MenuAction::DisconnectSession(session_id) => {
            let session_snapshot = snapshot_session_cache()?;
            queue_command(TrayCommand::Disconnect { session_id })?;
            let _ = wait_for_session_cache_update(&session_snapshot, Duration::from_secs(8));
        }
        MenuAction::CleanupPamLaunch(checkout_id) => {
            queue_command(TrayCommand::CleanupPamLaunch { checkout_id })?;
        }
        MenuAction::CleanupAllPamLaunches => {
            queue_command(TrayCommand::CleanupAllPamLaunches)?;
        }
        MenuAction::DisconnectAll => {
            let session_snapshot = snapshot_session_cache()?;
            queue_command(TrayCommand::DisconnectAll)?;
            let _ = wait_for_session_cache_update(&session_snapshot, Duration::from_secs(8));
        }
        MenuAction::Refresh => {
            queue_command(TrayCommand::Refresh)?;
        }
        MenuAction::OpenManager => {
            open_manager_window()?;
        }
        MenuAction::OpenTrayLog => {
            open_local_path(&tray_log_path())?;
        }
        MenuAction::OpenAgentLog => {
            open_local_path(&agent_log_path())?;
        }
        MenuAction::OpenLogFolder => {
            open_local_path(&log_dir_path())?;
        }
        MenuAction::Quit => {
            let _ = write_tray_shutdown_marker();
            std::process::exit(0);
        }
    }
    Ok(())
}

fn launch_bookmark_from_menu(
    app_id: &str,
    launcher_override: Option<&str>,
    temp_token: Option<&str>,
) -> Result<()> {
    let bookmarks = BookmarkState::load_default()?;
    if let Some(bookmark) = bookmarks
        .bookmarks
        .into_iter()
        .find(|entry| entry.app_id == app_id)
    {
        let parsed = LaunchRequest::parse(&bookmark.launch_uri)
            .with_context(|| format!("parse launch uri for {}", bookmark.app_id))?;
        let session_snapshot = snapshot_session_cache()?;
        let mut effective_request = parsed.clone();
        if let Some(launcher) = launcher_override {
            effective_request.launcher = Some(resolve_launcher_override(&parsed, launcher));
        }
        if let Some(token) = temp_token.map(str::trim).filter(|value| !value.is_empty()) {
            effective_request.temp_token = Some(token.to_string());
        }
        upsert_launch_request_entry(LaunchRequestEntry::connecting(
            app_id,
            &effective_request.target,
            effective_request.launcher.as_deref(),
        ))?;
        queue_command(TrayCommand::OpenApp {
            app_id: app_id.to_string(),
            forward_host: bookmark.target_host.clone(),
            forward_port: bookmark.target_port.map(|port| port as u16),
        })?;
        let _ = wait_for_session_cache_update(&session_snapshot, Duration::from_secs(8));
        record_recent_launch(&bookmark, &effective_request)?;

        let launch_result = if launcher_override.is_some() || effective_request.temp_token.is_some()
        {
            launch_launch_request_with_session_fallback(&effective_request)
        } else {
            launch_bookmark(&bookmark)
        };
        if let Err(err) = &launch_result {
            if err
                .to_string()
                .to_ascii_lowercase()
                .contains("pending approval")
            {
                return Ok(());
            }
            let _ = upsert_launch_request_entry(LaunchRequestEntry::failed(
                app_id,
                &effective_request.target,
                effective_request.launcher.as_deref(),
                err.to_string(),
            ));
        }
        if launch_result.is_ok() {
            let _ = clear_launch_request_entry(app_id);
        }
        launch_result
    } else {
        Ok(())
    }
}

fn resolve_launcher_override(parsed: &LaunchRequest, launcher_override: &str) -> String {
    let override_value = launcher_override.trim().to_ascii_lowercase();
    let current = parsed
        .launcher
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let is_bastion = current == "bastion"
        || current == "bastion-browser"
        || current == "bastion_web"
        || current == "bastion_ssh"
        || current == "bastion_rdp";
    if !is_bastion {
        return launcher_override.to_string();
    }
    match override_value.as_str() {
        "putty" => {
            if parsed.app_type.trim().eq_ignore_ascii_case("ssh") {
                "bastion_ssh".to_string()
            } else {
                current
            }
        }
        "html5" | "browser" => "bastion_web".to_string(),
        "rdp" => "bastion_rdp".to_string(),
        _ => current,
    }
}

fn record_recent_launch(bookmark: &BookmarkEntry, request: &LaunchRequest) -> Result<()> {
    let mut preferences = TrayPreferences::load_default().unwrap_or_default();
    preferences.record_recent_launch(RecentLaunchEntry {
        app_id: bookmark.app_id.clone(),
        app_name: bookmark.name.clone(),
        target: request.target.clone(),
        launcher: request.launcher.clone(),
        app_type: request.app_type.clone(),
        pam: request.credential_id.is_some(),
        launched_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
    });
    preferences.save_default()
}

fn queue_command(command: TrayCommand) -> Result<()> {
    info!(command = ?command, "queueing tray command");
    let mut queue = TrayCommandQueue::load_default()?;
    queue.push(command);
    queue.save_default()
}

fn write_tray_heartbeat() -> Result<()> {
    let path = tray_heartbeat_path()?;
    fs::write(path, std::process::id().to_string()).context("write tray heartbeat")
}

fn write_tray_shutdown_marker() -> Result<()> {
    let path = tray_shutdown_marker_path()?;
    fs::write(path, std::process::id().to_string()).context("write tray shutdown marker")
}

fn open_manager_window() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        Command::new(std::env::current_exe().context("resolve tray executable")?)
            .arg("manage")
            .creation_flags(CREATE_NO_WINDOW | 0x0000_0008)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("open ZTNA manager window")?;
    }
    Ok(())
}

fn log_dir_path() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:\ProgramData\eGuard\logs")
}

fn tray_log_path() -> std::path::PathBuf {
    log_dir_path().join("tray.log")
}

fn agent_log_path() -> std::path::PathBuf {
    log_dir_path().join("agent.log")
}

impl TrayUiState {
    fn status_icon_for_current_state(&self) -> Option<Icon> {
        let bookmarks = BookmarkState::load_default().ok()?;
        let sessions = effective_sessions(&bookmarks).ok()?;
        if sessions.is_empty() {
            self.disconnected_icon.clone()
        } else {
            self.connected_icon.clone()
        }
    }
}

fn current_tooltip() -> Option<String> {
    let bookmarks = BookmarkState::load_default().ok()?;
    let launch_requests = LaunchRequestState::load_default().ok()?;
    let sessions = effective_sessions(&bookmarks).ok()?;
    let dlp = DlpState::load_default().unwrap_or_default();
    let dlp_line = format!("\nDLP: {}", dlp_status_label(&dlp));
    if !launch_requests.active_entries().is_empty() {
        let waiting = launch_requests
            .active_entries()
            .iter()
            .filter(|entry| entry.status.eq_ignore_ascii_case("waiting_for_approval"))
            .count();
        if waiting > 0 {
            return Some(format!(
                "eGuard ZTNA\nStatus: Waiting for approval\nPending requests: {}{}",
                waiting, dlp_line
            ));
        }
        return Some(format!(
            "eGuard ZTNA\nStatus: Connecting\nPending requests: {}{}",
            launch_requests.active_entries().len(),
            dlp_line
        ));
    }
    if sessions.is_empty() {
        return Some(format!("eGuard ZTNA\nStatus: Not connected{}", dlp_line));
    }

    let total_rx: i64 = sessions
        .iter()
        .map(|session| session.bytes_rx.unwrap_or(0))
        .sum();
    let total_tx: i64 = sessions
        .iter()
        .map(|session| session.bytes_tx.unwrap_or(0))
        .sum();
    Some(format!(
        "eGuard ZTNA\nStatus: Connected ({})\nIncoming: {}\nOutgoing: {}{}",
        sessions.len(),
        format_bytes(total_rx),
        format_bytes(total_tx),
        dlp_line
    ))
}

fn format_bytes(bytes: i64) -> String {
    let value = bytes.max(0) as f64;
    let units = ["B", "KiB", "MiB", "GiB"];
    let mut size = value;
    let mut unit = 0usize;
    while size >= 1024.0 && unit < units.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", size as i64, units[unit])
    } else {
        format!("{size:.2} {}", units[unit])
    }
}

#[cfg(target_os = "windows")]
fn configure_hidden_console_command(cmd: &mut Command) {
    cmd.creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
}

fn prompt_for_temp_token() -> Result<Option<String>> {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("powershell");
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Add-Type -AssemblyName Microsoft.VisualBasic; $value = [Microsoft.VisualBasic.Interaction]::InputBox('Paste a temporary launch token', 'eGuard ZTNA Temporary Token', ''); Write-Output $value",
        ]);
        configure_hidden_console_command(&mut cmd);
        let output = cmd.output().context("open temporary token prompt")?;
        if !output.status.success() {
            return Ok(None);
        }
        let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if token.is_empty() {
            return Ok(None);
        }
        return Ok(Some(token));
    }

    #[allow(unreachable_code)]
    Ok(None)
}

fn build_status_icon(connected: bool) -> Result<Icon> {
    let mut rgba = load_base_icon_rgba()?;
    let width = 16u32;
    let height = 16u32;
    let dot_color = if connected {
        [34u8, 197u8, 94u8, 255u8]
    } else {
        [148u8, 163u8, 184u8, 255u8]
    };
    let outline_color = [255u8, 255u8, 255u8, 255u8];
    let center_x = 11i32;
    let center_y = 11i32;
    let outer_radius_sq = 16i32;
    let inner_radius_sq = 9i32;

    for y in 7..16 {
        for x in 7..16 {
            let dx = x as i32 - center_x;
            let dy = y as i32 - center_y;
            let dist_sq = dx * dx + dy * dy;
            let idx = ((y * width + x) * 4) as usize;
            if dist_sq <= inner_radius_sq {
                rgba[idx..idx + 4].copy_from_slice(&dot_color);
            } else if dist_sq <= outer_radius_sq {
                rgba[idx..idx + 4].copy_from_slice(&outline_color);
            }
        }
    }
    Icon::from_rgba(rgba, width, height).context("build tray status icon")
}

fn load_base_icon_rgba() -> Result<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        let icon_path = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/tray.ico");
        let image = ImageReader::open(icon_path)
            .with_context(|| format!("open tray icon {}", icon_path))?
            .decode()
            .with_context(|| format!("decode tray icon {}", icon_path))?
            .into_rgba8();
        let resized =
            image::imageops::resize(&image, 16, 16, image::imageops::FilterType::Lanczos3);
        return Ok(resized.into_raw());
    }

    #[allow(unreachable_code)]
    default_icon_rgba()
}

fn default_icon() -> Result<Icon> {
    #[cfg(target_os = "windows")]
    {
        let icon_path = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/tray.ico");
        let image = ImageReader::open(icon_path)
            .with_context(|| format!("open tray icon {}", icon_path))?
            .decode()
            .with_context(|| format!("decode tray icon {}", icon_path))?
            .into_rgba8();
        let (width, height) = image.dimensions();
        return Icon::from_rgba(image.into_raw(), width, height)
            .context("build tray icon from ico");
    }

    #[allow(unreachable_code)]
    {
        let rgba = default_icon_rgba()?;
        Icon::from_rgba(rgba, 32, 32).context("build tray icon rgba")
    }
}

fn default_icon_rgba() -> Result<Vec<u8>> {
    let mut rgba = Vec::with_capacity(32 * 32 * 4);
    for y in 0..32 {
        for x in 0..32 {
            let in_outer = (4..=27).contains(&x) && (4..=27).contains(&y);
            let in_inner = (10..=21).contains(&x) && (10..=21).contains(&y);
            let in_bar = (8..=23).contains(&x) && (14..=17).contains(&y);
            let (r, g, b, a) = if in_inner {
                (241, 246, 242, 255)
            } else if in_outer {
                (25, 111, 97, 255)
            } else if in_bar {
                (181, 214, 92, 255)
            } else {
                (0, 0, 0, 0)
            };
            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }
    Ok(rgba)
}

pub fn is_tray_running() -> bool {
    false
}

fn effective_sessions(bookmarks: &BookmarkState) -> Result<Vec<crate::state::SessionEntry>> {
    let mut sessions = SessionState::load_default().unwrap_or_default().sessions;
    let pam_sessions = sessions_from_pam_launches(bookmarks).unwrap_or_default();

    #[cfg(target_os = "windows")]
    if sessions.is_empty() {
        if let Some(session) = session_from_wireguard(bookmarks)? {
            sessions.push(session);
        }
    }

    for pam_session in pam_sessions {
        let duplicate = sessions.iter().any(|session| {
            session.app_id == pam_session.app_id
                && session
                    .transport
                    .eq_ignore_ascii_case(&pam_session.transport)
                && session.status.eq_ignore_ascii_case(&pam_session.status)
        });
        if !duplicate {
            sessions.push(pam_session);
        }
    }

    Ok(sessions)
}

fn sessions_from_pam_launches(
    bookmarks: &BookmarkState,
) -> Result<Vec<crate::state::SessionEntry>> {
    let state = PamLaunchState::load_default().unwrap_or_default();
    let sessions = state
        .entries
        .into_iter()
        .map(|entry| {
            let bookmark = bookmarks
                .bookmarks
                .iter()
                .find(|bookmark| bookmark.app_id == entry.app_id);
            crate::state::SessionEntry {
                session_id: String::new(),
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
            }
        })
        .collect();
    Ok(sessions)
}

#[cfg(target_os = "windows")]
fn session_from_wireguard(bookmarks: &BookmarkState) -> Result<Option<crate::state::SessionEntry>> {
    let mut cmd = Command::new(r"C:\Program Files\WireGuard\wg.exe");
    cmd.arg("show");
    configure_hidden_console_command(&mut cmd);
    let output = cmd
        .output()
        .context("run wg show for tray session detection")?;
    if !output.status.success() {
        return Ok(None);
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let Some(interface_name) = raw
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface: ").map(str::trim))
        .filter(|name| name.eq_ignore_ascii_case("eguard-ztna"))
        .map(str::to_string)
    else {
        return Ok(None);
    };

    let mut latest_handshake = None;
    let mut bytes_rx = None;
    let mut bytes_tx = None;
    for line in raw.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("latest handshake: ") {
            latest_handshake = Some(value.trim().to_string());
        }
        if let Some(value) = line.strip_prefix("transfer: ") {
            let parts: Vec<_> = value.split(',').map(str::trim).collect();
            if parts.len() == 2 {
                bytes_rx = parse_human_size(parts[0].trim_end_matches(" received"));
                bytes_tx = parse_human_size(parts[1].trim_end_matches(" sent"));
            }
        }
    }

    let conf = std::fs::read_to_string(r"C:\ProgramData\eGuard\ztna\eguard-ztna.conf")
        .context("read local eguard-ztna config")?;
    let allowed_line = conf
        .lines()
        .find(|line| line.trim_start().starts_with("AllowedIPs = "))
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    let allowed_ips = allowed_line
        .strip_prefix("AllowedIPs = ")
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    let bookmark = bookmarks.bookmarks.iter().find(|bookmark| {
        bookmark
            .target_host
            .as_deref()
            .map(str::trim)
            .map(|host| allowed_ips.iter().any(|cidr| cidr.starts_with(host)))
            .unwrap_or(false)
    });

    let app_id = bookmark
        .map(|bookmark| bookmark.app_id.clone())
        .unwrap_or_else(|| interface_name.clone());
    let app_name = bookmark
        .map(|bookmark| bookmark.name.clone())
        .unwrap_or_else(|| interface_name.clone());

    Ok(Some(crate::state::SessionEntry {
        session_id: String::new(),
        app_id,
        app_name,
        transport: "wireguard".to_string(),
        status: "active".to_string(),
        started_at: None,
        last_activity_at: None,
        last_outcome: latest_handshake.map(|value| format!("handshake {}", value)),
        local_url: None,
        bytes_tx,
        bytes_rx,
        active_connections: Some(1),
        tunnel_latency_ms: None,
    }))
}

#[cfg(target_os = "windows")]
fn parse_human_size(raw: &str) -> Option<i64> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 2 {
        return None;
    }
    let value = parts[0].parse::<f64>().ok()?;
    let multiplier = match parts[1] {
        "B" => 1.0,
        "KiB" => 1024.0,
        "MiB" => 1024.0 * 1024.0,
        "GiB" => 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((value * multiplier) as i64)
}

fn format_session_stats(session: &crate::state::SessionEntry) -> String {
    let incoming = format_bytes(session.bytes_rx.unwrap_or(0));
    let outgoing = format_bytes(session.bytes_tx.unwrap_or(0));
    let connections = session.active_connections.unwrap_or(0);
    format!("  ↓{} ↑{} · conn {}", incoming, outgoing, connections)
}

trait SessionLabel {
    fn app_name_or_app_id(&self) -> String;
}

impl SessionLabel for crate::state::SessionEntry {
    fn app_name_or_app_id(&self) -> String {
        if self.app_name.trim().is_empty() {
            self.app_id.clone()
        } else {
            self.app_name.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{dlp_menu_label, dlp_status_label};
    use crate::state::DlpState;

    #[test]
    fn dlp_menu_label_reports_safe_operational_state() {
        assert_eq!(dlp_status_label(&DlpState::default()), "Disabled");
        assert_eq!(dlp_menu_label(&DlpState::default()), "DLP: Disabled");
        assert_eq!(
            dlp_menu_label(&DlpState {
                enabled: true,
                scanner_loaded: true,
                max_file_scan_size_mb: 10,
                status: "active".to_string(),
                last_detection_unix: None,
                last_rule_id: None,
            }),
            "DLP: Active · 10 MB"
        );
        assert_eq!(
            dlp_menu_label(&DlpState {
                enabled: true,
                scanner_loaded: false,
                max_file_scan_size_mb: 10,
                status: "degraded".to_string(),
                last_detection_unix: None,
                last_rule_id: None,
            }),
            "DLP: Degraded"
        );
    }
}
