use anyhow::{Context, Result};
use std::time::Duration;
use tracing::error;

use crate::protocol::LaunchRequest;

#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "windows")]
use image::ImageReader;
use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIconBuilder, TrayIconEvent};

#[cfg(target_os = "windows")]
use windows::core::w;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::CreateMutexW;

use crate::launcher::{launch_bookmark, launch_launch_request_with_session_fallback};
use crate::state::{
    snapshot_bookmark_cache, snapshot_session_cache, wait_for_bookmark_cache_update,
    wait_for_session_cache_update, BookmarkEntry, BookmarkState, PamLaunchState,
    RecentLaunchEntry, SessionState, TrayCommand, TrayCommandQueue, TrayPreferences,
};

pub fn run_windows_tray() -> Result<()> {
    let _guard = SingleInstanceGuard::acquire()?;
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
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(tao::event::StartCause::Init) => {
                if let Ok((menu, actions)) = build_menu() {
                    state.actions = actions;
                    let icon = state
                        .status_icon_for_current_state()
                        .unwrap_or_else(|| default_icon().expect("build tray icon"));
                    let mut builder = TrayIconBuilder::new()
                        .with_menu(Box::new(menu))
                        .with_icon(icon)
                        .with_title("eGuard");
                    if let Some(tooltip) = current_tooltip() {
                        builder = builder.with_tooltip(tooltip);
                    }
                    tray_icon = Some(builder.build().expect("create tray icon"));
                }
            }
            Event::UserEvent(TrayUserEvent::Menu(event)) => {
                if let Err(err) = handle_menu_event(&mut state, event.id()) {
                    if err.to_string().contains("quit requested") {
                        *control_flow = ControlFlow::Exit;
                    } else {
                        error!(error = %err, "tray menu action failed");
                    }
                }
                refresh_menu(&mut state, tray_icon.as_mut());
            }
            Event::UserEvent(TrayUserEvent::Tray) => {
                refresh_tray_visuals(&state, tray_icon.as_mut());
            }
            _ => {}
        }
    })
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
}

impl TrayUiState {
    fn new() -> Result<Self> {
        Ok(Self {
            actions: Vec::new(),
            connected_icon: Some(build_status_icon(true)?),
            disconnected_icon: Some(build_status_icon(false)?),
        })
    }
}

#[derive(Clone)]
enum MenuAction {
    LaunchBookmarkDefault { app_id: String },
    LaunchBookmarkWithLauncher { app_id: String, launcher: String },
    ToggleFavorite { app_id: String },
    DisconnectSession(String),
    CleanupPamLaunch(i64),
    CleanupAllPamLaunches,
    DisconnectAll,
    Refresh,
    Quit,
}

impl MenuAction {
    fn id(&self) -> String {
        match self {
            MenuAction::LaunchBookmarkDefault { app_id } => format!("app-launch-default:{app_id}"),
            MenuAction::LaunchBookmarkWithLauncher { app_id, launcher } => {
                format!("app-launch:{app_id}:{launcher}")
            }
            MenuAction::ToggleFavorite { app_id } => format!("app-favorite:{app_id}"),
            MenuAction::DisconnectSession(session_id) => format!("session-disconnect:{session_id}"),
            MenuAction::CleanupPamLaunch(checkout_id) => format!("pam-cleanup:{checkout_id}"),
            MenuAction::CleanupAllPamLaunches => "action-cleanup-all-pam".to_string(),
            MenuAction::DisconnectAll => "action-disconnect-all".to_string(),
            MenuAction::Refresh => "action-refresh".to_string(),
            MenuAction::Quit => "action-quit".to_string(),
        }
    }
}

fn build_menu() -> Result<(Menu, Vec<MenuAction>)> {
    let bookmarks = BookmarkState::load_default().context("load bookmarks for tray")?;
    let sessions = effective_sessions(&bookmarks).context("load effective sessions for tray")?;
    let pam_launches = PamLaunchState::load_default().unwrap_or_default();
    let preferences = TrayPreferences::load_default().unwrap_or_default();

    let menu = Menu::new();
    let mut actions = Vec::new();

    let connection_label = if sessions.is_empty() {
        "Status: Not connected".to_string()
    } else if sessions.len() == 1 {
        "Status: Connected · 1 active session".to_string()
    } else {
        format!("Status: Connected · {} active sessions", sessions.len())
    };
    menu.append(&MenuItem::new(&connection_label, false, None))?;
    menu.append(&PredefinedMenuItem::separator())?;

    let favorites_menu = Submenu::new("Favorites", true);
    let favorite_bookmarks: Vec<_> = bookmarks
        .bookmarks
        .iter()
        .filter(|bookmark| preferences.is_favorite(&bookmark.app_id))
        .collect();
    if favorite_bookmarks.is_empty() {
        favorites_menu.append(&MenuItem::new("No pinned favorites", false, None))?;
    } else {
        for bookmark in favorite_bookmarks {
            let app_menu = build_bookmark_submenu(bookmark, &pam_launches, &preferences, &mut actions)?;
            favorites_menu.append(&app_menu)?;
        }
    }
    menu.append(&favorites_menu)?;

    let recent_menu = Submenu::new("Recent PAM Targets", true);
    let recent_entries: Vec<_> = preferences
        .recent_launches
        .iter()
        .filter(|entry| entry.pam)
        .collect();
    if recent_entries.is_empty() {
        recent_menu.append(&MenuItem::new("No recent PAM launches", false, None))?;
    } else {
        for recent in recent_entries {
            let Some(bookmark) = bookmarks
                .bookmarks
                .iter()
                .find(|bookmark| bookmark.app_id == recent.app_id)
            else {
                continue;
            };
            let launcher = recent.launcher.as_deref();
            let action = match launcher {
                Some(value) if !value.trim().is_empty() && !value.eq_ignore_ascii_case("ssh") && !value.eq_ignore_ascii_case("openssh") => {
                    MenuAction::LaunchBookmarkWithLauncher {
                        app_id: bookmark.app_id.clone(),
                        launcher: value.to_string(),
                    }
                }
                _ => MenuAction::LaunchBookmarkDefault {
                    app_id: bookmark.app_id.clone(),
                },
            };
            let label = format!(
                "{} -> {}{}",
                app_label(bookmark, LaunchRequest::parse(&bookmark.launch_uri).ok().as_ref()),
                blank_fallback(&recent.target, "unknown"),
                recent_launcher_suffix(recent),
            );
            let item = MenuItem::with_id(action.id(), label, bookmark.launcher_supported, None);
            actions.push(action);
            recent_menu.append(&item)?;
        }
    }
    menu.append(&recent_menu)?;

    let apps_menu = Submenu::new("Applications", true);
    if bookmarks.bookmarks.is_empty() {
        apps_menu.append(&MenuItem::new("No applications", false, None))?;
    } else {
        for bookmark in &bookmarks.bookmarks {
            let app_menu = build_bookmark_submenu(bookmark, &pam_launches, &preferences, &mut actions)?;
            apps_menu.append(&app_menu)?;
        }
    }
    menu.append(&apps_menu)?;

    let sessions_menu = Submenu::new("Active Sessions", true);
    if sessions.is_empty() {
        sessions_menu.append(&MenuItem::new("No active sessions", false, None))?;
    } else {
        for session in &sessions {
            let session_menu = Submenu::new(session.app_name_or_app_id(), true);
            let stats = format_session_stats(session);
            session_menu.append(&MenuItem::new(&stats, false, None))?;
            session_menu.append(&MenuItem::new(
                format!("Transport: {}", blank_fallback(&session.transport, "unknown")),
                false,
                None,
            ))?;
            session_menu.append(&MenuItem::new(
                format!("Status: {}", blank_fallback(&session.status, "unknown")),
                false,
                None,
            ))?;
            if !session.session_id.trim().is_empty() {
                session_menu.append(&PredefinedMenuItem::separator())?;
                let action = MenuAction::DisconnectSession(session.session_id.clone());
                let item = MenuItem::with_id(
                    action.id(),
                    format!("Disconnect {}", session.app_name_or_app_id()),
                    true,
                    None,
                );
                actions.push(action);
                session_menu.append(&item)?;
            }
            sessions_menu.append(&session_menu)?;
        }
    }
    menu.append(&sessions_menu)?;

    let pam_menu = Submenu::new("PAM Launches", true);
    if pam_launches.entries.is_empty() {
        pam_menu.append(&MenuItem::new("No tracked PAM launches", false, None))?;
    } else {
        for entry in &pam_launches.entries {
            let entry_menu = Submenu::new(
                format!("{} · {}", entry.app_id, entry.launcher_kind.to_ascii_uppercase()),
                true,
            );
            entry_menu.append(&MenuItem::new(
                format!("Target: {}", blank_fallback(&entry.target_host, "unknown")),
                false,
                None,
            ))?;
            if let Some(pid) = entry.process_id {
                entry_menu.append(&MenuItem::new(format!("PID: {pid}"), false, None))?;
            }
            entry_menu.append(&PredefinedMenuItem::separator())?;
            let action = MenuAction::CleanupPamLaunch(entry.checkout_id);
            let item = MenuItem::with_id(
                action.id(),
                format!("Force Check-in / Cleanup #{}", entry.checkout_id),
                true,
                None,
            );
            actions.push(action);
            entry_menu.append(&item)?;
            pam_menu.append(&entry_menu)?;
        }
        pam_menu.append(&PredefinedMenuItem::separator())?;
        let action = MenuAction::CleanupAllPamLaunches;
        let item = MenuItem::with_id(action.id(), "Cleanup All PAM Launches", true, None);
        actions.push(action);
        pam_menu.append(&item)?;
    }
    menu.append(&pam_menu)?;

    menu.append(&PredefinedMenuItem::separator())?;

    let disconnect_all = MenuItem::with_id(
        MenuAction::DisconnectAll.id(),
        "Disconnect All Sessions",
        !sessions.is_empty(),
        None,
    );
    actions.push(MenuAction::DisconnectAll);
    menu.append(&disconnect_all)?;

    let refresh_action = MenuAction::Refresh;
    let refresh = MenuItem::with_id(refresh_action.id(), "Refresh", true, None);
    actions.push(refresh_action);
    menu.append(&refresh)?;

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

    if let Some(request) = parsed.as_ref() {
        menu.append(&MenuItem::new(format!("Target: {}", request.target), false, None))?;
        if let Some(user) = request.user.as_deref().filter(|value| !value.trim().is_empty()) {
            menu.append(&MenuItem::new(format!("User: {user}"), false, None))?;
        }
        if request.credential_id.is_some() {
            menu.append(&MenuItem::new("Auth: PAM credential bound", false, None))?;
        }
    } else if let Some(target_host) = bookmark.target_host.as_deref() {
        menu.append(&MenuItem::new(format!("Target: {target_host}"), false, None))?;
    }

    menu.append(&MenuItem::new(
        format!("Health: {}", blank_fallback(&bookmark.health_status, "unknown")),
        false,
        None,
    ))?;
    menu.append(&MenuItem::new(
        format!("Pinned: {}", if preferences.is_favorite(&bookmark.app_id) { "Yes" } else { "No" }),
        false,
        None,
    ))?;
    if active_pam_for_app.is_empty() {
        menu.append(&MenuItem::new("PAM: No active local launch", false, None))?;
    } else if active_pam_for_app.len() == 1 {
        let entry = active_pam_for_app[0];
        menu.append(&MenuItem::new(
            format!("PAM: Active via {} (checkout #{})", entry.launcher_kind, entry.checkout_id),
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
        menu.append(&MenuItem::new("Launcher not available on this endpoint", false, None))?;
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
            append_variant_action(bookmark, menu, actions, "html5", ssh_variant_label("html5", request), ssh_variant_enabled("html5", request))?;
            append_variant_action(bookmark, menu, actions, "putty", ssh_variant_label("putty", request), ssh_variant_enabled("putty", request))?;
        }
        "rdp" => {
            append_variant_action(bookmark, menu, actions, "rdp", launch_label_with_pam("Launch in Remote Desktop", request), rdp_available())?;
        }
        "web" | "http" | "https" => {
            append_variant_action(bookmark, menu, actions, "browser", launch_label_with_pam("Open in Browser", request), true)?;
        }
        "vnc" => {
            append_variant_action(bookmark, menu, actions, "vnc", launch_label_with_pam("Launch in VNC Viewer", request), vnc_available())?;
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
    std::env::split_paths(&path).any(|dir| candidates.iter().any(|candidate| dir.join(candidate).is_file()))
}

fn recent_launcher_suffix(entry: &RecentLaunchEntry) -> String {
    entry
        .launcher
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!(" via {}", value.to_ascii_uppercase()))
        .unwrap_or_default()
}

fn blank_fallback<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    }
}

fn refresh_menu(state: &mut TrayUiState, tray_icon: Option<&mut tray_icon::TrayIcon>) {
    if let Ok((menu, actions)) = build_menu() {
        state.actions = actions;
        if let Some(icon) = tray_icon {
            let _ = icon.set_menu(Some(Box::new(menu)));
            refresh_tray_visuals(state, Some(icon));
        }
    }
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
    match action {
        MenuAction::LaunchBookmarkDefault { app_id } => {
            launch_bookmark_from_menu(&app_id, None)?;
        }
        MenuAction::LaunchBookmarkWithLauncher { app_id, launcher } => {
            launch_bookmark_from_menu(&app_id, Some(&launcher))?;
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
            let bookmark_snapshot = snapshot_bookmark_cache()?;
            let session_snapshot = snapshot_session_cache()?;
            queue_command(TrayCommand::Refresh)?;
            wait_for_bookmark_cache_update(&bookmark_snapshot, Duration::from_secs(6))?;
            let _ = wait_for_session_cache_update(&session_snapshot, Duration::from_secs(6));
        }
        MenuAction::Quit => anyhow::bail!("quit requested"),
    }
    Ok(())
}

fn launch_bookmark_from_menu(app_id: &str, launcher_override: Option<&str>) -> Result<()> {
    let bookmarks = BookmarkState::load_default()?;
    if let Some(bookmark) = bookmarks
        .bookmarks
        .into_iter()
        .find(|entry| entry.app_id == app_id)
    {
        let parsed = LaunchRequest::parse(&bookmark.launch_uri)
            .with_context(|| format!("parse launch uri for {}", bookmark.app_id))?;
        let session_snapshot = snapshot_session_cache()?;
        queue_command(TrayCommand::OpenApp {
            app_id: app_id.to_string(),
            forward_host: bookmark.target_host.clone(),
            forward_port: bookmark.target_port.map(|port| port as u16),
        })?;
        let _ = wait_for_session_cache_update(&session_snapshot, Duration::from_secs(8));

        let mut effective_request = parsed.clone();
        if let Some(launcher) = launcher_override {
            effective_request.launcher = Some(launcher.to_string());
        }
        record_recent_launch(&bookmark, &effective_request)?;

        if launcher_override.is_some() {
            launch_launch_request_with_session_fallback(&effective_request)
        } else {
            launch_bookmark(&bookmark)
        }
    } else {
        Ok(())
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
    let mut queue = TrayCommandQueue::load_default()?;
    queue.push(command);
    queue.save_default()
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
    let sessions = effective_sessions(&bookmarks).ok()?;
    if sessions.is_empty() {
        return Some("eGuard ZTNA\nStatus: Not connected".to_string());
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
        "eGuard ZTNA\nStatus: Connected ({})\nIncoming: {}\nOutgoing: {}",
        sessions.len(),
        format_bytes(total_rx),
        format_bytes(total_tx)
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
        let resized = image::imageops::resize(&image, 16, 16, image::imageops::FilterType::Lanczos3);
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
    #[cfg(target_os = "windows")]
    {
        return SingleInstanceGuard::already_running();
    }

    #[allow(unreachable_code)]
    false
}

#[cfg(target_os = "windows")]
struct SingleInstanceGuard {
    handle: HANDLE,
}

#[cfg(not(target_os = "windows"))]
struct SingleInstanceGuard;

impl SingleInstanceGuard {
    fn acquire() -> Result<Self> {
        #[cfg(target_os = "windows")]
        {
            let handle = unsafe { CreateMutexW(None, false, w!("Local\\eGuardTraySingleton")) }
                .context("create tray single-instance mutex")?;
            if handle.is_invalid() {
                return Err(anyhow::anyhow!("create tray single-instance mutex"));
            }

            let last_error = unsafe { GetLastError() };
            if last_error == ERROR_ALREADY_EXISTS {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                anyhow::bail!("eguard-tray is already running");
            }

            return Ok(Self { handle });
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok(Self)
        }
    }

    fn already_running() -> bool {
        #[cfg(target_os = "windows")]
        {
            let Ok(handle) =
                (unsafe { CreateMutexW(None, false, w!("Local\\eGuardTraySingleton")) })
            else {
                return false;
            };
            if handle.is_invalid() {
                return false;
            }

            let already_running = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
            unsafe {
                let _ = CloseHandle(handle);
            }
            return already_running;
        }

        #[allow(unreachable_code)]
        false
    }
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

fn effective_sessions(bookmarks: &BookmarkState) -> Result<Vec<crate::state::SessionEntry>> {
    let state = SessionState::load_default().unwrap_or_default();
    if !state.sessions.is_empty() {
        return Ok(state.sessions);
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(session) = session_from_wireguard(bookmarks)? {
            return Ok(vec![session]);
        }
    }

    Ok(Vec::new())
}

#[cfg(target_os = "windows")]
fn session_from_wireguard(bookmarks: &BookmarkState) -> Result<Option<crate::state::SessionEntry>> {
    let output = Command::new(r"C:\Program Files\WireGuard\wg.exe")
        .arg("show")
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
