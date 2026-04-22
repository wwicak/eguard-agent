use anyhow::{Context, Result};
use std::time::Duration;

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

use crate::launcher::launch_bookmark;
use crate::state::{
    snapshot_bookmark_cache, snapshot_session_cache, wait_for_bookmark_cache_update,
    wait_for_session_cache_update, BookmarkState, SessionState, TrayCommand, TrayCommandQueue,
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
                if handle_menu_event(&mut state, event.id()).is_err() {
                    *control_flow = ControlFlow::Exit;
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
    LaunchBookmark(String),
    DisconnectSession(String),
    DisconnectAll,
    Refresh,
    Quit,
}

fn build_menu() -> Result<(Menu, Vec<MenuAction>)> {
    let bookmarks = BookmarkState::load_default().context("load bookmarks for tray")?;
    let sessions = effective_sessions(&bookmarks).context("load effective sessions for tray")?;

    let menu = Menu::new();
    let mut actions = Vec::new();

    let connection_label = if sessions.is_empty() {
        "Status: Not connected".to_string()
    } else if sessions.len() == 1 {
        format!("Status: Connected · 1 active session")
    } else {
        format!("Status: Connected · {} active sessions", sessions.len())
    };
    menu.append(&MenuItem::new(&connection_label, false, None))?;
    menu.append(&PredefinedMenuItem::separator())?;

    let bookmarks_menu = Submenu::new("Applications", true);
    if bookmarks.bookmarks.is_empty() {
        bookmarks_menu.append(&MenuItem::new("No bookmarks", false, None))?;
    } else {
        for (index, bookmark) in bookmarks.bookmarks.iter().enumerate() {
            let item = MenuItem::with_id(
                format!("bookmark-{index}"),
                &bookmark.name,
                bookmark.launcher_supported,
                None,
            );
            actions.push(MenuAction::LaunchBookmark(bookmark.app_id.clone()));
            bookmarks_menu.append(&item)?;
        }
    }
    menu.append(&bookmarks_menu)?;

    let sessions_menu = Submenu::new("Active Sessions", true);
    if sessions.is_empty() {
        sessions_menu.append(&MenuItem::new("No active sessions", false, None))?;
    } else {
        for (index, session) in sessions.iter().enumerate() {
            let stats = format_session_stats(session);
            sessions_menu.append(&MenuItem::new(
                format!("{}{}", session.app_name_or_app_id(), stats),
                false,
                None,
            ))?;
            if !session.session_id.trim().is_empty() {
                let item = MenuItem::with_id(
                    format!("session-{index}"),
                    format!("Disconnect {}", session.app_name_or_app_id()),
                    true,
                    None,
                );
                actions.push(MenuAction::DisconnectSession(session.session_id.clone()));
                sessions_menu.append(&item)?;
            }
        }
    }
    menu.append(&sessions_menu)?;

    menu.append(&PredefinedMenuItem::separator())?;

    let disconnect_all = MenuItem::with_id(
        "action-disconnect-all",
        "Disconnect All Sessions",
        !sessions.is_empty(),
        None,
    );
    actions.push(MenuAction::DisconnectAll);
    menu.append(&disconnect_all)?;

    let refresh = MenuItem::with_id("action-refresh", "Refresh", true, None);
    actions.push(MenuAction::Refresh);
    menu.append(&refresh)?;

    menu.append(&PredefinedMenuItem::separator())?;

    let quit = MenuItem::with_id("action-quit", "Quit", true, None);
    actions.push(MenuAction::Quit);
    menu.append(&quit)?;

    Ok((menu, actions))
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
    let action = if let Some(index) = raw
        .strip_prefix("bookmark-")
        .and_then(|value| value.parse::<usize>().ok())
    {
        state
            .actions
            .get(index)
            .cloned()
            .context("resolve bookmark tray action")?
    } else if let Some(index) = raw
        .strip_prefix("session-")
        .and_then(|value| value.parse::<usize>().ok())
    {
        let offset = BookmarkState::load_default()?.bookmarks.len();
        state
            .actions
            .get(offset + index)
            .cloned()
            .context("resolve session tray action")?
    } else {
        state
            .actions
            .iter()
            .find(|action| action_matches_id(action, raw))
            .cloned()
            .context("resolve fixed tray action")?
    };
    match action {
        MenuAction::LaunchBookmark(app_id) => {
            let bookmarks = BookmarkState::load_default()?;
            if let Some(bookmark) = bookmarks
                .bookmarks
                .into_iter()
                .find(|entry| entry.app_id == app_id)
            {
                let session_snapshot = snapshot_session_cache()?;
                queue_command(TrayCommand::OpenApp {
                    app_id: app_id.clone(),
                    forward_host: bookmark.target_host.clone(),
                    forward_port: bookmark.target_port.map(|port| port as u16),
                })?;
                let _ = wait_for_session_cache_update(&session_snapshot, Duration::from_secs(8));
                launch_bookmark(&bookmark)?;
            }
        }
        MenuAction::DisconnectSession(session_id) => {
            let session_snapshot = snapshot_session_cache()?;
            queue_command(TrayCommand::Disconnect { session_id })?;
            let _ = wait_for_session_cache_update(&session_snapshot, Duration::from_secs(8));
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

fn action_matches_id(action: &MenuAction, raw: &str) -> bool {
    matches!(
        (action, raw),
        (MenuAction::DisconnectAll, "action-disconnect-all")
            | (MenuAction::Refresh, "action-refresh")
            | (MenuAction::Quit, "action-quit")
    )
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
