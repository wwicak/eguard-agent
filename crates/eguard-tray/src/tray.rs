use anyhow::{Context, Result};
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

use crate::app::open_admin_ui;
use crate::launcher::launch_bookmark;
use crate::state::{BookmarkState, SessionState, TrayCommand, TrayCommandQueue};

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
                    let icon = default_icon().expect("build tray icon");
                    tray_icon = Some(
                        TrayIconBuilder::new()
                            .with_tooltip("eGuard ZTNA")
                            .with_menu(Box::new(menu))
                            .with_icon(icon)
                            .with_title("eGuard")
                            .build()
                            .expect("create tray icon"),
                    );
                }
            }
            Event::UserEvent(TrayUserEvent::Menu(event)) => {
                if handle_menu_event(&mut state, event.id()).is_err() {
                    *control_flow = ControlFlow::Exit;
                }
                if let Ok((menu, actions)) = build_menu() {
                    state.actions = actions;
                    if let Some(icon) = tray_icon.as_mut() {
                        let _ = icon.set_menu(Some(Box::new(menu)));
                    }
                }
            }
            Event::UserEvent(TrayUserEvent::Tray) => {}
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
}

impl TrayUiState {
    fn new() -> Result<Self> {
        Ok(Self {
            actions: Vec::new(),
        })
    }
}

#[derive(Clone)]
enum MenuAction {
    LaunchBookmark(String),
    DisconnectSession(String),
    DisconnectAll,
    DisableTransport,
    EnableTransport,
    Refresh,
    RegisterProtocol,
    OpenAdminUi,
    Quit,
}

fn build_menu() -> Result<(Menu, Vec<MenuAction>)> {
    let bookmarks = BookmarkState::load_default().context("load bookmarks for tray")?;
    let sessions = SessionState::load_default().context("load sessions for tray")?;

    let menu = Menu::new();
    let mut actions = Vec::new();

    let bookmarks_menu = Submenu::new("Bookmarks", true);
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
    if sessions.sessions.is_empty() {
        sessions_menu.append(&MenuItem::new("No active sessions", false, None))?;
    } else {
        for (index, session) in sessions.sessions.iter().enumerate() {
            let item = MenuItem::with_id(
                format!("session-{index}"),
                format!("{} ({})", session.app_name_or_app_id(), session.session_id),
                true,
                None,
            );
            actions.push(MenuAction::DisconnectSession(session.session_id.clone()));
            sessions_menu.append(&item)?;
        }
    }
    menu.append(&sessions_menu)?;

    menu.append(&PredefinedMenuItem::separator())?;

    let disconnect_all = MenuItem::with_id("action-disconnect-all", "Disconnect All", true, None);
    actions.push(MenuAction::DisconnectAll);
    menu.append(&disconnect_all)?;

    let disable_transport =
        MenuItem::with_id("action-disable-transport", "Disable Transport", true, None);
    actions.push(MenuAction::DisableTransport);
    menu.append(&disable_transport)?;

    let enable_transport =
        MenuItem::with_id("action-enable-transport", "Enable Transport", true, None);
    actions.push(MenuAction::EnableTransport);
    menu.append(&enable_transport)?;

    let refresh = MenuItem::with_id("action-refresh", "Refresh", true, None);
    actions.push(MenuAction::Refresh);
    menu.append(&refresh)?;

    let register_protocol =
        MenuItem::with_id("action-register-protocol", "Register Protocol", true, None);
    actions.push(MenuAction::RegisterProtocol);
    menu.append(&register_protocol)?;

    let open_admin = MenuItem::with_id("action-open-admin", "Open Admin UI", true, None);
    actions.push(MenuAction::OpenAdminUi);
    menu.append(&open_admin)?;

    menu.append(&PredefinedMenuItem::separator())?;

    let quit = MenuItem::with_id("action-quit", "Quit", true, None);
    actions.push(MenuAction::Quit);
    menu.append(&quit)?;

    Ok((menu, actions))
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
            queue_command(TrayCommand::OpenApp {
                app_id: app_id.clone(),
            })?;
            let bookmarks = BookmarkState::load_default()?;
            if let Some(bookmark) = bookmarks
                .bookmarks
                .into_iter()
                .find(|entry| entry.app_id == app_id)
            {
                launch_bookmark(&bookmark)?;
            }
        }
        MenuAction::DisconnectSession(session_id) => {
            queue_command(TrayCommand::Disconnect { session_id })?
        }
        MenuAction::DisconnectAll => queue_command(TrayCommand::DisconnectAll)?,
        MenuAction::DisableTransport => queue_command(TrayCommand::DisableTransport)?,
        MenuAction::EnableTransport => queue_command(TrayCommand::EnableTransport)?,
        MenuAction::Refresh => queue_command(TrayCommand::Refresh)?,
        MenuAction::RegisterProtocol => {
            crate::protocol::register_protocol_handler(current_exe_string()?)?
        }
        MenuAction::OpenAdminUi => open_admin_ui()?,
        MenuAction::Quit => anyhow::bail!("quit requested"),
    }
    Ok(())
}

fn action_matches_id(action: &MenuAction, raw: &str) -> bool {
    matches!(
        (action, raw),
        (MenuAction::DisconnectAll, "action-disconnect-all")
            | (MenuAction::DisableTransport, "action-disable-transport")
            | (MenuAction::EnableTransport, "action-enable-transport")
            | (MenuAction::Refresh, "action-refresh")
            | (MenuAction::RegisterProtocol, "action-register-protocol")
            | (MenuAction::OpenAdminUi, "action-open-admin")
            | (MenuAction::Quit, "action-quit")
    )
}

fn queue_command(command: TrayCommand) -> Result<()> {
    let mut queue = TrayCommandQueue::load_default()?;
    queue.push(command);
    queue.save_default()
}

fn current_exe_string() -> Result<String> {
    Ok(std::env::current_exe()?.to_string_lossy().into_owned())
}

fn default_icon() -> Result<Icon> {
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
    Icon::from_rgba(rgba, 32, 32).context("build tray icon rgba")
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
