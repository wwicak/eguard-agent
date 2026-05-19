use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use std::{os::windows::process::CommandExt, process::Stdio};

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

use anyhow::{anyhow, Context, Result};
use pam::{
    launch_ssh_request, BastionSessionRecord, BastionSessionRequest, BrowserTerminalSessionRequest,
    CheckoutRequest, PamHttpClient, SecretString, SshLaunchRequest,
};
use tracing::warn;

use crate::app::open_external_url;
use crate::protocol::LaunchRequest;
use crate::state::{
    clear_launch_request_entry, upsert_launch_request_entry, BookmarkEntry, BookmarkState,
    LaunchRequestEntry, LaunchRequestState, PamLaunchEntry, PamLaunchState, SessionState,
};

#[cfg(target_os = "windows")]
fn configure_hidden_console_command(cmd: &mut Command) {
    cmd.creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
}

pub fn launch_bookmark(bookmark: &BookmarkEntry) -> Result<()> {
    let request = LaunchRequest::parse(&bookmark.launch_uri)
        .with_context(|| format!("parse launch uri for {}", bookmark.app_id))?;
    launch_with_session_fallback(&bookmark.app_id, &request)
}

pub fn launch_launch_request_with_session_fallback(request: &LaunchRequest) -> Result<()> {
    launch_with_session_fallback(&request.app_id, request)
}

pub fn launch_launch_request(request: &LaunchRequest) -> Result<()> {
    if prefers_bastion_launcher(request) {
        return launch_bastion_session(request);
    }
    match normalized_app_type(&request.app_type).as_str() {
        "ssh" => launch_ssh(request),
        "rdp" => launch_rdp(request),
        "vnc" => launch_vnc(request),
        "web" | "https" | "http" => open_external_url(&request.target),
        other => Err(anyhow!("unsupported launch target `{other}`")),
    }
}

pub fn reconcile_pending_launch_requests() -> Result<()> {
    let state = LaunchRequestState::load_default()?;
    let waiting: Vec<_> = state
        .entries
        .into_iter()
        .filter(|entry| {
            entry.status.eq_ignore_ascii_case("waiting_for_approval")
                && entry.checkout_id.unwrap_or_default() > 0
        })
        .collect();
    if waiting.is_empty() {
        return Ok(());
    }
    let base_url = match resolve_server_base_url() {
        Some(value) => value,
        None => return Ok(()),
    };
    let client = PamHttpClient::new(base_url)?;
    let envelope = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(client.list_checkouts()))?
    } else {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(client.list_checkouts())?
    };
    let bookmarks = BookmarkState::load_default()?;
    for entry in waiting {
        let Some(checkout_id) = entry.checkout_id else {
            continue;
        };
        let Some(checkout) = envelope
            .checkouts
            .iter()
            .find(|item| item.id == checkout_id)
        else {
            continue;
        };
        match checkout.status.trim().to_ascii_lowercase().as_str() {
            "active" => {
                if let Some(bookmark) = bookmarks
                    .bookmarks
                    .iter()
                    .find(|bookmark| bookmark.app_id == entry.app_id)
                    .cloned()
                {
                    let mut request = LaunchRequest::parse(&bookmark.launch_uri)
                        .with_context(|| format!("parse launch uri for {}", bookmark.app_id))?;
                    request.launcher = entry.launcher.clone();
                    let _ = clear_launch_request_entry(&entry.app_id);
                    if let Err(err) = launch_launch_request_with_session_fallback(&request) {
                        let _ = upsert_launch_request_entry(LaunchRequestEntry::failed(
                            &entry.app_id,
                            &entry.target,
                            entry.launcher.as_deref(),
                            err.to_string(),
                        ));
                    }
                }
            }
            "denied" | "expired" | "revoked" | "completed" => {
                let _ = upsert_launch_request_entry(LaunchRequestEntry::failed(
                    &entry.app_id,
                    &entry.target,
                    entry.launcher.as_deref(),
                    format!("Request {}", checkout.status.trim()),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn cleanup_pam_launch(checkout_id: i64) -> Result<()> {
    cleanup_pam_launch_with_reason(checkout_id, Some("manual_cleanup"))
}

pub fn cleanup_all_pam_launches() -> Result<()> {
    cleanup_all_pam_launches_with_reason(Some("manual_cleanup"))
}

pub fn reconcile_pam_launches_on_startup() -> Result<()> {
    cleanup_all_pam_launches_with_reason(Some("startup_recovery_cleanup"))
}

fn cleanup_pam_launch_with_reason(checkout_id: i64, reason: Option<&str>) -> Result<()> {
    let mut state = PamLaunchState::load_default()?;
    let entry = state
        .entries
        .iter()
        .find(|entry| entry.checkout_id == checkout_id)
        .cloned()
        .ok_or_else(|| anyhow!("pam launch `{checkout_id}` not found"))?;
    force_cleanup_entry(&entry, reason);
    state
        .entries
        .retain(|existing| existing.checkout_id != checkout_id);
    state.save_default()
}

fn cleanup_all_pam_launches_with_reason(reason: Option<&str>) -> Result<()> {
    let mut state = PamLaunchState::load_default()?;
    for entry in &state.entries {
        force_cleanup_entry(entry, reason);
    }
    state.entries.clear();
    state.save_default()
}

fn launch_with_session_fallback(app_id: &str, request: &LaunchRequest) -> Result<()> {
    match normalized_app_type(&request.app_type).as_str() {
        "web" | "https" | "http" => {
            let target = wait_for_web_launch_target(app_id, &request.target);
            open_external_url(&target)
        }
        "ssh" | "rdp" | "vnc" => {
            let resolved = resolve_request_via_local_forward(app_id, request);
            launch_launch_request(&resolved)
        }
        _ => launch_launch_request(request),
    }
}

fn normalized_app_type(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn resolve_request_via_local_forward(app_id: &str, request: &LaunchRequest) -> LaunchRequest {
    let Some((host, port)) = wait_for_forwarded_launch_target(app_id, request) else {
        return request.clone();
    };
    let mut resolved = request.clone();
    resolved.target = host;
    resolved.port = Some(port);
    resolved
}

fn launch_ssh(request: &LaunchRequest) -> Result<()> {
    if prefers_browser_terminal(request) {
        return launch_browser_terminal(request);
    }
    let checked_out = maybe_checkout_password(request)?;
    let effective_user = checked_out
        .as_ref()
        .map(|value| value.username.clone())
        .or_else(|| request.user.clone());
    let outcome = launch_ssh_request(&SshLaunchRequest {
        target: request.target.clone(),
        port: request.port,
        user: effective_user,
        launcher: request.launcher.clone(),
        password: checked_out.as_ref().and_then(|value| {
            value
                .password
                .as_ref()
                .map(|secret| secret.expose().to_string())
        }),
        private_key_pem: checked_out.as_ref().and_then(|value| {
            value
                .private_key_pem
                .as_ref()
                .map(|secret| secret.expose().to_string())
        }),
        passphrase: checked_out.as_ref().and_then(|value| {
            value
                .passphrase
                .as_ref()
                .map(|secret| secret.expose().to_string())
        }),
    })?;
    if let Some(state) = checked_out {
        if let Some(child) = outcome.child {
            let cleanup_paths: Vec<String> = outcome
                .cleanup_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect();
            record_pam_launch(
                state.checkout_id,
                &request.app_id,
                "ssh",
                child.id(),
                &request.target,
                &cleanup_paths,
                Some(&state.base_url),
            )?;
            spawn_ssh_checkin_watcher(
                state.base_url,
                state.checkout_id,
                child,
                outcome.cleanup_paths,
            );
        }
    }
    Ok(())
}

fn launch_bastion_session(request: &LaunchRequest) -> Result<()> {
    let _ = upsert_launch_request_entry(LaunchRequestEntry::connecting_bastion(
        &request.app_id,
        &request.target,
        request.launcher.as_deref(),
    ));
    let base_url = resolve_server_base_url()
        .ok_or_else(|| anyhow!("resolve server base url for bastion session"))?;
    let agent_id =
        resolve_agent_id().ok_or_else(|| anyhow!("resolve agent id for bastion session"))?;
    let client = PamHttpClient::new(base_url)?;
    let envelope = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(client.create_bastion_session(
            &BastionSessionRequest {
                agent_id,
                app_id: request.app_id.clone(),
            },
        ))
    })?;
    if let Some(session) = envelope.session.as_ref() {
        let mode = session.proxy_mode.trim().to_ascii_lowercase();
        let has_proxy_fields = bastion_session_has_proxy_fields(session);
        let assisted_direct = should_launch_rdp_assisted_direct(request, session);
        if mode == "rdp_assisted_direct" || has_proxy_fields || assisted_direct {
            let outcome = if assisted_direct {
                launch_rdp_assisted_direct_bastion(request, session)
            } else if mode == "rdp_proxy" || normalized_app_type(&request.app_type) == "rdp" {
                launch_rdp_proxy_session(request, session)
            } else {
                launch_ssh_request(&SshLaunchRequest {
                    target: session.proxy_host.trim().to_string(),
                    port: Some(session.proxy_port as u16),
                    user: Some(session.proxy_username.trim().to_string()),
                    launcher: Some("putty".to_string()),
                    password: Some(if !session.proxy_password.trim().is_empty() {
                        session.proxy_password.trim().to_string()
                    } else {
                        session.access_token.trim().to_string()
                    }),
                    private_key_pem: None,
                    passphrase: None,
                })
                .map(|_| ())
            };
            if outcome.is_ok() {
                let _ = clear_launch_request_entry(&request.app_id);
            }
            return outcome;
        }
    }
    let launch_url = resolve_bastion_browser_launch_url(request, &envelope)
        .ok_or_else(|| anyhow!("bastion session missing browser launch URL or proxy metadata"))?;
    let open_result = open_external_url(&launch_url);
    if open_result.is_ok() {
        let _ = clear_launch_request_entry(&request.app_id);
    }
    open_result
}

fn bastion_session_has_proxy_fields(session: &BastionSessionRecord) -> bool {
    !session.proxy_host.trim().is_empty()
        && session.proxy_port > 0
        && !session.proxy_username.trim().is_empty()
}

fn should_launch_rdp_assisted_direct(
    request: &LaunchRequest,
    session: &BastionSessionRecord,
) -> bool {
    normalized_app_type(&request.app_type) == "rdp"
        && !bastion_session_has_proxy_fields(session)
        && session.launch_url.trim().is_empty()
}

fn resolve_bastion_browser_launch_url(
    request: &LaunchRequest,
    envelope: &pam::BastionSessionEnvelope,
) -> Option<String> {
    envelope
        .session
        .as_ref()
        .map(|value| value.launch_url.trim().to_string())
        .filter(|value| is_external_browser_url(value))
        .or_else(|| {
            envelope
                .profile
                .as_ref()
                .map(|value| value.web_launch_url.trim().to_string())
                .filter(|value| is_external_browser_url(value))
        })
        .or_else(|| {
            let target = request.target.trim().to_string();
            if is_external_browser_url(&target) {
                Some(target)
            } else {
                None
            }
        })
}

fn is_external_browser_url(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value.starts_with("http://") || value.starts_with("https://")
}

fn prefers_bastion_launcher(request: &LaunchRequest) -> bool {
    matches!(
        request.launcher.as_deref().map(|value| value.trim().to_ascii_lowercase()),
        Some(value) if value == "bastion_web" || value == "bastion-browser" || value == "bastion" || value == "bastion_ssh" || value == "bastion_rdp"
    )
}

fn prefers_browser_terminal(request: &LaunchRequest) -> bool {
    matches!(
        request.launcher.as_deref().map(|value| value.trim().to_ascii_lowercase()),
        Some(value) if value == "browser" || value == "html5" || value == "web"
    )
}

fn launch_browser_terminal(request: &LaunchRequest) -> Result<()> {
    let credential_id = request
        .credential_id
        .ok_or_else(|| anyhow!("browser terminal requires credential_id"))?;
    let base_url = resolve_server_base_url()
        .ok_or_else(|| anyhow!("resolve server base url for browser terminal"))?;
    let agent_id =
        resolve_agent_id().ok_or_else(|| anyhow!("resolve agent id for browser terminal"))?;
    let client = PamHttpClient::new(base_url)?;
    let envelope = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(client.create_browser_terminal_session(
            &BrowserTerminalSessionRequest {
                agent_id,
                app_id: request.app_id.clone(),
                credential_id,
                user_id: request.user.clone(),
                requested_duration_min: Some(60),
            },
        ))
    })?;
    let url = envelope.url.trim();
    if url.is_empty() {
        return Err(anyhow!("browser terminal missing launch url"));
    }
    open_external_url(url)
}

struct CheckedOutPassword {
    base_url: String,
    checkout_id: i64,
    username: String,
    password: Option<SecretString>,
    private_key_pem: Option<SecretString>,
    passphrase: Option<SecretString>,
}

fn maybe_checkout_password(request: &LaunchRequest) -> Result<Option<CheckedOutPassword>> {
    let Some(credential_id) = request.credential_id else {
        return Ok(None);
    };
    let base_url = resolve_server_base_url()
        .ok_or_else(|| anyhow!("resolve server base url for PAM checkout"))?;
    let agent_id =
        resolve_agent_id().ok_or_else(|| anyhow!("resolve agent id for PAM checkout"))?;
    let client = PamHttpClient::new(base_url.clone())?;
    let user_id = request.user.clone();
    let req = CheckoutRequest {
        agent_id,
        app_id: request.app_id.clone(),
        credential_id,
        user_id,
        reason: Some("tray_ssh_launch".to_string()),
        requested_duration_min: Some(60),
        source_ip: None,
        temp_token: request
            .temp_token
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
    };
    let envelope = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(client.checkout(&req))
    })?;
    if envelope.status.eq_ignore_ascii_case("pending_approval") {
        if let Some(checkout) = envelope.checkout.as_ref() {
            let target = request.target.clone();
            let _ = upsert_launch_request_entry(LaunchRequestEntry::waiting_for_approval(
                &request.app_id,
                checkout.id,
                &target,
                request.launcher.as_deref(),
                envelope.reason.as_deref(),
            ));
        }
        return Err(anyhow!("pam checkout pending approval"));
    }
    if envelope.status.eq_ignore_ascii_case("deny") {
        let message = envelope
            .reason
            .unwrap_or_else(|| "access_denied".to_string());
        let _ = upsert_launch_request_entry(LaunchRequestEntry::failed(
            &request.app_id,
            &request.target,
            request.launcher.as_deref(),
            format!("PAM denied: {message}"),
        ));
        return Err(anyhow!("pam checkout denied: {}", message));
    }
    let credential = envelope
        .credential
        .ok_or_else(|| anyhow!("pam checkout missing credential payload"))?;
    let checkout_id = envelope
        .checkout
        .as_ref()
        .map(|value| value.id)
        .ok_or_else(|| anyhow!("pam checkout missing checkout id"))?;
    if credential.password.trim().is_empty() && credential.private_key_pem.trim().is_empty() {
        return Ok(None);
    }
    let _ = clear_launch_request_entry(&request.app_id);
    Ok(Some(CheckedOutPassword {
        base_url,
        checkout_id,
        username: first_non_empty_string(
            &credential.username,
            request.user.as_deref().unwrap_or_default(),
        ),
        password: (!credential.password.trim().is_empty())
            .then(|| SecretString::new(credential.password)),
        private_key_pem: (!credential.private_key_pem.trim().is_empty())
            .then(|| SecretString::new(credential.private_key_pem)),
        passphrase: (!credential.passphrase.trim().is_empty())
            .then(|| SecretString::new(credential.passphrase)),
    }))
}

fn maybe_checkout_rdp_password(request: &LaunchRequest) -> Result<Option<CheckedOutPassword>> {
    maybe_checkout_password(request)
}

fn spawn_ssh_checkin_watcher(
    base_url: String,
    checkout_id: i64,
    mut child: std::process::Child,
    cleanup_paths: Vec<std::path::PathBuf>,
) {
    std::thread::spawn(move || {
        let _ = child.wait();
        for path in cleanup_paths {
            let _ = std::fs::remove_file(path);
        }
        clear_pam_launch(checkout_id);
        let Ok(client) = PamHttpClient::new(base_url) else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Runtime::new() {
            let _ = runtime.block_on(client.checkin(checkout_id, Some("ssh_client_exit")));
        }
    });
}

fn resolve_server_base_url() -> Option<String> {
    if let Ok(value) = std::env::var("EGUARD_SERVER_ADDR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(normalize_server_base_url(trimmed));
        }
    }
    if let Some(value) =
        read_key_value_config_line(r"C:\ProgramData\eGuard\bootstrap.conf", "address")
    {
        return Some(normalize_server_base_url(&value));
    }
    if let Some(value) = read_agent_conf_string("controller_base_url") {
        return Some(normalize_server_base_url(&value));
    }
    if let Some(value) = read_agent_conf_string("server_addr") {
        return Some(normalize_server_base_url(&value));
    }
    None
}

fn normalize_server_base_url(value: &str) -> String {
    let trimmed = value.trim().trim_matches('[').trim_matches(']');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.replace(":50053", ":50054");
    }
    if trimmed.ends_with(":50053") {
        return format!("https://{}", trimmed.replace(":50053", ":50054"));
    }
    if trimmed.contains(':') {
        return format!("https://{}", trimmed);
    }
    format!("https://{}:50054", trimmed)
}

fn resolve_agent_id() -> Option<String> {
    std::env::var("EGUARD_AGENT_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| read_agent_conf_string("id"))
}

fn read_key_value_config_line(path: &str, key: &str) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    for line in raw.lines() {
        let line = line.trim();
        let prefix = format!("{key} = ");
        if let Some(value) = line.strip_prefix(&prefix) {
            let trimmed = value.trim().trim_matches('"').trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn read_agent_conf_string(key: &str) -> Option<String> {
    let raw = std::fs::read_to_string(r"C:\ProgramData\eGuard\agent.conf").ok()?;
    let needle = format!("{key} = ");
    for line in raw.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix(&needle) {
            let trimmed = value.trim().trim_matches('"').trim_matches('\'').trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn bastion_proxy_session_uses_proxy_credentials(session: &BastionSessionRecord) -> bool {
    session
        .proxy_mode
        .trim()
        .eq_ignore_ascii_case("rdp_terminating_broker")
}

fn launch_rdp_proxy_session(request: &LaunchRequest, session: &BastionSessionRecord) -> Result<()> {
    if session
        .proxy_mode
        .trim()
        .eq_ignore_ascii_case("rdp_assisted_direct")
    {
        return launch_rdp_assisted_direct_bastion(request, session);
    }
    let proxy_target = session.proxy_host.trim();
    if proxy_target.is_empty()
        || session.proxy_port <= 0
        || session.proxy_username.trim().is_empty()
    {
        return Err(anyhow!(
            "rdp bastion proxy session missing connection metadata"
        ));
    }
    let proxy_request = LaunchRequest {
        app_id: request.app_id.clone(),
        name: request.name.clone(),
        app_type: request.app_type.clone(),
        target: proxy_target.to_string(),
        port: Some(session.proxy_port as u16),
        user: Some(session.proxy_username.trim().to_string()),
        display: request.display.clone(),
        launcher: Some("rdp".to_string()),
        credential_id: None,
        temp_token: None,
    };
    let checked_out = if bastion_proxy_session_uses_proxy_credentials(session) {
        None
    } else {
        maybe_checkout_rdp_password(request)?
    };
    let (rdp_username, rdp_password, checkout_base_url, checkout_id) =
        if let Some(state) = checked_out.as_ref() {
            if let Some(password) = state.password.as_ref() {
                (
                    state.username.clone(),
                    password.expose().to_string(),
                    Some(state.base_url.clone()),
                    Some(state.checkout_id),
                )
            } else {
                (
                    session.proxy_username.trim().to_string(),
                    if !session.proxy_password.trim().is_empty() {
                        session.proxy_password.trim().to_string()
                    } else {
                        session.access_token.trim().to_string()
                    },
                    None,
                    None,
                )
            }
        } else {
            (
                session.proxy_username.trim().to_string(),
                if !session.proxy_password.trim().is_empty() {
                    session.proxy_password.trim().to_string()
                } else {
                    session.access_token.trim().to_string()
                },
                None,
                None,
            )
        };
    if rdp_username.trim().is_empty() || rdp_password.trim().is_empty() {
        return Err(anyhow!(
            "rdp bastion proxy session missing usable credentials"
        ));
    }
    apply_cmdkey_rdp_credential(&proxy_request, &rdp_username, &rdp_password)?;
    let temp_rdp_path = write_temp_rdp_file(&proxy_request, &rdp_username)?;
    let mstsc = find_in_path(&["mstsc.exe"])
        .or_else(|| Some(String::from(r"C:\Windows\System32\mstsc.exe")))
        .ok_or_else(|| anyhow!("`mstsc.exe` not available"))?;
    let mut cmd = Command::new(mstsc);
    cmd.arg(&temp_rdp_path);
    let child = spawn_detached_child(cmd, "rdp-bastion-proxy")?;
    let target_host = proxy_request.target.clone();
    let session_id = session.session_id.clone();
    let base_url = resolve_server_base_url().ok_or_else(|| anyhow!("resolve server base url"))?;
    mark_bastion_session_connected(&base_url, &session_id);
    if let (Some(checkout_base_url), Some(checkout_id)) = (checkout_base_url, checkout_id) {
        spawn_rdp_bastion_checkin_watcher(
            base_url,
            session_id,
            checkout_base_url,
            checkout_id,
            child,
            Some(temp_rdp_path),
            target_host,
        );
        return Ok(());
    }
    thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
        let _ = std::fs::remove_file(&temp_rdp_path);
        delete_cmdkey_rdp_credential(&target_host);
        close_bastion_session_async(base_url, session_id);
    });
    Ok(())
}

fn launch_rdp_assisted_direct_bastion(
    request: &LaunchRequest,
    session: &BastionSessionRecord,
) -> Result<()> {
    let mstsc = find_in_path(&["mstsc.exe"])
        .or_else(|| Some(String::from(r"C:\Windows\System32\mstsc.exe")))
        .ok_or_else(|| anyhow!("`mstsc.exe` not available"))?;
    let checked_out = maybe_checkout_rdp_password(request)?;
    let mut temp_rdp_path = None;
    if let Some(state) = checked_out.as_ref() {
        if let Some(password) = state.password.as_ref() {
            apply_cmdkey_rdp_credential(request, &state.username, password.expose())?;
            temp_rdp_path = Some(write_temp_rdp_file(request, &state.username)?);
        }
    }
    let mut cmd = Command::new(mstsc);
    if let Some(path) = temp_rdp_path.as_ref() {
        cmd.arg(path);
    } else {
        cmd.arg(format!(
            "/v:{}:{}",
            request.target,
            request.port.unwrap_or(3389)
        ));
        cmd.arg("/f");
    }
    let child = spawn_detached_child(cmd, "rdp-bastion-assisted-direct")?;
    let base_url = resolve_server_base_url().ok_or_else(|| anyhow!("resolve server base url"))?;
    mark_bastion_session_connected(&base_url, &session.session_id);
    let target_host = request.target.clone();
    if let Some(state) = checked_out {
        let session_id = session.session_id.clone();
        spawn_rdp_bastion_checkin_watcher(
            base_url,
            session_id,
            state.base_url,
            state.checkout_id,
            child,
            temp_rdp_path,
            target_host,
        );
        return Ok(());
    }
    let session_id = session.session_id.clone();
    thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
        if let Some(path) = temp_rdp_path {
            let _ = std::fs::remove_file(path);
        }
        delete_cmdkey_rdp_credential(&target_host);
        close_bastion_session_async(base_url, session_id);
    });
    Ok(())
}

fn launch_rdp(request: &LaunchRequest) -> Result<()> {
    let mstsc = find_in_path(&["mstsc.exe"])
        .or_else(|| Some(String::from(r"C:\Windows\System32\mstsc.exe")))
        .ok_or_else(|| anyhow!("`mstsc.exe` not available"))?;

    let checked_out = maybe_checkout_rdp_password(request)?;
    let mut temp_rdp_path = None;
    if let Some(state) = checked_out.as_ref() {
        if let Some(password) = state.password.as_ref() {
            apply_cmdkey_rdp_credential(request, &state.username, password.expose())?;
            temp_rdp_path = Some(write_temp_rdp_file(request, &state.username)?);
        }
    }

    let mut cmd = Command::new(mstsc);
    if let Some(path) = temp_rdp_path.as_ref() {
        cmd.arg(path);
    } else {
        cmd.arg(format!(
            "/v:{}:{}",
            request.target,
            request.port.unwrap_or(3389)
        ));
        if let Some(display) = request.display.as_deref() {
            let parts: Vec<_> = display.split('x').collect();
            if parts.len() == 2 {
                cmd.arg(format!("/w:{}", parts[0]));
                cmd.arg(format!("/h:{}", parts[1]));
            }
        } else {
            cmd.arg("/f");
        }
    }
    let child = spawn_detached_child(cmd, "rdp")?;
    if let Some(state) = checked_out {
        let mut cleanup_paths = Vec::new();
        if let Some(path) = temp_rdp_path.as_ref() {
            cleanup_paths.push(path.display().to_string());
        }
        record_pam_launch(
            state.checkout_id,
            &request.app_id,
            "rdp",
            child.id(),
            &request.target,
            &cleanup_paths,
            Some(&state.base_url),
        )?;
        spawn_rdp_checkin_watcher(
            state.base_url,
            state.checkout_id,
            child,
            temp_rdp_path,
            request.target.clone(),
        );
    }
    Ok(())
}

fn launch_vnc(request: &LaunchRequest) -> Result<()> {
    let viewer = find_in_path(&["vncviewer.exe", "tvnviewer.exe"]).ok_or_else(|| {
        anyhow!("no supported VNC viewer found (`vncviewer.exe`/`tvnviewer.exe`)")
    })?;
    let mut cmd = Command::new(viewer);
    cmd.arg(format!(
        "{}:{}",
        request.target,
        request.port.unwrap_or(5900)
    ));
    spawn_detached(cmd, "vnc")
}

fn find_in_path(candidates: &[&str]) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for candidate in candidates {
            let full = dir.join(candidate);
            if full.is_file() {
                return Some(full.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn spawn_detached(mut cmd: Command, label: &str) -> Result<()> {
    cmd.spawn()
        .with_context(|| format!("launch {label} client"))?;
    Ok(())
}

fn spawn_detached_child(mut cmd: Command, label: &str) -> Result<std::process::Child> {
    cmd.spawn()
        .with_context(|| format!("launch {label} client"))
}

fn apply_cmdkey_rdp_credential(
    request: &LaunchRequest,
    username: &str,
    password: &str,
) -> Result<()> {
    let target = format!("TERMSRV/{}", request.target);
    let full_user = first_non_empty_string(username, request.user.as_deref().unwrap_or_default());
    let mut cmd = Command::new("cmdkey");
    cmd.arg(format!("/generic:{target}"))
        .arg(format!("/user:{full_user}"))
        .arg(format!("/pass:{password}"));
    #[cfg(target_os = "windows")]
    configure_hidden_console_command(&mut cmd);
    let status = cmd.status().context("launch cmdkey for rdp credential")?;
    if !status.success() {
        return Err(anyhow!("cmdkey failed for rdp credential injection"));
    }
    Ok(())
}

fn delete_cmdkey_rdp_credential(target_host: &str) {
    let mut cmd = Command::new("cmdkey");
    cmd.arg(format!("/delete:TERMSRV/{target_host}"));
    #[cfg(target_os = "windows")]
    configure_hidden_console_command(&mut cmd);
    let _ = cmd.status();
}

fn write_temp_rdp_file(request: &LaunchRequest, username: &str) -> Result<std::path::PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let path = std::env::temp_dir().join(format!("eguard-pam-rdp-{stamp}.rdp"));
    std::fs::write(&path, rdp_file_content(request, username))
        .with_context(|| format!("write temp rdp file {}", path.display()))?;
    Ok(path)
}

fn rdp_file_content(request: &LaunchRequest, username: &str) -> String {
    let mut content = format!(
        "full address:s:{}:{}\nusername:s:{}\nauthentication level:i:0\nprompt for credentials:i:0\nuse multimon:i:0\nsmart sizing:i:1\n",
        request.target,
        request.port.unwrap_or(3389),
        username
    );
    if let Some(display) = request.display.as_deref() {
        let parts: Vec<_> = display.split('x').collect();
        if parts.len() == 2 {
            content.push_str("screen mode id:i:1\n");
            content.push_str(&format!(
                "desktopwidth:i:{}\ndesktopheight:i:{}\n",
                parts[0], parts[1]
            ));
            return content;
        }
    }
    content.push_str("screen mode id:i:2\n");
    content
}

fn spawn_rdp_checkin_watcher(
    base_url: String,
    checkout_id: i64,
    mut child: std::process::Child,
    temp_rdp_path: Option<std::path::PathBuf>,
    target_host: String,
) {
    std::thread::spawn(move || {
        let _ = child.wait();
        if let Some(path) = temp_rdp_path {
            let _ = std::fs::remove_file(path);
        }
        delete_cmdkey_rdp_credential(&target_host);
        clear_pam_launch(checkout_id);
        let Ok(client) = PamHttpClient::new(base_url) else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Runtime::new() {
            let _ = runtime.block_on(client.checkin(checkout_id, Some("rdp_client_exit")));
        }
    });
}

fn spawn_rdp_bastion_checkin_watcher(
    server_base_url: String,
    bastion_session_id: String,
    checkout_base_url: String,
    checkout_id: i64,
    mut child: std::process::Child,
    temp_rdp_path: Option<std::path::PathBuf>,
    target_host: String,
) {
    std::thread::spawn(move || {
        let _ = child.wait();
        if let Some(path) = temp_rdp_path {
            let _ = std::fs::remove_file(path);
        }
        delete_cmdkey_rdp_credential(&target_host);
        clear_pam_launch(checkout_id);
        if let Ok(client) = PamHttpClient::new(checkout_base_url) {
            if let Ok(runtime) = tokio::runtime::Runtime::new() {
                let _ =
                    runtime.block_on(client.checkin(checkout_id, Some("rdp_bastion_client_exit")));
            }
        }
        close_bastion_session_async(server_base_url, bastion_session_id);
    });
}

fn mark_bastion_session_connected(base_url: &str, session_id: &str) {
    let base_url = base_url.to_string();
    let session_id = session_id.to_string();
    std::thread::spawn(move || {
        let Ok(client) = PamHttpClient::new(base_url) else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Runtime::new() {
            let _ = runtime.block_on(client.touch_bastion_session_connected(&session_id));
        }
    });
}

fn close_bastion_session_async(base_url: String, session_id: String) {
    std::thread::spawn(move || {
        let Ok(client) = PamHttpClient::new(base_url) else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Runtime::new() {
            let _ = runtime.block_on(client.close_bastion_session(&session_id));
        }
    });
}

fn first_non_empty_string(primary: &str, fallback: &str) -> String {
    if !primary.trim().is_empty() {
        return primary.trim().to_string();
    }
    fallback.trim().to_string()
}

fn force_cleanup_entry(entry: &PamLaunchEntry, reason: Option<&str>) {
    if let Some(pid) = entry.process_id {
        terminate_process(pid);
    }
    for path in &entry.cleanup_paths {
        let _ = std::fs::remove_file(path);
    }
    if entry.launcher_kind.eq_ignore_ascii_case("rdp") {
        delete_cmdkey_rdp_credential(&entry.target_host);
    }
    if let Some(base_url) = entry.base_url.as_deref() {
        if let Ok(client) = PamHttpClient::new(base_url.to_string()) {
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(client.checkin(entry.checkout_id, reason))
            });
            if let Err(err) = result {
                warn!(checkout_id = entry.checkout_id, error = %err, "pam cleanup checkin failed");
            }
        }
    }
}

fn terminate_process(pid: u32) {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("taskkill");
        cmd.args(["/PID", &pid.to_string(), "/T", "/F"]);
        configure_hidden_console_command(&mut cmd);
        let _ = cmd.status();
    }
}

fn record_pam_launch(
    checkout_id: i64,
    app_id: &str,
    launcher_kind: &str,
    process_id: u32,
    target_host: &str,
    cleanup_paths: &[String],
    base_url: Option<&str>,
) -> Result<()> {
    let mut state = PamLaunchState::load_default()?;
    state
        .entries
        .retain(|entry| entry.checkout_id != checkout_id);
    state.entries.push(PamLaunchEntry {
        checkout_id,
        app_id: app_id.to_string(),
        launcher_kind: launcher_kind.to_string(),
        process_id: Some(process_id),
        target_host: target_host.to_string(),
        cleanup_paths: cleanup_paths.to_vec(),
        started_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
        base_url: base_url.map(|value| value.to_string()),
    });
    state.save_default()
}

fn clear_pam_launch(checkout_id: i64) {
    let Ok(mut state) = PamLaunchState::load_default() else {
        return;
    };
    let before = state.entries.len();
    state
        .entries
        .retain(|entry| entry.checkout_id != checkout_id);
    if state.entries.len() != before {
        let _ = state.save_default();
    }
}

fn wait_for_web_launch_target(app_id: &str, direct_target: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(45);
    let direct_socket = launch_target_socket_addr(direct_target);
    while Instant::now() < deadline {
        if let Some(target) = active_web_launch_target(app_id, direct_target) {
            return target;
        }
        if let Some(addr) = direct_socket {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
                return direct_target.to_string();
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
    direct_target.to_string()
}

fn wait_for_forwarded_launch_target(
    app_id: &str,
    request: &LaunchRequest,
) -> Option<(String, u16)> {
    let deadline = Instant::now() + Duration::from_secs(45);
    let direct_socket = launch_request_socket_addr(request);
    while Instant::now() < deadline {
        if let Some((host, port)) = active_forwarded_launch_target(app_id) {
            return Some((host, port));
        }
        if let Some(addr) = direct_socket {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
                return Some((request.target.clone(), request.port.unwrap_or(addr.port())));
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
    None
}

fn active_web_launch_target(app_id: &str, direct_target: &str) -> Option<String> {
    let state = SessionState::load_default().ok()?;
    let session = state
        .sessions
        .iter()
        .find(|session| session.app_id == app_id && session.status == "active")?;
    Some(
        session
            .local_url
            .clone()
            .unwrap_or_else(|| direct_target.to_string()),
    )
}

fn active_forwarded_launch_target(app_id: &str) -> Option<(String, u16)> {
    let state = SessionState::load_default().ok()?;
    let session = state
        .sessions
        .iter()
        .find(|session| session.app_id == app_id && session.status == "active")?;
    forwarded_host_port_from_session(session)
}

fn forwarded_host_port_from_session(session: &crate::state::SessionEntry) -> Option<(String, u16)> {
    let local = session.local_url.as_deref()?.trim();
    let parsed = url::Url::parse(local).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default()?;
    Some((host, port))
}

fn launch_request_socket_addr(request: &LaunchRequest) -> Option<SocketAddr> {
    let port = request.port?;
    (request.target.as_str(), port)
        .to_socket_addrs()
        .ok()?
        .find(|addr| addr.is_ipv4())
}

fn launch_target_socket_addr(target: &str) -> Option<SocketAddr> {
    let parsed = url::Url::parse(target).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default()?;
    (host, port)
        .to_socket_addrs()
        .ok()?
        .find(|addr| addr.is_ipv4())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use pam::{BastionProfileRecord, BastionSessionEnvelope, BastionSessionRecord};

    use super::{
        active_forwarded_launch_target, active_web_launch_target,
        bastion_proxy_session_uses_proxy_credentials, normalized_app_type, rdp_file_content,
        resolve_bastion_browser_launch_url, resolve_request_via_local_forward,
        should_launch_rdp_assisted_direct,
    };

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn normalizes_app_type() {
        assert_eq!(normalized_app_type(" RDP "), "rdp");
    }

    #[test]
    fn prefers_local_url_when_present() {
        let _guard = env_lock().lock().expect("lock env");
        let dir = unique_test_dir();
        unsafe {
            std::env::set_var("EGUARD_TRAY_DATA_DIR", &dir);
        }
        fs::write(
            dir.join("ztna-sessions.json"),
            r#"{
  "sessions": [
    {
      "session_id": "s1",
      "app_id": "app-1",
      "status": "active",
      "local_url": "http://127.0.0.1:45678/"
    }
  ]
}"#,
        )
        .expect("write sessions");

        assert_eq!(
            active_web_launch_target("app-1", "http://172.16.10.11:18080/").as_deref(),
            Some("http://127.0.0.1:45678/")
        );

        unsafe {
            std::env::remove_var("EGUARD_TRAY_DATA_DIR");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn falls_back_to_original_url_for_active_direct_route_session() {
        let _guard = env_lock().lock().expect("lock env");
        let dir = unique_test_dir();
        unsafe {
            std::env::set_var("EGUARD_TRAY_DATA_DIR", &dir);
        }
        fs::write(
            dir.join("ztna-sessions.json"),
            r#"{
  "sessions": [
    {
      "session_id": "s1",
      "app_id": "app-1",
      "status": "active"
    }
  ]
}"#,
        )
        .expect("write sessions");

        assert_eq!(
            active_web_launch_target("app-1", "http://172.16.10.11:18080/").as_deref(),
            Some("http://172.16.10.11:18080/")
        );

        unsafe {
            std::env::remove_var("EGUARD_TRAY_DATA_DIR");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolves_local_forward_target_for_ssh_like_launches() {
        let _guard = env_lock().lock().expect("lock env");
        let dir = unique_test_dir();
        unsafe {
            std::env::set_var("EGUARD_TRAY_DATA_DIR", &dir);
        }
        fs::write(
            dir.join("ztna-sessions.json"),
            r#"{
  "sessions": [
    {
      "session_id": "s1",
      "app_id": "app-ssh",
      "status": "active",
      "local_url": "http://127.0.0.1:41234/"
    }
  ]
}"#,
        )
        .expect("write sessions");

        let request = crate::protocol::LaunchRequest {
            app_id: "app-ssh".to_string(),
            name: None,
            app_type: "ssh".to_string(),
            target: "172.16.10.11".to_string(),
            port: Some(22),
            user: None,
            display: None,
            launcher: Some("ssh".to_string()),
            credential_id: None,
            temp_token: None,
        };
        let resolved = resolve_request_via_local_forward("app-ssh", &request);
        assert_eq!(resolved.target, "127.0.0.1");
        assert_eq!(resolved.port, Some(41234));
        assert_eq!(
            active_forwarded_launch_target("app-ssh"),
            Some(("127.0.0.1".to_string(), 41234))
        );

        unsafe {
            std::env::remove_var("EGUARD_TRAY_DATA_DIR");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rdp_file_defaults_to_full_screen() {
        let request = crate::protocol::LaunchRequest {
            app_id: "rdp-app".to_string(),
            name: None,
            app_type: "rdp".to_string(),
            target: "10.10.10.10".to_string(),
            port: Some(3390),
            user: None,
            display: None,
            launcher: Some("rdp".to_string()),
            credential_id: None,
            temp_token: None,
        };
        let content = rdp_file_content(&request, "admin");
        assert!(content.contains("full address:s:10.10.10.10:3390\n"));
        assert!(content.contains("username:s:admin\n"));
        assert!(content.contains("screen mode id:i:2\n"));
        assert!(content.contains("smart sizing:i:1\n"));
    }

    #[test]
    fn rdp_file_uses_explicit_display_when_requested() {
        let request = crate::protocol::LaunchRequest {
            app_id: "rdp-app".to_string(),
            name: None,
            app_type: "rdp".to_string(),
            target: "10.10.10.10".to_string(),
            port: Some(3389),
            user: None,
            display: Some("1280x720".to_string()),
            launcher: Some("rdp".to_string()),
            credential_id: None,
            temp_token: None,
        };
        let content = rdp_file_content(&request, "admin");
        assert!(content.contains("screen mode id:i:1\n"));
        assert!(content.contains("desktopwidth:i:1280\n"));
        assert!(content.contains("desktopheight:i:720\n"));
        assert!(!content.contains("screen mode id:i:2\n"));
    }

    #[test]
    fn rdp_terminating_broker_uses_proxy_credentials() {
        let session = BastionSessionRecord {
            session_id: "s-rdp".to_string(),
            app_id: "rdp-app".to_string(),
            agent_id: String::new(),
            profile_id: String::new(),
            status: String::new(),
            launch_url: String::new(),
            access_token: "token".to_string(),
            proxy_host: "broker.internal".to_string(),
            proxy_port: 53390,
            proxy_username: "broker-user".to_string(),
            proxy_password: "broker-pass".to_string(),
            proxy_mode: "rdp_terminating_broker".to_string(),
            proxy_host_key_hint: String::new(),
            expires_at: String::new(),
        };
        assert!(bastion_proxy_session_uses_proxy_credentials(&session));
    }

    #[test]
    fn rdp_bastion_without_proxy_metadata_uses_assisted_direct_not_browser_url() {
        let request = crate::protocol::LaunchRequest {
            app_id: "rdp-app".to_string(),
            name: None,
            app_type: "rdp".to_string(),
            target: "10.10.10.10".to_string(),
            port: Some(3389),
            user: None,
            display: None,
            launcher: Some("bastion_rdp".to_string()),
            credential_id: None,
            temp_token: None,
        };
        let session = BastionSessionRecord {
            session_id: "s-rdp".to_string(),
            app_id: "rdp-app".to_string(),
            agent_id: String::new(),
            profile_id: String::new(),
            status: String::new(),
            launch_url: String::new(),
            access_token: String::new(),
            proxy_host: String::new(),
            proxy_port: 0,
            proxy_username: String::new(),
            proxy_password: String::new(),
            proxy_mode: String::new(),
            proxy_host_key_hint: String::new(),
            expires_at: String::new(),
        };
        let envelope = BastionSessionEnvelope {
            status: "created".to_string(),
            session: Some(session.clone()),
            profile: None,
        };

        assert!(should_launch_rdp_assisted_direct(&request, &session));
        assert_eq!(
            resolve_bastion_browser_launch_url(&request, &envelope),
            None
        );
    }

    #[test]
    fn web_bastion_can_still_fall_back_to_http_target() {
        let request = crate::protocol::LaunchRequest {
            app_id: "web-app".to_string(),
            name: None,
            app_type: "web".to_string(),
            target: "https://example.internal/".to_string(),
            port: None,
            user: None,
            display: None,
            launcher: Some("bastion".to_string()),
            credential_id: None,
            temp_token: None,
        };
        let envelope = BastionSessionEnvelope {
            status: "created".to_string(),
            session: None,
            profile: Some(BastionProfileRecord {
                profile_id: String::new(),
                name: String::new(),
                protocol: "web".to_string(),
                bastion_host: String::new(),
                bastion_port: 0,
                jump_username: String::new(),
                web_launch_url: String::new(),
            }),
        };

        assert_eq!(
            resolve_bastion_browser_launch_url(&request, &envelope).as_deref(),
            Some("https://example.internal/")
        );
    }

    fn env_lock() -> &'static Mutex<()> {
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_test_dir() -> PathBuf {
        let base = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("unix epoch")
            .as_nanos();
        let dir = base.join(format!(
            "eguard-tray-launcher-test-{}-{}",
            nonce,
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }
}
