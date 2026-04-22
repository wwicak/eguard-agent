use std::process::Command;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};

use crate::app::open_external_url;
use crate::protocol::LaunchRequest;
use crate::state::{BookmarkEntry, SessionState};

pub fn launch_bookmark(bookmark: &BookmarkEntry) -> Result<()> {
    let request = LaunchRequest::parse(&bookmark.launch_uri)
        .with_context(|| format!("parse launch uri for {}", bookmark.app_id))?;
    launch_with_session_fallback(&bookmark.app_id, &request)
}

pub fn launch_launch_request_with_session_fallback(request: &LaunchRequest) -> Result<()> {
    launch_with_session_fallback(&request.app_id, request)
}

pub fn launch_launch_request(request: &LaunchRequest) -> Result<()> {
    match normalized_app_type(&request.app_type).as_str() {
        "ssh" => launch_ssh(request),
        "rdp" => launch_rdp(request),
        "vnc" => launch_vnc(request),
        "web" | "https" | "http" => open_external_url(&request.target),
        other => Err(anyhow!("unsupported launch target `{other}`")),
    }
}

fn launch_with_session_fallback(app_id: &str, request: &LaunchRequest) -> Result<()> {
    match normalized_app_type(&request.app_type).as_str() {
        "web" | "https" | "http" => {
            let target = wait_for_web_launch_target(app_id, &request.target);
            open_external_url(&target)
        }
        _ => launch_launch_request(request),
    }
}

fn normalized_app_type(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn launch_ssh(request: &LaunchRequest) -> Result<()> {
    let ssh_exe = find_in_path(&["ssh.exe"])
        .ok_or_else(|| anyhow!("OpenSSH client `ssh.exe` not found in PATH"))?;

    let target = match request.user.as_deref() {
        Some(user) if !user.trim().is_empty() => format!("{}@{}", user.trim(), request.target),
        _ => request.target.clone(),
    };

    let mut cmd = Command::new(ssh_exe);
    if let Some(port) = request.port {
        cmd.arg("-p").arg(port.to_string());
    }
    cmd.arg(target);
    spawn_detached(cmd, "ssh")
}

fn launch_rdp(request: &LaunchRequest) -> Result<()> {
    let mstsc = find_in_path(&["mstsc.exe"])
        .or_else(|| Some(String::from(r"C:\Windows\System32\mstsc.exe")))
        .ok_or_else(|| anyhow!("`mstsc.exe` not available"))?;

    let mut cmd = Command::new(mstsc);
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
    }
    spawn_detached(cmd, "rdp")
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

fn launch_target_socket_addr(target: &str) -> Option<SocketAddr> {
    let parsed = url::Url::parse(target).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default()?;
    (host, port).to_socket_addrs().ok()?.find(|addr| addr.is_ipv4())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{active_web_launch_target, normalized_app_type};

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
