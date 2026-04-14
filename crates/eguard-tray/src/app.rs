use anyhow::{anyhow, Result};
use std::fs;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::UI::Shell::ShellExecuteW;
#[cfg(target_os = "windows")]
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub fn open_admin_ui() -> Result<()> {
    let target = std::env::var("EGUARD_ADMIN_UI_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(resolve_admin_ui_url_from_config)
        .unwrap_or_else(|| "https://127.0.0.1:1443/".to_string());
    open_external_url(&target)
}

fn resolve_admin_ui_url_from_config() -> Option<String> {
    let path = PathBuf::from(r"C:\ProgramData\eGuard\bootstrap.conf");
    let raw = fs::read_to_string(path).ok()?;
    let mut address = None;
    for line in raw.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("address = ") {
            address = Some(value.trim().trim_matches('"').to_string());
            break;
        }
    }
    let address = address?
        .trim()
        .trim_matches('[')
        .trim_matches(']')
        .to_string();
    if address.is_empty() {
        return None;
    }
    Some(format!("https://{}:1443/admin", address))
}

pub fn open_external_url(target: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let operation = wide("open");
        let target = wide(target);
        let result = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(operation.as_ptr()),
                PCWSTR(target.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        let code = result.0 as isize;
        if code <= 32 {
            return Err(anyhow!(
                "failed to open external URL (ShellExecuteW={code})"
            ));
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(anyhow!(
        "opening external URLs is only implemented for Windows in this crate"
    ))
}

#[cfg(target_os = "windows")]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
