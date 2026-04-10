use anyhow::{anyhow, Result};

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
        .unwrap_or_else(|| "https://127.0.0.1:1443/".to_string());
    open_external_url(&target)
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
