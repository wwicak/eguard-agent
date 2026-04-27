use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use url::Url;

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE,
    REG_OPTION_NON_VOLATILE, REG_SZ,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchRequest {
    pub app_id: String,
    pub name: Option<String>,
    pub app_type: String,
    pub target: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub display: Option<String>,
    pub launcher: Option<String>,
    pub credential_id: Option<i64>,
}

impl LaunchRequest {
    pub fn parse(raw: &str) -> Result<Self> {
        let url = Url::parse(raw)?;
        if url.scheme() != "eguard-ztna" {
            return Err(anyhow!("unsupported scheme `{}`", url.scheme()));
        }
        if url.host_str() != Some("launch") {
            return Err(anyhow!("unsupported action in `{raw}`"));
        }

        let mut app_id = None;
        let mut name = None;
        let mut app_type = None;
        let mut target = None;
        let mut port = None;
        let mut user = None;
        let mut display = None;
        let mut launcher = None;
        let mut credential_id = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "app" | "app_id" => app_id = Some(value.into_owned()),
                "name" => name = Some(value.into_owned()),
                "type" | "app_type" => app_type = Some(value.into_owned()),
                "target" | "server" | "host" | "url" => target = Some(value.into_owned()),
                "port" => {
                    port = Some(
                        value
                            .parse::<u16>()
                            .map_err(|_| anyhow!("invalid port `{value}`"))?,
                    )
                }
                "user" | "username" => user = Some(value.into_owned()),
                "display" => display = Some(value.into_owned()),
                "launcher" | "client" | "terminal" => launcher = Some(value.into_owned()),
                "credential_id" | "cred" => {
                    credential_id = Some(
                        value
                            .parse::<i64>()
                            .map_err(|_| anyhow!("invalid credential_id `{value}`"))?,
                    )
                }
                _ => {}
            }
        }

        Ok(Self {
            app_id: app_id.ok_or_else(|| anyhow!("missing `app` parameter"))?,
            name,
            app_type: app_type.ok_or_else(|| anyhow!("missing `type` parameter"))?,
            target: target.ok_or_else(|| anyhow!("missing `target`/`server`/`url` parameter"))?,
            port,
            user,
            display,
            launcher,
            credential_id,
        })
    }

    pub fn forward_host(&self) -> String {
        Url::parse(&self.target)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .unwrap_or_else(|| self.target.clone())
    }

    pub fn forward_port(&self) -> Option<u16> {
        if self.port.is_some() {
            return self.port;
        }
        Url::parse(&self.target)
            .ok()
            .and_then(|url| url.port_or_known_default())
    }
}

pub fn register_protocol_handler(exe_path: String) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        register_protocol_handler_windows(&exe_path)?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(anyhow!(
        "protocol registration is only implemented for Windows in this crate"
    ))
}

#[cfg(target_os = "windows")]
fn register_protocol_handler_windows(exe_path: &str) -> Result<()> {
    let key_path = wide("Software\\Classes\\eguard-ztna");
    let command_key_path = wide("Software\\Classes\\eguard-ztna\\shell\\open\\command");

    let root = create_key(HKEY_CURRENT_USER, &key_path)?;
    set_reg_sz(root, None, "URL:eGuard ZTNA Protocol")?;
    set_reg_sz(root, Some("URL Protocol"), "")?;
    unsafe {
        let _ = RegCloseKey(root);
    };

    let command = format!("\"{exe_path}\" handle-url \"%1\"");
    let command_key = create_key(HKEY_CURRENT_USER, &command_key_path)?;
    set_reg_sz(command_key, None, &command)?;
    unsafe {
        let _ = RegCloseKey(command_key);
    };

    Ok(())
}

#[cfg(target_os = "windows")]
fn create_key(parent: HKEY, subkey: &[u16]) -> Result<HKEY> {
    let mut key = HKEY::default();
    unsafe {
        RegCreateKeyExW(
            parent,
            PCWSTR(subkey.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        )
        .ok()?;
    }
    Ok(key)
}

#[cfg(target_os = "windows")]
fn set_reg_sz(key: HKEY, value_name: Option<&str>, value: &str) -> Result<()> {
    let wide_name = value_name.map(wide);
    let wide_value = wide(value);
    let bytes = unsafe {
        std::slice::from_raw_parts(
            wide_value.as_ptr() as *const u8,
            wide_value.len() * std::mem::size_of::<u16>(),
        )
    };
    unsafe {
        RegSetValueExW(
            key,
            wide_name
                .as_ref()
                .map(|name| PCWSTR(name.as_ptr()))
                .unwrap_or(PCWSTR::null()),
            0,
            REG_SZ,
            Some(bytes),
        )
        .ok()?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::LaunchRequest;

    #[test]
    fn parses_launch_uri() {
        let request = LaunchRequest::parse(
            "eguard-ztna://launch?app=rdp-prod&type=rdp&server=rdp.internal.example&port=3389&user=alice",
        )
        .expect("parse request");

        assert_eq!(request.app_id, "rdp-prod");
        assert_eq!(request.app_type, "rdp");
        assert_eq!(request.target, "rdp.internal.example");
        assert_eq!(request.port, Some(3389));
        assert_eq!(request.user.as_deref(), Some("alice"));
        assert_eq!(request.forward_host(), "rdp.internal.example");
        assert_eq!(request.forward_port(), Some(3389));
    }

    #[test]
    fn extracts_forward_target_from_url_parameter() {
        let request = LaunchRequest::parse(
            "eguard-ztna://launch?app=test-internal&type=http&url=http://172.16.10.11:18080/",
        )
        .expect("parse request");

        assert_eq!(request.target, "http://172.16.10.11:18080/");
        assert_eq!(request.forward_host(), "172.16.10.11");
        assert_eq!(request.forward_port(), Some(18080));
    }
}
