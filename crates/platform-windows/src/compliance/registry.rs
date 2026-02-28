//! Registry-based compliance checks.
//!
//! Generic helpers for reading registry values used by other compliance modules.

#[cfg(target_os = "windows")]
use crate::windows_cmd::{POWERSHELL_EXE, REG_EXE};
#[cfg(target_os = "windows")]
use std::process::Command;

/// Read a DWORD value from the registry.
pub fn read_reg_dword(hive: &str, subkey: &str, value_name: &str) -> Option<u32> {
    let output = run_reg_query(hive, subkey, value_name)?;
    parse_reg_dword(&output, value_name)
}

/// Read a string value from the registry.
pub fn read_reg_string(hive: &str, subkey: &str, value_name: &str) -> Option<String> {
    let output = run_reg_query(hive, subkey, value_name)?;
    parse_reg_string(&output, value_name)
}

#[cfg(target_os = "windows")]
pub(crate) fn run_powershell(command: &str) -> Option<String> {
    let output = Command::new(POWERSHELL_EXE)
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        None
    } else {
        Some(stdout)
    }
}

fn run_reg_query(hive: &str, subkey: &str, value_name: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let full_key = format!(r"{}\{}", hive, subkey);
        let output = Command::new(REG_EXE)
            .args(["query", &full_key, "/v", value_name])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (hive, subkey, value_name);
        None
    }
}

fn parse_reg_dword(output: &str, value_name: &str) -> Option<u32> {
    let (_, reg_type, value) = parse_reg_line(output, value_name)?;
    if reg_type != "REG_DWORD" {
        return None;
    }

    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u32>().ok()
    }
}

fn parse_reg_string(output: &str, value_name: &str) -> Option<String> {
    let (_, reg_type, value) = parse_reg_line(output, value_name)?;
    match reg_type.as_str() {
        "REG_SZ" | "REG_EXPAND_SZ" | "REG_MULTI_SZ" => Some(value.trim().to_string()),
        _ => None,
    }
}

fn parse_reg_line(output: &str, value_name: &str) -> Option<(String, String, String)> {
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let name = parts.next()?;
        if !name.eq_ignore_ascii_case(value_name) {
            continue;
        }

        let reg_type = parts.next()?.to_string();
        let value = parts.collect::<Vec<_>>().join(" ");
        if value.is_empty() {
            continue;
        }
        return Some((name.to_string(), reg_type, value));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{parse_reg_dword, parse_reg_string};

    #[test]
    fn parses_reg_dword_hex_value() {
        let output = r#"
HKEY_LOCAL_MACHINE\SOFTWARE\Test
    EnableLUA    REG_DWORD    0x1
"#;
        assert_eq!(parse_reg_dword(output, "EnableLUA"), Some(1));
    }

    #[test]
    fn parses_reg_sz_value() {
        let output = r#"
HKEY_LOCAL_MACHINE\SOFTWARE\Test
    ProductName    REG_SZ    Windows Defender
"#;
        assert_eq!(
            parse_reg_string(output, "ProductName").as_deref(),
            Some("Windows Defender")
        );
    }

    #[test]
    fn does_not_match_prefix_only_value_names() {
        let output = r#"
HKEY_LOCAL_MACHINE\SOFTWARE\Test
    ProductNameEx    REG_SZ    Not Defender
"#;
        assert_eq!(parse_reg_string(output, "ProductName"), None);
    }
}
