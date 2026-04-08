use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

pub fn register_protocol_handler_for_current_exe(exe_path: &Path) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        return register_linux(exe_path);
    }
    #[cfg(target_os = "macos")]
    {
        return register_macos(exe_path);
    }
    #[cfg(target_os = "windows")]
    {
        return register_windows(exe_path);
    }
    #[allow(unreachable_code)]
    Err(anyhow!("platform_not_supported"))
}

#[cfg(target_os = "linux")]
fn register_linux(exe_path: &Path) -> Result<PathBuf> {
    let home = std::env::var("HOME").map(PathBuf::from)?;
    let applications_dir = home.join(".local/share/applications");
    fs::create_dir_all(&applications_dir)?;
    let desktop = applications_dir.join("eguard-ztna.desktop");
    let content = format!("[Desktop Entry]\nName=eGuard ZTNA Launcher\nExec=\"{}\" --ztna-open %u\nType=Application\nTerminal=false\nMimeType=x-scheme-handler/eguard-ztna;\nNoDisplay=true\n", exe_path.display());
    fs::write(&desktop, content)?;
    Ok(desktop)
}

#[cfg(target_os = "macos")]
fn register_macos(exe_path: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let home = std::env::var("HOME").map(PathBuf::from)?;
    let app_root = home.join("Applications/eGuard ZTNA Launcher.app/Contents");
    let macos_dir = app_root.join("MacOS");
    fs::create_dir_all(&macos_dir)?;
    let plist_path = app_root.join("Info.plist");
    let launcher_path = macos_dir.join("eguard-ztna-launcher");
    let plist = format!(
        r#"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"> 
<plist version=\"1.0\"><dict>
<key>CFBundleName</key><string>eGuard ZTNA Launcher</string>
<key>CFBundleIdentifier</key><string>com.eguard.ztna.launcher</string>
<key>CFBundleExecutable</key><string>eguard-ztna-launcher</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLName</key><string>eguard-ztna</string><key>CFBundleURLSchemes</key><array><string>eguard-ztna</string></array></dict></array>
</dict></plist>"#
    );
    let script = format!(
        "#!/bin/sh\nexec \"{}\" --ztna-open \"$@\"\n",
        exe_path.display()
    );
    fs::write(&plist_path, plist)?;
    fs::write(&launcher_path, script)?;
    let mut perms = fs::metadata(&launcher_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&launcher_path, perms)?;
    Ok(plist_path)
}

#[cfg(target_os = "windows")]
fn register_windows(exe_path: &Path) -> Result<PathBuf> {
    use std::process::Command;

    let command = format!(r#"\"{}\" --ztna-open \"%1\""#, exe_path.display());
    let key_root = r"HKCU\Software\Classes\eguard-ztna";
    Command::new("reg")
        .args([
            "add",
            key_root,
            "/ve",
            "/d",
            "URL:eGuard ZTNA Protocol",
            "/f",
        ])
        .status()?;
    Command::new("reg")
        .args(["add", key_root, "/v", "URL Protocol", "/d", "", "/f"])
        .status()?;
    Command::new("reg")
        .args([
            "add",
            &(String::from(key_root) + r"\shell\open\command"),
            "/ve",
            "/d",
            &command,
            "/f",
        ])
        .status()?;
    Ok(PathBuf::from(key_root))
}
