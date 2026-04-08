use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveredLaunchers {
    pub ssh: Option<PathBuf>,
    pub rdp: Option<PathBuf>,
    pub vnc: Option<PathBuf>,
    pub web: Option<PathBuf>,
}

pub fn discover_launchers() -> DiscoveredLaunchers {
    DiscoveredLaunchers {
        ssh: first_available(&ssh_candidates()),
        rdp: first_available(&rdp_candidates()),
        vnc: first_available(&vnc_candidates()),
        web: first_available(&web_candidates()),
    }
}

fn first_available(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().find_map(|candidate| which(candidate))
}

fn which(binary: &str) -> Option<PathBuf> {
    let candidate_path = Path::new(binary);
    if candidate_path.is_absolute() && candidate_path.exists() {
        return Some(candidate_path.to_path_buf());
    }
    let path_var = env::var_os("PATH")?;
    let paths = env::split_paths(&path_var);
    #[cfg(target_os = "windows")]
    let exts: Vec<String> = env::var("PATHEXT")
        .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string())
        .split(';')
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    for dir in paths {
        let joined = dir.join(binary);
        if joined.exists() {
            return Some(joined);
        }
        #[cfg(target_os = "windows")]
        {
            for ext in &exts {
                let with_ext = dir.join(format!("{}{}", binary, ext));
                if with_ext.exists() {
                    return Some(with_ext);
                }
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn ssh_candidates() -> Vec<&'static str> {
    vec!["ssh", r"C:\Windows\System32\OpenSSH\ssh.exe"]
}

#[cfg(not(target_os = "windows"))]
fn ssh_candidates() -> Vec<&'static str> {
    vec!["ssh", "/usr/bin/ssh"]
}

#[cfg(target_os = "windows")]
fn rdp_candidates() -> Vec<&'static str> {
    vec!["mstsc", r"C:\Windows\System32\mstsc.exe"]
}

#[cfg(target_os = "macos")]
fn rdp_candidates() -> Vec<&'static str> {
    vec!["open", "/usr/bin/open"]
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn rdp_candidates() -> Vec<&'static str> {
    vec!["xfreerdp", "remmina"]
}

#[cfg(target_os = "macos")]
fn vnc_candidates() -> Vec<&'static str> {
    vec!["open", "/usr/bin/open"]
}

#[cfg(target_os = "windows")]
fn vnc_candidates() -> Vec<&'static str> {
    vec!["vncviewer"]
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn vnc_candidates() -> Vec<&'static str> {
    vec!["vncviewer", "vinagre", "remmina"]
}

#[cfg(target_os = "windows")]
fn web_candidates() -> Vec<&'static str> {
    vec!["cmd", r"C:\Windows\System32\cmd.exe"]
}

#[cfg(target_os = "macos")]
fn web_candidates() -> Vec<&'static str> {
    vec!["open", "/usr/bin/open"]
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn web_candidates() -> Vec<&'static str> {
    vec!["xdg-open"]
}
