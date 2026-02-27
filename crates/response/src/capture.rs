#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;

use crate::errors::ResponseResult;

#[cfg(target_os = "linux")]
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct ScriptCapture {
    pub pid: u32,
    pub script_path: Option<PathBuf>,
    pub script_content: Option<Vec<u8>>,
    pub stdin_content: Option<Vec<u8>>,
    pub environment: Option<String>,
}

pub fn capture_script_content(pid: u32) -> ResponseResult<ScriptCapture> {
    #[cfg(target_os = "linux")]
    {
        capture_script_content_linux(pid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // /proc filesystem is not available on macOS/Windows.
        Ok(ScriptCapture {
            pid,
            ..ScriptCapture::default()
        })
    }
}

#[cfg(target_os = "linux")]
fn capture_script_content_linux(pid: u32) -> ResponseResult<ScriptCapture> {
    let args = read_cmdline_args(pid)?;
    let mut capture = ScriptCapture {
        pid,
        ..ScriptCapture::default()
    };

    if args.len() > 1 {
        let script_path = Path::new(&args[1]);
        if script_path.exists() {
            if let Ok(content) = read_file_capped(script_path, MAX_CAPTURE_BYTES) {
                capture.script_path = Some(script_path.to_path_buf());
                capture.script_content = Some(content);
            }
        }
    }

    let stdin_path = PathBuf::from(format!("/proc/{}/fd/0", pid));
    if let Ok(target) = fs::read_link(&stdin_path) {
        if target.to_string_lossy().contains("pipe:") {
            if let Ok(content) = read_pipe_nonblocking_capped(&stdin_path, MAX_CAPTURE_BYTES) {
                if !content.is_empty() {
                    capture.stdin_content = Some(content);
                }
            }
        }
    }

    if let Ok(environ) = fs::read(format!("/proc/{}/environ", pid)) {
        capture.environment = normalize_environ_bytes(&environ);
    }

    Ok(capture)
}

#[cfg(target_os = "linux")]
fn read_cmdline_args(pid: u32) -> ResponseResult<Vec<String>> {
    let raw = fs::read(format!("/proc/{}/cmdline", pid))?;
    Ok(raw
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect())
}

#[cfg(target_os = "linux")]
fn read_file_capped(path: &Path, cap: usize) -> std::io::Result<Vec<u8>> {
    let data = fs::read(path)?;
    if data.len() > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds capture limit",
        ));
    }
    Ok(data)
}

#[cfg(target_os = "linux")]
fn read_pipe_nonblocking_capped(path: &Path, cap: usize) -> std::io::Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(path)?;

        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => {
                    if out.len().saturating_add(read) > cap {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "file exceeds capture limit",
                        ));
                    }
                    out.extend_from_slice(&buf[..read]);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err),
            }
        }

        Ok(out)
    }

    #[cfg(not(unix))]
    {
        read_file_capped(path, cap)
    }
}

#[cfg(target_os = "linux")]
fn normalize_environ_bytes(raw: &[u8]) -> Option<String> {
    let normalized = raw
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

#[cfg(test)]
mod tests;
