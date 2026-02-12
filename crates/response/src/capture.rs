use std::fs;
use std::path::{Path, PathBuf};

use crate::errors::ResponseResult;

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
            if let Ok(content) = read_file_capped(&stdin_path, MAX_CAPTURE_BYTES) {
                capture.stdin_content = Some(content);
            }
        }
    }

    if let Ok(environ) = fs::read(format!("/proc/{}/environ", pid)) {
        let normalized = environ
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        if !normalized.is_empty() {
            capture.environment = Some(normalized);
        }
    }

    Ok(capture)
}

fn read_cmdline_args(pid: u32) -> ResponseResult<Vec<String>> {
    let raw = fs::read(format!("/proc/{}/cmdline", pid))?;
    Ok(raw
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect())
}

fn read_file_capped(path: &Path, cap: usize) -> std::io::Result<Vec<u8>> {
    let mut data = fs::read(path)?;
    if data.len() > cap {
        data.truncate(cap);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_current_process_metadata() {
        let pid = std::process::id();
        let capture = capture_script_content(pid).expect("capture script content");
        assert_eq!(capture.pid, pid);
    }
}
