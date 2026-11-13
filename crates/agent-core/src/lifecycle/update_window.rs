// Keep the visible 15-minute INFO window across both package and worker stops.
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use grpc_client::EventEnvelope;
use serde::Deserialize;

use super::command_pipeline::paths::resolve_agent_data_dir;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpdateWindow {
    command_id: String,
    target_version: String,
    expires_at: i64,
}

fn open_child(parent: &File, name: &std::ffi::CStr, directory: bool) -> Option<File> {
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    (fd >= 0).then(|| unsafe { File::from_raw_fd(fd) })
}

fn load(root: &Path, owner: u32) -> Option<(File, UpdateWindow)> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .ok()?;
    let meta = root.metadata().ok()?;
    if meta.uid() != owner || meta.mode() & 0o022 != 0 {
        return None;
    }
    let dir = open_child(&root, c"update-restart", true)?;
    let meta = dir.metadata().ok()?;
    if meta.uid() != owner || meta.mode() & 0o7777 != 0o700 {
        return None;
    }
    let file = open_child(&dir, c"window.json", false)?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.uid() != owner || meta.mode() & 0o7777 != 0o600 || meta.len() > 1024
    {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 1024 {
        return None;
    }
    let window: UpdateWindow = serde_json::from_slice(&bytes).ok()?;
    for token in [&window.command_id, &window.target_version] {
        if token.is_empty()
            || token.len() > 128
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return None;
        }
    }
    Some((dir, window))
}

fn read(root: &Path, now: i64, owner: u32) -> Option<UpdateWindow> {
    let (_, window) = load(root, owner)?;
    (now >= 0 && window.expires_at > now && window.expires_at <= now.saturating_add(900))
        .then_some(window)
}

pub(super) fn current(now: i64) -> Option<UpdateWindow> {
    read(&resolve_agent_data_dir(), now, 0)
}

pub(super) fn cleanup(root: &Path, now: i64, owner: u32) {
    if let Some((dir, window)) = load(root, owner) {
        if window.expires_at <= now {
            unsafe {
                libc::unlinkat(dir.as_raw_fd(), c"window.json".as_ptr(), 0);
            }
        }
    }
}

pub(super) fn classify(event: &mut EventEnvelope, window: Option<UpdateWindow>) {
    if let Some(window) = window {
        event.severity = "info".into();
        event.rule_name = "agent_update_restart".into();
        let mut payload: serde_json::Value =
            serde_json::from_str(&event.payload_json).expect("shutdown payload");
        payload["rule_name"] = event.rule_name.clone().into();
        payload["severity"] = event.severity.clone().into();
        payload["detail"] = "agent restarting during a verified update window".into();
        payload["command_id"] = window.command_id.into();
        payload["target_version"] = window.target_version.into();
        event.payload_json = payload.to_string();
    }
}

#[cfg(test)]
mod tests;
