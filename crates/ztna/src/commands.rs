use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::types::{TrayCommand, TrayCommandKind};

pub fn default_command_queue_dir() -> PathBuf {
    if let Ok(raw) = std::env::var("EGUARD_ZTNA_COMMAND_QUEUE") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    #[cfg(target_os = "linux")]
    {
        return PathBuf::from("/var/lib/eguard-agent/ztna-commands");
    }
    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Library/Application Support/eGuard/ztna-commands");
    }
    #[cfg(target_os = "windows")]
    {
        return PathBuf::from(r"C:\ProgramData\eGuard\ztna-commands");
    }
    #[allow(unreachable_code)]
    PathBuf::from("ztna-commands")
}

pub fn enqueue_command(dir: &Path, kind: TrayCommandKind) -> Result<TrayCommand> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed creating command queue dir {}", dir.display()))?;
    let sequence = next_sequence();
    let command = TrayCommand {
        command_id: format!("cmd-{}-{}", now_unix(), sequence),
        created_at_unix: now_unix(),
        kind,
    };
    let path = dir.join(format!("{}.json", command.command_id));
    let body = serde_json::to_string_pretty(&command)?;
    fs::write(&path, body).with_context(|| format!("failed writing command {}", path.display()))?;
    Ok(command)
}

pub fn drain_commands(dir: &Path) -> Result<Vec<TrayCommand>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(dir)
        .with_context(|| format!("failed reading command queue dir {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    paths.sort();
    let mut commands = Vec::with_capacity(paths.len());
    for path in paths {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed reading command file {}", path.display()))?;
        let command = serde_json::from_str::<TrayCommand>(&raw)
            .with_context(|| format!("failed parsing command file {}", path.display()))?;
        commands.push(command);
        let _ = fs::remove_file(&path);
    }
    Ok(commands)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn next_sequence() -> u64 {
    static SEQUENCE: AtomicU64 = AtomicU64::new(1);
    SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::{drain_commands, enqueue_command};
    use crate::types::TrayCommandKind;

    #[test]
    fn queue_roundtrip_preserves_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        enqueue_command(dir.path(), TrayCommandKind::DisconnectAll).expect("enqueue 1");
        enqueue_command(
            dir.path(),
            TrayCommandKind::DisconnectSession {
                session_id: "s-1".to_string(),
            },
        )
        .expect("enqueue 2");
        let drained = drain_commands(dir.path()).expect("drain commands");
        assert_eq!(drained.len(), 2);
        assert!(matches!(drained[0].kind, TrayCommandKind::DisconnectAll));
        assert!(matches!(
            drained[1].kind,
            TrayCommandKind::DisconnectSession { .. }
        ));
    }
}
