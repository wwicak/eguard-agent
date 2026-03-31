use std::fs;
use std::path::{Path, PathBuf};

const UPDATE_OUTCOME_PREFIX: &str = "update-outcome-";
const UPDATE_OUTCOME_SUFFIX: &str = ".txt";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UpdateOutcomeReport {
    pub(super) command_id: String,
    pub(super) status: String,
    pub(super) detail: String,
}

fn sanitize_file_component(raw: &str) -> String {
    let cleaned = raw
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

pub(super) fn update_outcome_path(update_dir: &Path, command_id: &str) -> PathBuf {
    update_dir.join(format!(
        "{}{}{}",
        UPDATE_OUTCOME_PREFIX,
        sanitize_file_component(command_id),
        UPDATE_OUTCOME_SUFFIX
    ))
}

pub(super) fn write_update_outcome_report(
    update_dir: &Path,
    command_id: &str,
    status: &str,
    detail: &str,
) -> Result<(), String> {
    fs::create_dir_all(update_dir)
        .map_err(|err| format!("create update dir {}: {}", update_dir.display(), err))?;

    let path = update_outcome_path(update_dir, command_id);
    let tmp_path = path.with_extension("tmp");
    let content = format!("{}\n{}\n{}", command_id.trim(), status.trim(), detail);
    fs::write(&tmp_path, content)
        .map_err(|err| format!("write update outcome {}: {}", tmp_path.display(), err))?;
    fs::rename(&tmp_path, &path)
        .map_err(|err| format!("persist update outcome {}: {}", path.display(), err))
}

pub(super) fn load_update_outcome_reports(
    update_dir: &Path,
) -> Result<Vec<(PathBuf, UpdateOutcomeReport)>, String> {
    let entries = match fs::read_dir(update_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(format!(
                "read update outcome dir {}: {}",
                update_dir.display(),
                err
            ))
        }
    };

    let mut reports = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| {
            format!(
                "read update outcome dir entry {}: {}",
                update_dir.display(),
                err
            )
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.starts_with(UPDATE_OUTCOME_PREFIX) || !name.ends_with(UPDATE_OUTCOME_SUFFIX) {
            continue;
        }

        let raw = fs::read_to_string(&path)
            .map_err(|err| format!("read update outcome {}: {}", path.display(), err))?;
        let mut parts = raw.splitn(3, '\n');
        let command_id = parts
            .next()
            .unwrap_or_default()
            .trim()
            .trim_start_matches('\u{feff}')
            .to_string();
        let status = parts.next().unwrap_or_default().trim().to_string();
        let detail = parts.next().unwrap_or_default().trim().to_string();
        if command_id.is_empty() || status.is_empty() {
            continue;
        }
        reports.push((
            path,
            UpdateOutcomeReport {
                command_id,
                status,
                detail,
            },
        ));
    }

    reports.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::{load_update_outcome_reports, update_outcome_path, write_update_outcome_report};

    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "eguard-update-outcome-{}-{}-{}",
            label,
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn outcome_report_round_trips() {
        let dir = unique_temp_dir("roundtrip");
        let command_id = "cmd-update-123";
        write_update_outcome_report(&dir, command_id, "failed", "checksum mismatch")
            .expect("write outcome");

        let reports = load_update_outcome_reports(&dir).expect("load outcomes");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].1.command_id, command_id);
        assert_eq!(reports[0].1.status, "failed");
        assert_eq!(reports[0].1.detail, "checksum mismatch");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn outcome_path_sanitizes_file_component() {
        let dir = unique_temp_dir("sanitize");
        let path = update_outcome_path(&dir, "cmd/update:123");
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        assert!(name.contains("cmd_update_123"));
    }

    #[test]
    fn load_update_outcome_reports_strips_utf8_bom_from_command_id() {
        let dir = unique_temp_dir("bom");
        let path = update_outcome_path(&dir, "cmd-update-bom");
        std::fs::create_dir_all(&dir).expect("create temp outcome dir");
        std::fs::write(
            &path,
            b"\xEF\xBB\xBFcmd-update-bom\ncompleted\nagent update applied",
        )
        .expect("write bom outcome");

        let reports = load_update_outcome_reports(&dir).expect("load outcomes");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].1.command_id, "cmd-update-bom");
        assert_eq!(reports[0].1.status, "completed");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
