use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use super::super::bundle_path::{is_remote_bundle_reference, resolve_rules_staging_root};
use super::{
    DEFAULT_MACHINE_ID_PATH, MACHINE_ID_PATH_ENV, THREAT_INTEL_LAST_KNOWN_GOOD_FILENAME,
    THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV, THREAT_INTEL_LAST_KNOWN_GOOD_SIG_CONTEXT,
    THREAT_INTEL_REPLAY_FLOOR_FILENAME, THREAT_INTEL_REPLAY_FLOOR_PATH_ENV,
    THREAT_INTEL_REPLAY_FLOOR_SIG_CONTEXT,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ThreatIntelReplayFloorState {
    pub(super) version_floor: String,
    pub(super) published_at_unix_floor: i64,
    pub(super) signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ThreatIntelLastKnownGoodState {
    pub(super) version: String,
    pub(super) bundle_path: String,
    pub(super) signature: String,
}

pub(super) fn resolve_threat_intel_replay_floor_path() -> PathBuf {
    if let Some(path) = threat_intel_replay_floor_path_override_from_env() {
        return path;
    }

    resolve_rules_staging_root().join(THREAT_INTEL_REPLAY_FLOOR_FILENAME)
}

fn threat_intel_replay_floor_path_override_from_env() -> Option<PathBuf> {
    std::env::var(THREAT_INTEL_REPLAY_FLOOR_PATH_ENV)
        .ok()
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

pub(super) fn resolve_threat_intel_last_known_good_path() -> PathBuf {
    if let Some(path) = threat_intel_last_known_good_path_override_from_env() {
        return path;
    }

    resolve_rules_staging_root().join(THREAT_INTEL_LAST_KNOWN_GOOD_FILENAME)
}

fn threat_intel_last_known_good_path_override_from_env() -> Option<PathBuf> {
    std::env::var(THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV)
        .ok()
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

pub(super) fn persist_threat_intel_replay_floor_state(
    version_floor: &str,
    published_at_unix_floor: i64,
) -> Result<()> {
    if cfg!(test) && threat_intel_replay_floor_path_override_from_env().is_none() {
        return Ok(());
    }

    let version_floor = version_floor.trim();
    if version_floor.is_empty() && published_at_unix_floor <= 0 {
        return Ok(());
    }

    let state = ThreatIntelReplayFloorState {
        version_floor: version_floor.to_string(),
        published_at_unix_floor,
        signature: sign_threat_intel_replay_floor(version_floor, published_at_unix_floor),
    };
    let payload = serde_json::to_vec_pretty(&state)
        .map_err(|err| anyhow!("serialize threat-intel replay floor state: {}", err))?;

    let path = resolve_threat_intel_replay_floor_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            anyhow!(
                "create threat-intel replay floor directory '{}': {}",
                parent.display(),
                err
            )
        })?;
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = path.with_extension(format!("tmp-{}-{}", std::process::id(), nonce));
    fs::write(&tmp_path, payload).map_err(|err| {
        anyhow!(
            "write threat-intel replay floor state temp '{}': {}",
            tmp_path.display(),
            err
        )
    })?;
    fs::rename(&tmp_path, &path).map_err(|err| {
        anyhow!(
            "persist threat-intel replay floor state '{}' via '{}': {}",
            path.display(),
            tmp_path.display(),
            err
        )
    })?;

    Ok(())
}

pub(super) fn load_threat_intel_replay_floor_state() -> Option<ThreatIntelReplayFloorState> {
    if cfg!(test) && threat_intel_replay_floor_path_override_from_env().is_none() {
        return None;
    }

    let path = resolve_threat_intel_replay_floor_path();
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => {
            warn!(
                error = %err,
                path = %path.display(),
                "failed reading threat-intel replay floor state"
            );
            return None;
        }
    };

    let state: ThreatIntelReplayFloorState = match serde_json::from_str(&raw) {
        Ok(state) => state,
        Err(err) => {
            warn!(
                error = %err,
                path = %path.display(),
                "failed parsing threat-intel replay floor state"
            );
            return None;
        }
    };

    let expected_signature =
        sign_threat_intel_replay_floor(&state.version_floor, state.published_at_unix_floor);
    if expected_signature != state.signature {
        warn!(
            path = %path.display(),
            "threat-intel replay floor state signature mismatch; ignoring file"
        );
        return None;
    }

    Some(state)
}

pub(super) fn persist_threat_intel_last_known_good_state(
    version: &str,
    bundle_path: &str,
) -> Result<()> {
    if cfg!(test) && threat_intel_last_known_good_path_override_from_env().is_none() {
        return Ok(());
    }

    let version = version.trim();
    let bundle_path = bundle_path.trim();
    if version.is_empty() || bundle_path.is_empty() || is_remote_bundle_reference(bundle_path) {
        return Ok(());
    }

    let canonical_bundle_path = canonicalize_bundle_path_for_state(bundle_path)?;
    let state = ThreatIntelLastKnownGoodState {
        version: version.to_string(),
        bundle_path: canonical_bundle_path.clone(),
        signature: sign_threat_intel_last_known_good(version, &canonical_bundle_path),
    };
    let payload = serde_json::to_vec_pretty(&state)
        .map_err(|err| anyhow!("serialize threat-intel last-known-good state: {}", err))?;

    let path = resolve_threat_intel_last_known_good_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            anyhow!(
                "create threat-intel last-known-good directory '{}': {}",
                parent.display(),
                err
            )
        })?;
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = path.with_extension(format!("tmp-{}-{}", std::process::id(), nonce));
    fs::write(&tmp_path, payload).map_err(|err| {
        anyhow!(
            "write threat-intel last-known-good state temp '{}': {}",
            tmp_path.display(),
            err
        )
    })?;
    fs::rename(&tmp_path, &path).map_err(|err| {
        anyhow!(
            "persist threat-intel last-known-good state '{}' via '{}': {}",
            path.display(),
            tmp_path.display(),
            err
        )
    })?;

    Ok(())
}

pub(super) fn load_threat_intel_last_known_good_state() -> Option<ThreatIntelLastKnownGoodState> {
    if cfg!(test) && threat_intel_last_known_good_path_override_from_env().is_none() {
        return None;
    }

    let path = resolve_threat_intel_last_known_good_path();
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => {
            warn!(
                error = %err,
                path = %path.display(),
                "failed reading threat-intel last-known-good state"
            );
            return None;
        }
    };

    let state: ThreatIntelLastKnownGoodState = match serde_json::from_str(&raw) {
        Ok(state) => state,
        Err(err) => {
            warn!(
                error = %err,
                path = %path.display(),
                "failed parsing threat-intel last-known-good state"
            );
            return None;
        }
    };

    let expected_signature = sign_threat_intel_last_known_good(&state.version, &state.bundle_path);
    if expected_signature != state.signature {
        warn!(
            path = %path.display(),
            "threat-intel last-known-good state signature mismatch; ignoring file"
        );
        return None;
    }

    Some(state)
}

pub(super) fn canonicalize_bundle_path_for_state(raw_path: &str) -> Result<String> {
    let trimmed = raw_path.trim();
    let canonical = fs::canonicalize(trimmed).map_err(|err| {
        anyhow!(
            "canonicalize threat-intel bundle path '{}' for persisted state: {}",
            trimmed,
            err
        )
    })?;

    Ok(canonical.to_string_lossy().into_owned())
}

fn sign_threat_intel_replay_floor(version_floor: &str, published_at_unix_floor: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(THREAT_INTEL_REPLAY_FLOOR_SIG_CONTEXT.as_bytes());
    hasher.update(b"\n");
    hasher.update(threat_intel_state_key_material().as_bytes());
    hasher.update(b"\n");
    hasher.update(version_floor.trim().as_bytes());
    hasher.update(b"\n");
    hasher.update(published_at_unix_floor.to_string().as_bytes());

    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

fn sign_threat_intel_last_known_good(version: &str, bundle_path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(THREAT_INTEL_LAST_KNOWN_GOOD_SIG_CONTEXT.as_bytes());
    hasher.update(b"\n");
    hasher.update(threat_intel_state_key_material().as_bytes());
    hasher.update(b"\n");
    hasher.update(version.trim().as_bytes());
    hasher.update(b"\n");
    hasher.update(bundle_path.trim().as_bytes());

    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

fn threat_intel_state_key_material() -> String {
    let machine_id_path = std::env::var(MACHINE_ID_PATH_ENV)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .unwrap_or_else(|| DEFAULT_MACHINE_ID_PATH.to_string());

    fs::read_to_string(&machine_id_path)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .unwrap_or_else(|| "eguard-agent-unknown-machine".to_string())
}
