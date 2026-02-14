use std::cmp::Ordering;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use grpc_client::ThreatIntelVersionEnvelope;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use super::bundle_path::{
    is_remote_bundle_reference, resolve_rules_staging_root, staging_bundle_archive_path,
};
use super::{
    build_detection_engine, interval_due, is_signed_bundle_archive, load_bundle_full, AgentRuntime,
    ReloadReport, THREAT_INTEL_INTERVAL_SECS,
};

const THREAT_INTEL_REPLAY_FLOOR_FILENAME: &str = "threat-intel-replay-floor.v1.json";
const THREAT_INTEL_REPLAY_FLOOR_PATH_ENV: &str = "EGUARD_THREAT_INTEL_REPLAY_FLOOR_PATH";
const THREAT_INTEL_REPLAY_FLOOR_SIG_CONTEXT: &str = "eguard-threat-intel-replay-floor-v1";
const THREAT_INTEL_LAST_KNOWN_GOOD_FILENAME: &str = "threat-intel-last-known-good.v1.json";
const THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV: &str = "EGUARD_THREAT_INTEL_LAST_KNOWN_GOOD_PATH";
const THREAT_INTEL_LAST_KNOWN_GOOD_SIG_CONTEXT: &str = "eguard-threat-intel-last-known-good-v1";
const MACHINE_ID_PATH_ENV: &str = "EGUARD_MACHINE_ID_PATH";
const DEFAULT_MACHINE_ID_PATH: &str = "/etc/machine-id";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThreatIntelReplayFloorState {
    version_floor: String,
    published_at_unix_floor: i64,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThreatIntelLastKnownGoodState {
    version: String,
    bundle_path: String,
    signature: String,
}

impl AgentRuntime {
    pub(super) fn bootstrap_threat_intel_replay_floor(&mut self) {
        let Some(state) = load_threat_intel_replay_floor_state() else {
            return;
        };

        let version_floor = state.version_floor.trim();
        if !version_floor.is_empty() {
            self.threat_intel_version_floor = Some(version_floor.to_string());
        }

        if state.published_at_unix_floor > 0 {
            self.latest_threat_published_at_unix = Some(state.published_at_unix_floor);
        }

        info!(
            version_floor = version_floor,
            published_at_unix_floor = state.published_at_unix_floor,
            "loaded persisted threat-intel replay floor state"
        );
    }

    pub(super) fn bootstrap_last_known_good_bundle(&mut self) {
        let Some(state) = load_threat_intel_last_known_good_state() else {
            return;
        };

        let version = state.version.trim();
        let bundle_path = state.bundle_path.trim();
        if version.is_empty() || bundle_path.is_empty() || is_remote_bundle_reference(bundle_path) {
            return;
        }

        if let Err(err) =
            ensure_version_monotonicity(self.threat_intel_version_floor.as_deref(), version)
        {
            warn!(
                error = %err,
                version = version,
                bundle_path = bundle_path,
                "skipping persisted last-known-good bundle due to version floor violation"
            );
            return;
        }

        if let Err(err) = self.reload_detection_state(version, bundle_path, None) {
            warn!(
                error = %err,
                version = version,
                bundle_path = bundle_path,
                "failed loading persisted last-known-good threat-intel bundle"
            );
            return;
        }

        self.latest_threat_version = Some(version.to_string());
        self.threat_intel_version_floor = Some(version.to_string());
        if let Err(err) = persist_threat_intel_replay_floor_state(
            self.threat_intel_version_floor
                .as_deref()
                .unwrap_or_default(),
            self.latest_threat_published_at_unix.unwrap_or_default(),
        ) {
            warn!(error = %err, "failed persisting replay floor after last-known-good bootstrap");
        }

        info!(
            version = version,
            bundle_path = bundle_path,
            "bootstrapped detection state from persisted last-known-good threat-intel bundle"
        );
    }

    pub(super) async fn refresh_threat_intel_if_due(&mut self, now_unix: i64) -> Result<()> {
        if !interval_due(
            self.last_threat_intel_refresh_unix,
            now_unix,
            THREAT_INTEL_INTERVAL_SECS,
        ) {
            return Ok(());
        }
        self.last_threat_intel_refresh_unix = Some(now_unix);

        if let Some(intel) = self.client.fetch_latest_threat_intel().await? {
            self.ensure_threat_intel_freshness(&intel)?;
            let changed = self.threat_intel_changed(&intel)?;
            let latest_hash = intel.custom_rule_version_hash.clone();
            if changed {
                info!(
                    version = %intel.version,
                    bundle = %intel.bundle_path,
                    bundle_signature = %intel.bundle_signature_path,
                    bundle_sha256 = %intel.bundle_sha256,
                    published_at_unix = intel.published_at_unix,
                    custom_rule_count = intel.custom_rule_count,
                    custom_rule_hash = %latest_hash,
                    "new threat intel version available"
                );
                let local_bundle_path = self.prepare_bundle_for_reload(&intel).await?;
                self.reload_detection_state(&intel.version, &local_bundle_path, Some(&intel))?;
            }

            self.update_threat_intel_freshness_state(&intel, latest_hash);
        }

        Ok(())
    }

    fn threat_intel_changed(&self, intel: &ThreatIntelVersionEnvelope) -> Result<bool> {
        let known_version = self.current_threat_version()?;
        let latest_hash = intel.custom_rule_version_hash.as_str();

        Ok(known_version.as_deref() != Some(intel.version.as_str())
            || self.latest_custom_rule_hash.as_deref() != Some(latest_hash))
    }

    fn current_threat_version(&self) -> Result<Option<String>> {
        Ok(self
            .latest_threat_version
            .clone()
            .or(self.detection_state.version()?))
    }

    fn ensure_threat_intel_freshness(&self, intel: &ThreatIntelVersionEnvelope) -> Result<()> {
        let known_version = self.current_threat_version()?;
        ensure_version_monotonicity(known_version.as_deref(), &intel.version)?;
        ensure_version_monotonicity(self.threat_intel_version_floor.as_deref(), &intel.version)?;
        ensure_publish_timestamp_floor(
            self.latest_threat_published_at_unix,
            intel.published_at_unix,
        )?;
        Ok(())
    }

    fn update_threat_intel_freshness_state(
        &mut self,
        intel: &ThreatIntelVersionEnvelope,
        latest_hash: String,
    ) {
        self.latest_threat_version = Some(intel.version.clone());
        self.latest_custom_rule_hash = Some(latest_hash);

        let version_floor = intel.version.trim();
        if !version_floor.is_empty() {
            self.threat_intel_version_floor = Some(version_floor.to_string());
        }

        let published_at_unix = intel.published_at_unix;
        if published_at_unix > 0 {
            self.latest_threat_published_at_unix = Some(
                self.latest_threat_published_at_unix
                    .map(|floor| floor.max(published_at_unix))
                    .unwrap_or(published_at_unix),
            );
        }

        if let Err(err) = persist_threat_intel_replay_floor_state(
            self.threat_intel_version_floor
                .as_deref()
                .unwrap_or_default(),
            self.latest_threat_published_at_unix.unwrap_or_default(),
        ) {
            warn!(error = %err, "failed persisting threat-intel replay floor state");
        }
    }

    pub(super) fn reload_detection_state(
        &mut self,
        version: &str,
        bundle_path: &str,
        expected_intel: Option<&ThreatIntelVersionEnvelope>,
    ) -> Result<()> {
        let old_version = self.detection_state.version()?.unwrap_or_default();
        let mut next_engine = build_detection_engine();
        let summary = load_bundle_full(&mut next_engine, bundle_path);
        let ioc_entries = next_engine.layer1.ioc_entry_count();

        self.corroborate_threat_intel_update(version, expected_intel, &summary, ioc_entries)?;

        let shard_count = self.detection_state.shard_count();
        if shard_count <= 1 {
            self.detection_state
                .swap_engine(version.to_string(), next_engine)?;
        } else {
            let bundle_path = bundle_path.to_string();
            self.detection_state.swap_engine_with_builder(
                version.to_string(),
                next_engine,
                move || {
                    let mut shard_engine = build_detection_engine();
                    let _ = load_bundle_full(&mut shard_engine, &bundle_path);
                    shard_engine
                },
            )?;
        }
        let report = ReloadReport {
            old_version,
            new_version: version.to_string(),
            sigma_rules: summary.sigma_loaded,
            yara_rules: summary.yara_loaded,
            ioc_entries,
        };
        self.last_reload_report = Some(report.clone());
        info!(
            old_version = %report.old_version,
            new_version = %report.new_version,
            bundle = %bundle_path,
            sigma_rules = report.sigma_rules,
            yara_rules = report.yara_rules,
            ioc_entries = report.ioc_entries,
            "detection state hot-reloaded"
        );

        if let Err(err) = persist_threat_intel_last_known_good_state(version, bundle_path) {
            warn!(
                error = %err,
                version = version,
                bundle_path = bundle_path,
                "failed persisting last-known-good threat-intel bundle state"
            );
        }

        Ok(())
    }

    fn corroborate_threat_intel_update(
        &self,
        version: &str,
        expected_intel: Option<&ThreatIntelVersionEnvelope>,
        summary: &super::rule_bundle_loader::BundleLoadSummary,
        ioc_entries: usize,
    ) -> Result<()> {
        let Some(expected) = expected_intel else {
            return Ok(());
        };

        if !expected.version.trim().is_empty() && expected.version.trim() != version.trim() {
            return Err(anyhow!(
                "threat-intel version mismatch: expected '{}' but applying '{}'",
                expected.version,
                version
            ));
        }

        let mut mismatches = Vec::new();
        push_count_mismatch(
            &mut mismatches,
            "sigma_count",
            expected.sigma_count,
            summary.sigma_loaded,
        );
        push_count_mismatch(
            &mut mismatches,
            "yara_count",
            expected.yara_count,
            summary.yara_loaded,
        );
        push_count_mismatch(
            &mut mismatches,
            "ioc_count",
            expected.ioc_count,
            ioc_entries,
        );
        push_count_mismatch(
            &mut mismatches,
            "cve_count",
            expected.cve_count,
            summary.cve_entries,
        );

        if !mismatches.is_empty() {
            return Err(anyhow!(
                "threat-intel bundle corroboration failed for version '{}': {}",
                version,
                mismatches.join(", ")
            ));
        }

        Ok(())
    }

    async fn prepare_bundle_for_reload(
        &self,
        intel: &ThreatIntelVersionEnvelope,
    ) -> Result<String> {
        let version = intel.version.trim();
        let bundle_path = intel.bundle_path.trim();
        if bundle_path.is_empty() {
            return Ok(String::new());
        }

        if !is_remote_bundle_reference(bundle_path) {
            verify_bundle_sha256_if_present(Path::new(bundle_path), &intel.bundle_sha256)?;
            return Ok(bundle_path.to_string());
        }

        let local_bundle = self
            .download_remote_bundle_archive(version, bundle_path)
            .await?;
        verify_bundle_sha256_if_present(&local_bundle, &intel.bundle_sha256)?;
        self.download_remote_bundle_signature_if_needed(
            bundle_path,
            &intel.bundle_signature_path,
            &local_bundle,
        )
        .await?;

        Ok(local_bundle.to_string_lossy().into_owned())
    }

    async fn download_remote_bundle_archive(
        &self,
        version: &str,
        bundle_url: &str,
    ) -> Result<PathBuf> {
        let local_bundle = staging_bundle_archive_path(version, bundle_url)?;
        self.client
            .download_bundle(bundle_url, &local_bundle)
            .await
            .map_err(|err| anyhow!("download threat-intel bundle '{}': {}", bundle_url, err))?;
        Ok(local_bundle)
    }

    async fn download_remote_bundle_signature_if_needed(
        &self,
        bundle_url: &str,
        bundle_signature_ref: &str,
        local_bundle: &Path,
    ) -> Result<()> {
        if !is_signed_bundle_archive(local_bundle) {
            return Ok(());
        }

        let signature_url = resolve_signature_reference(bundle_url, bundle_signature_ref);
        let signature_dst = PathBuf::from(format!("{}.sig", local_bundle.to_string_lossy()));
        self.client
            .download_bundle(&signature_url, &signature_dst)
            .await
            .map_err(|err| {
                anyhow!(
                    "download threat-intel bundle signature '{}': {}",
                    signature_url,
                    err
                )
            })?;
        Ok(())
    }
}

fn resolve_signature_reference(bundle_ref: &str, signature_ref: &str) -> String {
    let explicit_ref = signature_ref.trim();
    if !explicit_ref.is_empty() {
        return explicit_ref.to_string();
    }

    format!("{}.sig", bundle_ref.trim())
}

fn resolve_threat_intel_replay_floor_path() -> PathBuf {
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

fn resolve_threat_intel_last_known_good_path() -> PathBuf {
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

fn persist_threat_intel_replay_floor_state(
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

fn load_threat_intel_replay_floor_state() -> Option<ThreatIntelReplayFloorState> {
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

fn persist_threat_intel_last_known_good_state(version: &str, bundle_path: &str) -> Result<()> {
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

fn load_threat_intel_last_known_good_state() -> Option<ThreatIntelLastKnownGoodState> {
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

fn canonicalize_bundle_path_for_state(raw_path: &str) -> Result<String> {
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

fn ensure_version_monotonicity(
    current_version: Option<&str>,
    incoming_version: &str,
) -> Result<()> {
    let incoming_version = incoming_version.trim();
    let Some(current_version) = current_version else {
        return Ok(());
    };
    let current_version = current_version.trim();

    if current_version.is_empty()
        || incoming_version.is_empty()
        || current_version == incoming_version
    {
        return Ok(());
    }

    let current_family = version_family_prefix(current_version);
    let incoming_family = version_family_prefix(incoming_version);
    if !current_family.is_empty()
        && !incoming_family.is_empty()
        && current_family != incoming_family
    {
        return Ok(());
    }

    if compare_version_natural(incoming_version, current_version) != Ordering::Greater {
        return Err(anyhow!(
            "threat-intel version replay detected: incoming '{}' is not newer than current '{}'",
            incoming_version,
            current_version
        ));
    }

    Ok(())
}

fn ensure_publish_timestamp_floor(
    publish_floor_unix: Option<i64>,
    incoming_published_at_unix: i64,
) -> Result<()> {
    if incoming_published_at_unix <= 0 {
        return Ok(());
    }

    let Some(floor_unix) = publish_floor_unix else {
        return Ok(());
    };
    if floor_unix <= 0 {
        return Ok(());
    }

    if incoming_published_at_unix < floor_unix {
        return Err(anyhow!(
            "threat-intel publish timestamp replay detected: incoming {} is below floor {}",
            incoming_published_at_unix,
            floor_unix
        ));
    }

    Ok(())
}

fn version_family_prefix(raw: &str) -> String {
    raw.chars()
        .take_while(|ch| !ch.is_ascii_digit())
        .filter(|ch| ch.is_ascii_alphabetic())
        .flat_map(|ch| ch.to_lowercase())
        .collect::<String>()
}

fn compare_version_natural(lhs: &str, rhs: &str) -> Ordering {
    let lhs = lhs.as_bytes();
    let rhs = rhs.as_bytes();
    let mut i = 0usize;
    let mut j = 0usize;

    while i < lhs.len() && j < rhs.len() {
        let l = lhs[i];
        let r = rhs[j];

        if l.is_ascii_digit() && r.is_ascii_digit() {
            let lhs_start = i;
            while i < lhs.len() && lhs[i].is_ascii_digit() {
                i += 1;
            }
            let rhs_start = j;
            while j < rhs.len() && rhs[j].is_ascii_digit() {
                j += 1;
            }

            let lhs_digits = &lhs[lhs_start..i];
            let rhs_digits = &rhs[rhs_start..j];
            let lhs_trimmed = trim_leading_zeroes(lhs_digits);
            let rhs_trimmed = trim_leading_zeroes(rhs_digits);

            match lhs_trimmed.len().cmp(&rhs_trimmed.len()) {
                Ordering::Equal => match lhs_trimmed.cmp(rhs_trimmed) {
                    Ordering::Equal => continue,
                    non_eq => return non_eq,
                },
                non_eq => return non_eq,
            }
        }

        match normalize_version_byte(l).cmp(&normalize_version_byte(r)) {
            Ordering::Equal => {
                i += 1;
                j += 1;
            }
            non_eq => return non_eq,
        }
    }

    match (i == lhs.len(), j == rhs.len()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => Ordering::Equal,
    }
}

fn trim_leading_zeroes(raw: &[u8]) -> &[u8] {
    let mut idx = 0usize;
    while idx + 1 < raw.len() && raw[idx] == b'0' {
        idx += 1;
    }
    &raw[idx..]
}

fn normalize_version_byte(raw: u8) -> u8 {
    raw.to_ascii_lowercase()
}

fn verify_bundle_sha256_if_present(bundle_path: &Path, expected_sha256: &str) -> Result<()> {
    let expected = normalize_optional_sha256_hex(expected_sha256)?;
    let Some(expected) = expected else {
        return Ok(());
    };

    let actual = compute_file_sha256_hex(bundle_path)?;
    if actual != expected {
        return Err(anyhow!(
            "threat-intel bundle sha256 mismatch for '{}': expected '{}' got '{}'",
            bundle_path.display(),
            expected,
            actual
        ));
    }

    Ok(())
}

fn normalize_optional_sha256_hex(raw: &str) -> Result<Option<String>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let normalized = trimmed
        .strip_prefix("sha256:")
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "invalid threat-intel bundle_sha256 '{}': expected 64 hex characters",
            raw
        ));
    }

    Ok(Some(normalized))
}

fn compute_file_sha256_hex(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path).map_err(|err| {
        anyhow!(
            "open threat-intel bundle '{}' for sha256: {}",
            path.display(),
            err
        )
    })?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer).map_err(|err| {
            anyhow!(
                "read threat-intel bundle '{}' for sha256: {}",
                path.display(),
                err
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{:02x}", byte);
    }
    Ok(out)
}

fn push_count_mismatch(out: &mut Vec<String>, field: &str, expected: i64, actual: usize) {
    if expected <= 0 {
        return;
    }

    let expected = expected as usize;
    if actual != expected {
        out.push(format!("{} expected {} got {}", field, expected, actual));
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        compare_version_natural, compute_file_sha256_hex, ensure_publish_timestamp_floor,
        ensure_version_monotonicity, load_threat_intel_last_known_good_state,
        load_threat_intel_replay_floor_state, persist_threat_intel_last_known_good_state,
        persist_threat_intel_replay_floor_state, resolve_signature_reference,
        resolve_threat_intel_last_known_good_path, resolve_threat_intel_replay_floor_path,
        verify_bundle_sha256_if_present, THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV,
        THREAT_INTEL_REPLAY_FLOOR_PATH_ENV,
    };
    use std::cmp::Ordering;

    #[test]
    fn resolve_signature_reference_prefers_explicit_value() {
        let signature = resolve_signature_reference(
            "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.14",
            "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.14.sig",
        );
        assert_eq!(
            signature,
            "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.14.sig"
        );
    }

    #[test]
    fn resolve_signature_reference_falls_back_to_bundle_sidecar() {
        let signature = resolve_signature_reference(
            "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.14",
            "",
        );
        assert_eq!(
            signature,
            "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.14.sig"
        );
    }

    #[test]
    fn verify_bundle_sha256_if_present_accepts_matching_digest() {
        let bundle_path = write_temp_bundle_file("sha256-accept", b"bundle-payload");
        let expected = compute_file_sha256_hex(&bundle_path).expect("compute bundle sha256");

        verify_bundle_sha256_if_present(&bundle_path, &format!("sha256:{}", expected))
            .expect("sha256 should match");

        let _ = std::fs::remove_file(bundle_path);
    }

    #[test]
    fn verify_bundle_sha256_if_present_rejects_mismatch() {
        let bundle_path = write_temp_bundle_file("sha256-reject", b"bundle-payload");
        let err = verify_bundle_sha256_if_present(
            &bundle_path,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect_err("mismatch should be rejected");
        assert!(err.to_string().contains("sha256 mismatch"));

        let _ = std::fs::remove_file(bundle_path);
    }

    #[test]
    fn compare_version_natural_handles_numeric_tokens() {
        assert_eq!(
            compare_version_natural("rules-2026.02.14.2", "rules-2026.02.14.10"),
            Ordering::Less
        );
        assert_eq!(
            compare_version_natural("rules-2026.02.14.10", "rules-2026.02.14.2"),
            Ordering::Greater
        );
    }

    #[test]
    fn ensure_version_monotonicity_rejects_replay_or_downgrade() {
        let err = ensure_version_monotonicity(Some("rules-2026.02.14.10"), "rules-2026.02.14.2")
            .expect_err("downgrade should be rejected");
        assert!(err.to_string().contains("version replay detected"));
    }

    #[test]
    fn ensure_version_monotonicity_accepts_cross_family_migration() {
        ensure_version_monotonicity(Some("v2"), "rules-2026.02.14.1")
            .expect("cross-family migration should not be rejected");
    }

    #[test]
    fn ensure_publish_timestamp_floor_rejects_older_timestamp() {
        let err = ensure_publish_timestamp_floor(Some(1_700_000_100), 1_700_000_050)
            .expect_err("older timestamp should be rejected");
        assert!(err.to_string().contains("timestamp replay detected"));
    }

    #[test]
    fn threat_intel_replay_floor_state_roundtrip_persists_and_loads() {
        let _guard = env_lock().lock().expect("lock env vars");
        let path = write_temp_replay_floor_path("roundtrip");
        std::env::set_var(THREAT_INTEL_REPLAY_FLOOR_PATH_ENV, &path);

        persist_threat_intel_replay_floor_state("rules-2026.02.14.10", 1_700_000_100)
            .expect("persist replay floor state");
        let resolved = resolve_threat_intel_replay_floor_path();
        assert_eq!(resolved, path);

        let loaded = load_threat_intel_replay_floor_state().expect("load replay floor state");
        assert_eq!(loaded.version_floor, "rules-2026.02.14.10");
        assert_eq!(loaded.published_at_unix_floor, 1_700_000_100);

        std::env::remove_var(THREAT_INTEL_REPLAY_FLOOR_PATH_ENV);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn threat_intel_replay_floor_state_rejects_signature_mismatch() {
        let _guard = env_lock().lock().expect("lock env vars");
        let path = write_temp_replay_floor_path("tampered");
        std::env::set_var(THREAT_INTEL_REPLAY_FLOOR_PATH_ENV, &path);

        persist_threat_intel_replay_floor_state("rules-2026.02.14.10", 1_700_000_100)
            .expect("persist replay floor state");

        let mut payload: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&path).expect("read replay floor state file"),
        )
        .expect("parse replay floor state file");
        payload["version_floor"] = serde_json::Value::String("rules-2026.02.14.09".to_string());
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&payload).expect("encode tampered replay floor payload"),
        )
        .expect("write tampered replay floor payload");

        assert!(
            load_threat_intel_replay_floor_state().is_none(),
            "tampered replay floor state should be ignored"
        );

        std::env::remove_var(THREAT_INTEL_REPLAY_FLOOR_PATH_ENV);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn threat_intel_last_known_good_state_roundtrip_persists_and_loads() {
        let _guard = env_lock().lock().expect("lock env vars");
        let bundle_path = write_temp_bundle_file("last-good-roundtrip", b"bundle-payload");
        let state_path = write_temp_last_known_good_path("roundtrip");
        std::env::set_var(THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV, &state_path);

        persist_threat_intel_last_known_good_state(
            "rules-2026.02.14.12",
            bundle_path.to_string_lossy().as_ref(),
        )
        .expect("persist last-known-good state");

        let resolved = resolve_threat_intel_last_known_good_path();
        assert_eq!(resolved, state_path);

        let loaded = load_threat_intel_last_known_good_state().expect("load last-known-good state");
        assert_eq!(loaded.version, "rules-2026.02.14.12");
        assert!(loaded.bundle_path.ends_with(".bundle.tar.zst"));

        std::env::remove_var(THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV);
        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(bundle_path);
    }

    #[test]
    fn threat_intel_last_known_good_state_rejects_signature_mismatch() {
        let _guard = env_lock().lock().expect("lock env vars");
        let bundle_path = write_temp_bundle_file("last-good-tampered", b"bundle-payload");
        let state_path = write_temp_last_known_good_path("tampered");
        std::env::set_var(THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV, &state_path);

        persist_threat_intel_last_known_good_state(
            "rules-2026.02.14.12",
            bundle_path.to_string_lossy().as_ref(),
        )
        .expect("persist last-known-good state");

        let mut payload: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&state_path).expect("read last-known-good state file"),
        )
        .expect("parse last-known-good state file");
        payload["bundle_path"] = serde_json::Value::String("/tmp/fake.bundle.tar.zst".to_string());
        std::fs::write(
            &state_path,
            serde_json::to_vec_pretty(&payload).expect("encode tampered last-known-good payload"),
        )
        .expect("write tampered last-known-good payload");

        assert!(
            load_threat_intel_last_known_good_state().is_none(),
            "tampered last-known-good state should be ignored"
        );

        std::env::remove_var(THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV);
        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(bundle_path);
    }

    fn write_temp_bundle_file(name: &str, payload: &[u8]) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "eguard-agent-{}-{}-{}.bundle.tar.zst",
            name,
            std::process::id(),
            nonce
        ));
        std::fs::write(&path, payload).expect("write temp bundle");
        path
    }

    fn write_temp_replay_floor_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "eguard-agent-{}-{}-{}.replay-floor.json",
            name,
            std::process::id(),
            nonce
        ))
    }

    fn write_temp_last_known_good_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "eguard-agent-{}-{}-{}.last-known-good.json",
            name,
            std::process::id(),
            nonce
        ))
    }

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        ENV_LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }
}
