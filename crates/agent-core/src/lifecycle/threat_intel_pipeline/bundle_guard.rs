use std::fmt::Write as _;
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

use super::{
    DEFAULT_RULE_BUNDLE_MIN_SIGNATURE_TOTAL, RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT_ENV,
    RULE_BUNDLE_MIN_SIGNATURE_TOTAL_ENV,
};

pub(super) fn verify_bundle_sha256_if_present(
    bundle_path: &Path,
    expected_sha256: &str,
) -> Result<()> {
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

pub(super) fn compute_file_sha256_hex(path: &Path) -> Result<String> {
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

pub(super) fn push_count_mismatch(
    out: &mut Vec<String>,
    field: &str,
    expected: i64,
    actual: usize,
) {
    if expected <= 0 {
        return;
    }

    let expected = expected as usize;
    if actual != expected {
        out.push(format!("{} expected {} got {}", field, expected, actual));
    }
}

pub(super) fn ensure_shard_bundle_summary_matches(
    shard_idx: usize,
    primary: &super::super::rule_bundle_loader::BundleLoadSummary,
    shard: &super::super::rule_bundle_loader::BundleLoadSummary,
) -> Result<()> {
    if shard == primary {
        return Ok(());
    }

    Err(anyhow!(
        "threat-intel shard {} load diverged: primary {:?} vs shard {:?}",
        shard_idx,
        primary,
        shard
    ))
}

pub(super) fn bundle_ioc_total(
    summary: &super::super::rule_bundle_loader::BundleLoadSummary,
) -> usize {
    summary.ioc_hashes + summary.ioc_domains + summary.ioc_ips
}

pub(super) fn signature_database_total(
    summary: &super::super::rule_bundle_loader::BundleLoadSummary,
) -> usize {
    summary.sigma_loaded + summary.yara_loaded + bundle_ioc_total(summary)
}

fn resolve_rule_bundle_min_signature_total() -> usize {
    std::env::var(RULE_BUNDLE_MIN_SIGNATURE_TOTAL_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_RULE_BUNDLE_MIN_SIGNATURE_TOTAL)
}

fn resolve_rule_bundle_max_signature_drop_pct() -> Option<f64> {
    std::env::var(RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0 && *value <= 100.0)
}

pub(super) fn enforce_signature_drop_guard(
    bundle_path: &str,
    previous_signature_total: Option<usize>,
    incoming_signature_total: usize,
) -> Result<()> {
    if bundle_path.trim().is_empty() {
        return Ok(());
    }

    let Some(max_drop_pct) = resolve_rule_bundle_max_signature_drop_pct() else {
        return Ok(());
    };
    let Some(previous_signature_total) = previous_signature_total else {
        return Ok(());
    };
    if previous_signature_total == 0 {
        return Ok(());
    }

    let min_allowed =
        ((previous_signature_total as f64) * (1.0 - (max_drop_pct / 100.0))).ceil() as usize;
    if incoming_signature_total < min_allowed {
        return Err(anyhow!(
            "threat-intel signature database drop guard violation for '{}': incoming signature_total {} below minimum {} (previous {}, max_drop_pct {})",
            bundle_path,
            incoming_signature_total,
            min_allowed,
            previous_signature_total,
            max_drop_pct
        ));
    }

    Ok(())
}

pub(super) fn enforce_bundle_signature_database_floor(
    bundle_path: &str,
    summary: &super::super::rule_bundle_loader::BundleLoadSummary,
) -> Result<()> {
    if bundle_path.trim().is_empty() {
        return Ok(());
    }

    let signature_total = signature_database_total(summary);
    let min_signature_total = resolve_rule_bundle_min_signature_total();
    if signature_total < min_signature_total {
        return Err(anyhow!(
            "threat-intel signature database floor violation for '{}': signature_total {} below floor {}",
            bundle_path,
            signature_total,
            min_signature_total
        ));
    }

    Ok(())
}
