use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use detection::{DetectionEngine, RansomwarePolicy};

use crate::config::AgentConfig;

use super::{rule_bundle_loader, rule_bundle_verify};

#[cfg(test)]
pub(super) fn load_bundle_rules(
    detection: &mut DetectionEngine,
    bundle_path: &str,
) -> (usize, usize) {
    rule_bundle_loader::load_bundle_rules(detection, bundle_path)
}

pub(super) fn load_bundle_full(
    detection: &mut DetectionEngine,
    bundle_path: &str,
) -> rule_bundle_loader::BundleLoadSummary {
    rule_bundle_loader::load_bundle_full(detection, bundle_path)
}

pub(super) fn is_signed_bundle_archive(path: &Path) -> bool {
    rule_bundle_loader::is_signed_bundle_archive(path)
}

#[cfg(test)]
pub(super) fn sanitize_archive_relative_path(path: &Path) -> Option<PathBuf> {
    rule_bundle_loader::sanitize_archive_relative_path(path)
}

pub(super) fn verify_bundle_signature(bundle_path: &Path) -> bool {
    rule_bundle_verify::verify_bundle_signature(bundle_path)
}

#[cfg(test)]
pub(super) fn verify_bundle_signature_with_material(
    bundle_path: &Path,
    signature_path: &Path,
    public_key: [u8; 32],
) -> std::result::Result<(), String> {
    rule_bundle_verify::verify_bundle_signature_with_material(
        bundle_path,
        signature_path,
        public_key,
    )
}

pub(super) fn build_ransomware_policy(config: &AgentConfig) -> RansomwarePolicy {
    let mut policy = RansomwarePolicy::default();
    policy.write_threshold = config.detection_ransomware_write_threshold;
    policy.write_window_secs = config.detection_ransomware_write_window_secs as i64;
    policy.adaptive_delta = config.detection_ransomware_adaptive_delta;
    policy.adaptive_min_samples = config.detection_ransomware_adaptive_min_samples;
    policy.adaptive_floor = config.detection_ransomware_adaptive_floor;
    policy.learned_root_min_hits = config.detection_ransomware_learned_root_min_hits;
    policy.learned_root_max = config.detection_ransomware_learned_root_max;
    if !config.detection_ransomware_user_path_prefixes.is_empty() {
        policy.user_path_prefixes = config.detection_ransomware_user_path_prefixes.clone();
    }
    if !config.detection_ransomware_system_path_prefixes.is_empty() {
        policy.system_path_prefixes = config.detection_ransomware_system_path_prefixes.clone();
    }
    if !config.detection_ransomware_temp_path_tokens.is_empty() {
        policy.temp_path_tokens = config.detection_ransomware_temp_path_tokens.clone();
    }
    policy.sanitized()
}
