use tracing::warn;

use compliance::{parse_policy_json, CompliancePolicy};
use ed25519_dalek::Verifier;
use grpc_client::PolicyEnvelope;
use sha2::{Digest, Sha256};

use super::rule_bundle_verify::{decode_hex_bytes, parse_ed25519_key_material};
use crate::config::AgentConfig;

#[cfg(test)]
use super::SECONDS_PER_DAY;
#[cfg(test)]
use anyhow::{anyhow, Result};

pub(super) fn load_compliance_policy() -> CompliancePolicy {
    if let Ok(path) = std::env::var("EGUARD_COMPLIANCE_POLICY_PATH") {
        let path = path.trim();
        if !path.is_empty() {
            match std::fs::read_to_string(path) {
                Ok(raw) => match parse_policy_json(&raw) {
                    Ok(policy) => return policy,
                    Err(err) => {
                        warn!(error = %err, path = %path, "invalid compliance policy file; using fallback")
                    }
                },
                Err(err) => {
                    warn!(error = %err, path = %path, "failed reading compliance policy file; using fallback")
                }
            }
        }
    }

    if let Ok(raw) = std::env::var("EGUARD_COMPLIANCE_POLICY_JSON") {
        let raw = raw.trim();
        if !raw.is_empty() {
            match parse_policy_json(raw) {
                Ok(policy) => return policy,
                Err(err) => {
                    warn!(error = %err, "invalid EGUARD_COMPLIANCE_POLICY_JSON; using fallback")
                }
            }
        }
    }

    CompliancePolicy {
        firewall_required: true,
        min_kernel_prefix: Some("5.".to_string()),
        disk_encryption_required: true,
        require_ssh_root_login_disabled: true,
        password_policy_required: true,
        screen_lock_required: true,
        auto_updates_required: true,
        antivirus_required: true,
        ..CompliancePolicy::default()
    }
}

pub(super) fn verify_policy_envelope(policy: &PolicyEnvelope) -> bool {
    if policy.policy_json.trim().is_empty() {
        return true;
    }

    let computed_hash = policy_hash_hex(policy.policy_json.as_bytes());
    if !policy.policy_hash.trim().is_empty()
        && !normalize_hash(&policy.policy_hash)
            .map(|hash| hash == computed_hash)
            .unwrap_or(false)
    {
        warn!("policy hash mismatch; rejecting policy update");
        return false;
    }

    if policy.policy_signature.trim().is_empty() {
        return true;
    }

    let Some(public_key) = resolve_policy_public_key() else {
        warn!("policy signature provided but no public key configured; rejecting policy update");
        return false;
    };

    let Some(signature) = decode_hex_bytes(policy.policy_signature.trim()) else {
        warn!("invalid policy signature encoding; rejecting policy update");
        return false;
    };
    if signature.len() != 64 {
        warn!("invalid policy signature length; rejecting policy update");
        return false;
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&signature);

    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&public_key) {
        Ok(key) => key,
        Err(err) => {
            warn!(error = %err, "invalid policy public key");
            return false;
        }
    };

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    if let Err(err) = verifying_key.verify(policy.policy_json.as_bytes(), &signature) {
        warn!(error = %err, "policy signature verification failed");
        return false;
    }

    true
}

fn resolve_policy_public_key() -> Option<[u8; 32]> {
    if let Ok(path) = std::env::var("EGUARD_POLICY_PUBKEY_PATH") {
        let path = path.trim();
        if !path.is_empty() {
            match std::fs::read(path) {
                Ok(raw) => {
                    if let Some(key) = parse_ed25519_key_material(&raw) {
                        return Some(key);
                    }
                    warn!(path = %path, "invalid policy Ed25519 public key contents");
                }
                Err(err) => {
                    warn!(error = %err, path = %path, "failed reading policy public key")
                }
            }
        }
    }

    if let Ok(raw) = std::env::var("EGUARD_POLICY_PUBKEY") {
        return parse_ed25519_key_material(raw.as_bytes());
    }

    None
}

fn policy_hash_hex(raw: &[u8]) -> String {
    let digest = Sha256::digest(raw);
    format!("{:x}", digest)
}

fn normalize_hash(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches("sha256:").trim();
    if trimmed.len() != 64 {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

pub(super) fn update_tls_policy_from_server(
    config: &mut AgentConfig,
    policy: &PolicyEnvelope,
) -> bool {
    let Some(cert_policy) = policy.certificate_policy.as_ref() else {
        return false;
    };

    let mut changed = false;

    let pinned = cert_policy.pinned_ca_sha256.trim();
    if !pinned.is_empty() && config.tls_pinned_ca_sha256.as_deref() != Some(pinned) {
        config.tls_pinned_ca_sha256 = Some(pinned.to_string());
        changed = true;
    }

    if cert_policy.rotate_before_expiry_days > 0 {
        let days = cert_policy.rotate_before_expiry_days as u64;
        if config.tls_rotate_before_expiry_days != days {
            config.tls_rotate_before_expiry_days = days;
            changed = true;
        }
    }

    changed
}

#[cfg(test)]
pub(super) fn days_until_certificate_expiry(cert_path: &str, now_unix: i64) -> Result<i64> {
    let cert_bytes = std::fs::read(cert_path)
        .map_err(|err| anyhow!("read certificate '{}': {}", cert_path, err))?;
    let not_after_unix = parse_certificate_not_after_unix(&cert_bytes)?;
    Ok((not_after_unix - now_unix) / SECONDS_PER_DAY)
}

#[cfg(test)]
pub(super) fn parse_certificate_not_after_unix(cert_bytes: &[u8]) -> Result<i64> {
    let der = if cert_bytes.starts_with(b"-----BEGIN") {
        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_bytes)
            .map_err(|err| anyhow!("parse certificate PEM: {}", err))?;
        pem.contents
    } else {
        cert_bytes.to_vec()
    };

    let (_, cert) = x509_parser::prelude::parse_x509_certificate(&der)
        .map_err(|err| anyhow!("parse X509 certificate DER payload: {}", err))?;
    Ok(cert.validity().not_after.timestamp())
}
