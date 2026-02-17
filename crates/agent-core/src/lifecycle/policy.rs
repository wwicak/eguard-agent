use tracing::warn;

use compliance::{parse_policy_json, CompliancePolicy};
use grpc_client::PolicyEnvelope;

use crate::config::AgentConfig;

#[cfg(test)]
use anyhow::{anyhow, Result};
#[cfg(test)]
use super::SECONDS_PER_DAY;

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
        min_kernel_prefix: None,
        ..CompliancePolicy::default()
    }
}

pub(super) fn update_tls_policy_from_server(config: &mut AgentConfig, policy: &PolicyEnvelope) -> bool {
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
    let cert_bytes =
        std::fs::read(cert_path).map_err(|err| anyhow!("read certificate '{}': {}", cert_path, err))?;
    let not_after_unix = parse_certificate_not_after_unix(&cert_bytes)?;
    Ok((not_after_unix - now_unix) / SECONDS_PER_DAY)
}

#[cfg(test)]
pub(super) fn parse_certificate_not_after_unix(cert_bytes: &[u8]) -> Result<i64> {
    let der = if cert_bytes.starts_with(b"-----BEGIN") {
        let (_, pem) =
            x509_parser::pem::parse_x509_pem(cert_bytes).map_err(|err| anyhow!("parse certificate PEM: {}", err))?;
        pem.contents
    } else {
        cert_bytes.to_vec()
    };

    let (_, cert) = x509_parser::prelude::parse_x509_certificate(&der)
        .map_err(|err| anyhow!("parse X509 certificate DER payload: {}", err))?;
    Ok(cert.validity().not_after.timestamp())
}
