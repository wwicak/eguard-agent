use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};

use super::constants::{
    ENCRYPTED_CONFIG_AAD, ENCRYPTED_CONFIG_PREFIX, MACHINE_ID_PATH_ENV, TPM2_MATERIAL_ENV,
};
use super::util::{env_non_empty, non_empty};

pub(super) fn read_agent_config_text(path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading config file {}", path.display()))?;
    if !raw.trim_start().starts_with(ENCRYPTED_CONFIG_PREFIX) {
        return Ok(raw);
    }

    decrypt_agent_config_payload(raw.trim())
}

fn decrypt_agent_config_payload(raw: &str) -> Result<String> {
    let encoded = raw
        .strip_prefix(ENCRYPTED_CONFIG_PREFIX)
        .context("invalid encrypted config prefix")?
        .trim();
    let blob = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("invalid base64 payload for encrypted agent config")?;
    if blob.len() <= 12 {
        anyhow::bail!("encrypted agent config payload is too short");
    }

    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let key = derive_encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).context("invalid AES-256 key material")?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: ENCRYPTED_CONFIG_AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("failed decrypting encrypted agent config"))?;

    String::from_utf8(plaintext).context("decrypted agent config is not valid UTF-8")
}

fn derive_encryption_key() -> Result<[u8; 32]> {
    let machine_id = read_machine_id_material()?;
    let tpm_material = env_non_empty(TPM2_MATERIAL_ENV);
    Ok(derive_encryption_key_from_material(
        &machine_id,
        tpm_material.as_deref(),
    ))
}

fn read_machine_id_material() -> Result<String> {
    let path = std::env::var(MACHINE_ID_PATH_ENV)
        .ok()
        .and_then(|v| non_empty(Some(v)))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/machine-id"));

    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed reading machine-id from {}", path.display()))?;
    let machine_id = raw.trim();
    if machine_id.is_empty() {
        anyhow::bail!("machine-id from {} is empty", path.display());
    }
    Ok(machine_id.to_string())
}

fn derive_encryption_key_from_material(machine_id: &str, tpm_material: Option<&str>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    hasher.update(b"\n");
    if let Some(tpm_material) = tpm_material {
        hasher.update(tpm_material.as_bytes());
    }
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

#[cfg(test)]
pub(super) fn encrypt_agent_config_for_tests(
    plaintext: &str,
    machine_id: &str,
    tpm_material: Option<&str>,
    nonce_bytes: [u8; 12],
) -> Result<String> {
    let key = derive_encryption_key_from_material(machine_id, tpm_material);
    let cipher = Aes256Gcm::new_from_slice(&key).context("invalid AES-256 key material")?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext.as_bytes(),
                aad: ENCRYPTED_CONFIG_AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("failed encrypting test agent config"))?;

    let mut blob = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(format!(
        "{}{}",
        ENCRYPTED_CONFIG_PREFIX,
        base64::engine::general_purpose::STANDARD.encode(blob)
    ))
}
