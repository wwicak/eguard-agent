use std::fs;
#[cfg(unix)]
use std::io::Read;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};

use super::constants::{
    CONFIG_KEY_SEED_PATH_ENV, ENCRYPTED_CONFIG_AAD, ENCRYPTED_CONFIG_PREFIX, MACHINE_ID_PATH_ENV,
    TPM2_MATERIAL_ENV,
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

    let (machine_id, tpm_material, local_seed) = read_encryption_materials()?;
    let primary_key =
        derive_encryption_key_from_material(&machine_id, tpm_material.as_deref(), &local_seed);

    let decrypt_with_key = |key: &[u8; 32]| -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key).context("invalid AES-256 key material")?;
        cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: ENCRYPTED_CONFIG_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed decrypting encrypted agent config"))
    };

    let plaintext = match decrypt_with_key(&primary_key) {
        Ok(plaintext) => plaintext,
        Err(primary_err) => {
            let legacy_key =
                derive_legacy_encryption_key_from_material(&machine_id, tpm_material.as_deref());
            decrypt_with_key(&legacy_key).map_err(|_| primary_err)?
        }
    };

    String::from_utf8(plaintext).context("decrypted agent config is not valid UTF-8")
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

fn read_encryption_materials() -> Result<(String, Option<String>, Vec<u8>)> {
    let machine_id = read_machine_id_material()?;
    let tpm_material = env_non_empty(TPM2_MATERIAL_ENV);
    let local_seed = read_or_create_local_key_seed()?;
    Ok((machine_id, tpm_material, local_seed))
}

fn read_or_create_local_key_seed() -> Result<Vec<u8>> {
    let path = std::env::var(CONFIG_KEY_SEED_PATH_ENV)
        .ok()
        .and_then(|value| non_empty(Some(value)))
        .map(PathBuf::from)
        .unwrap_or_else(default_key_seed_path);

    if let Ok(existing) = fs::read(&path) {
        if !existing.is_empty() {
            return Ok(existing);
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating key seed dir {}", parent.display()))?;
    }

    let mut seed = [0u8; 32];
    fill_random_seed(&mut seed)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("failed creating key seed {}", path.display()))?;
        file.write_all(&seed)
            .with_context(|| format!("failed writing key seed {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed syncing key seed {}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        fs::write(&path, seed)
            .with_context(|| format!("failed writing key seed {}", path.display()))?;
    }

    Ok(seed.to_vec())
}

#[cfg(target_os = "linux")]
fn default_key_seed_path() -> PathBuf {
    PathBuf::from("/var/lib/eguard-agent/config.key.seed")
}

#[cfg(target_os = "macos")]
fn default_key_seed_path() -> PathBuf {
    PathBuf::from("/Library/Application Support/eGuard/config.key.seed")
}

#[cfg(target_os = "windows")]
fn default_key_seed_path() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\eGuard\config.key.seed")
}

fn fill_random_seed(seed: &mut [u8; 32]) -> Result<()> {
    #[cfg(unix)]
    {
        let mut file = std::fs::File::open("/dev/urandom").context("open /dev/urandom")?;
        file.read_exact(seed).context("read /dev/urandom")?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        let mut hasher = Sha256::new();
        hasher.update(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos().to_le_bytes().to_vec())
                .unwrap_or_default(),
        );
        hasher.update(std::process::id().to_le_bytes());
        let digest = hasher.finalize();
        seed.copy_from_slice(&digest);
        Ok(())
    }
}

fn derive_encryption_key_from_material(
    machine_id: &str,
    tpm_material: Option<&str>,
    local_seed: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"eguard-config-key-v2\n");
    hasher.update(machine_id.as_bytes());
    hasher.update(b"\n");
    if let Some(tpm_material) = tpm_material {
        hasher.update(tpm_material.as_bytes());
    }
    hasher.update(b"\n");
    hasher.update(local_seed);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

fn derive_legacy_encryption_key_from_material(
    machine_id: &str,
    tpm_material: Option<&str>,
) -> [u8; 32] {
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
    encrypt_with_key(
        plaintext,
        derive_encryption_key_from_material(machine_id, tpm_material, b"test-config-key-seed"),
        nonce_bytes,
    )
}

#[cfg(test)]
pub(super) fn encrypt_agent_config_for_tests_legacy(
    plaintext: &str,
    machine_id: &str,
    tpm_material: Option<&str>,
    nonce_bytes: [u8; 12],
) -> Result<String> {
    encrypt_with_key(
        plaintext,
        derive_legacy_encryption_key_from_material(machine_id, tpm_material),
        nonce_bytes,
    )
}

#[cfg(test)]
fn encrypt_with_key(plaintext: &str, key: [u8; 32], nonce_bytes: [u8; 12]) -> Result<String> {
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
