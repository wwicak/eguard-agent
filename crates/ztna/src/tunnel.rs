use anyhow::{Context, Result};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::rngs::OsRng;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct WireguardIdentity {
    pub private_key_b64: String,
    pub public_key_b64: String,
    pub storage_backend: String,
    pub storage_path: Option<PathBuf>,
}

pub fn resolve_or_create_wireguard_identity(
    agent_id: &str,
    data_dir: &Path,
) -> Result<WireguardIdentity> {
    let identity_name = if agent_id.trim().is_empty() {
        "default"
    } else {
        agent_id.trim()
    };
    let storage_path = data_dir
        .join("ztna")
        .join(format!("wireguard-{identity_name}.key"));
    if let Ok(existing) = fs::read_to_string(&storage_path) {
        if let Some(identity) =
            identity_from_private_b64(&existing, "file", Some(storage_path.clone()))
        {
            return Ok(identity);
        }
    }

    let created = generate_identity("file", Some(storage_path.clone()));
    if let Some(parent) = storage_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create ztna key dir {}", parent.display()))?;
    }
    fs::write(&storage_path, format!("{}\n", created.private_key_b64))
        .with_context(|| format!("write ztna wireguard key {}", storage_path.display()))?;
    Ok(created)
}

fn generate_identity(storage_backend: &str, storage_path: Option<PathBuf>) -> WireguardIdentity {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);
    WireguardIdentity {
        private_key_b64: base64_key(private.to_bytes()),
        public_key_b64: base64_key(public.to_bytes()),
        storage_backend: storage_backend.to_string(),
        storage_path,
    }
}

fn identity_from_private_b64(
    raw: &str,
    storage_backend: &str,
    storage_path: Option<PathBuf>,
) -> Option<WireguardIdentity> {
    let trimmed = raw.trim();
    let decoded = decode_b64_key(trimmed)?;
    let private = StaticSecret::from(decoded);
    let public = PublicKey::from(&private);
    Some(WireguardIdentity {
        private_key_b64: trimmed.to_string(),
        public_key_b64: base64_key(public.to_bytes()),
        storage_backend: storage_backend.to_string(),
        storage_path,
    })
}

fn base64_key(bytes: [u8; 32]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(bytes)
}

fn decode_b64_key(input: &str) -> Option<[u8; 32]> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let bytes = STANDARD.decode(input).ok()?;
    let array: [u8; 32] = bytes.try_into().ok()?;
    Some(array)
}

#[cfg(test)]
mod tests {
    use super::resolve_or_create_wireguard_identity;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn file_fallback_creates_and_reloads_identity() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("eguard-ztna-{unique}"));
        let first =
            resolve_or_create_wireguard_identity("agent-test", &dir).expect("create identity");
        let second =
            resolve_or_create_wireguard_identity("agent-test", &dir).expect("reload identity");
        assert_eq!(first.public_key_b64, second.public_key_b64);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
