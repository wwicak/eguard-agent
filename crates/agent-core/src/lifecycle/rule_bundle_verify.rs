use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use tracing::warn;

use super::MAX_SIGNED_RULE_BUNDLE_BYTES;

pub(super) fn verify_bundle_signature(bundle_path: &Path) -> bool {
    let Some(public_key) = resolve_rule_bundle_public_key() else {
        warn!("rule bundle public key is not configured; set EGUARD_RULE_BUNDLE_PUBKEY_PATH or EGUARD_RULE_BUNDLE_PUBKEY");
        return false;
    };

    let Some(signature_path) = resolve_bundle_signature_path(bundle_path) else {
        warn!(path = %bundle_path.display(), "bundle signature sidecar file not found");
        return false;
    };

    match verify_bundle_signature_with_material(bundle_path, &signature_path, public_key) {
        Ok(()) => true,
        Err(err) => {
            warn!(
                error = %err,
                bundle = %bundle_path.display(),
                signature = %signature_path.display(),
                "bundle signature verification failed"
            );
            false
        }
    }
}

pub(super) fn resolve_rule_bundle_public_key() -> Option<[u8; 32]> {
    if let Ok(path) = std::env::var("EGUARD_RULE_BUNDLE_PUBKEY_PATH") {
        let path = path.trim();
        if !path.is_empty() {
            match fs::read(path) {
                Ok(raw) => {
                    if let Some(key) = parse_ed25519_key_material(&raw) {
                        return Some(key);
                    }
                    warn!(path = %path, "invalid Ed25519 public key file contents");
                }
                Err(err) => {
                    warn!(error = %err, path = %path, "failed reading Ed25519 public key file")
                }
            }
        }
    }

    if let Ok(raw) = std::env::var("EGUARD_RULE_BUNDLE_PUBKEY") {
        return parse_ed25519_key_material(raw.as_bytes());
    }

    None
}

pub(super) fn resolve_bundle_signature_path(bundle_path: &Path) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    candidates.push(PathBuf::from(format!(
        "{}.sig",
        bundle_path.to_string_lossy()
    )));
    candidates.push(bundle_path.with_extension("sig"));

    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

pub(super) fn verify_bundle_signature_with_material(
    bundle_path: &Path,
    signature_path: &Path,
    public_key: [u8; 32],
) -> std::result::Result<(), String> {
    let bundle_bytes = read_file_limited(bundle_path, MAX_SIGNED_RULE_BUNDLE_BYTES)?;
    let signature_raw = fs::read(signature_path)
        .map_err(|err| format!("read signature {}: {}", signature_path.display(), err))?;
    let signature_bytes = parse_ed25519_signature_material(&signature_raw)
        .ok_or_else(|| format!("invalid signature material in {}", signature_path.display()))?;

    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|err| format!("invalid Ed25519 public key: {}", err))?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(&bundle_bytes, &signature)
        .map_err(|err| format!("signature mismatch: {}", err))
}

pub(super) fn read_file_limited(
    path: &Path,
    max_bytes: u64,
) -> std::result::Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|err| format!("stat {}: {}", path.display(), err))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "file {} exceeds max size ({} > {})",
            path.display(),
            metadata.len(),
            max_bytes
        ));
    }

    let mut file =
        fs::File::open(path).map_err(|err| format!("open {}: {}", path.display(), err))?;
    let mut out = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut out)
        .map_err(|err| format!("read {}: {}", path.display(), err))?;
    Ok(out)
}

pub(super) fn parse_ed25519_key_material(raw: &[u8]) -> Option<[u8; 32]> {
    parse_fixed_key_material(raw, 32)
}

fn parse_ed25519_signature_material(raw: &[u8]) -> Option<[u8; 64]> {
    parse_fixed_key_material(raw, 64)
}

fn parse_fixed_key_material<const N: usize>(raw: &[u8], expected_len: usize) -> Option<[u8; N]> {
    if raw.len() == expected_len {
        let mut out = [0u8; N];
        out.copy_from_slice(raw);
        return Some(out);
    }

    let text = std::str::from_utf8(raw).ok()?.trim();
    let bytes = decode_hex_bytes(text)?;
    if bytes.len() != expected_len {
        return None;
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Some(out)
}

pub(super) fn decode_hex_bytes(raw: &str) -> Option<Vec<u8>> {
    let normalized = raw
        .trim()
        .strip_prefix("0x")
        .or_else(|| raw.trim().strip_prefix("0X"))
        .unwrap_or(raw.trim());

    let compact = normalized
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    if compact.len() % 2 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(compact.len() / 2);
    let bytes = compact.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let hi = decode_hex_nibble(bytes[idx])?;
        let lo = decode_hex_nibble(bytes[idx + 1])?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Some(out)
}

fn decode_hex_nibble(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}
