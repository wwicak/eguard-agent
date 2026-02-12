use std::fmt;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

pub const SHA256_DIGEST_LEN: usize = 32;

#[derive(Debug)]
pub enum CryptoAccelError {
    InvalidInput(&'static str),
    ZigBackend(i32),
    Io(std::io::Error),
}

impl fmt::Display for CryptoAccelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "invalid input: {}", msg),
            Self::ZigBackend(code) => write!(f, "zig backend returned error code {}", code),
            Self::Io(err) => write!(f, "io error: {}", err),
        }
    }
}

impl std::error::Error for CryptoAccelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CryptoAccelError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(crypto_accel_zig)]
unsafe extern "C" {
    fn sha256_ni_available() -> bool;
    fn sha256_ni_hash(data: *const u8, len: usize, out: *mut u8) -> i32;

    fn aes_ni_available() -> bool;
    fn aes_ni_encrypt_block(key: *const u8, input: *const u8, out: *mut u8) -> i32;

    fn integrity_check_sha256(data: *const u8, len: usize, expected_digest: *const u8) -> bool;
}

pub fn sha256_available() -> bool {
    #[cfg(crypto_accel_zig)]
    {
        // SAFETY: No preconditions for the C ABI availability probe.
        return unsafe { sha256_ni_available() };
    }

    #[cfg(not(crypto_accel_zig))]
    {
        false
    }
}

pub fn aes_available() -> bool {
    #[cfg(crypto_accel_zig)]
    {
        // SAFETY: No preconditions for the C ABI availability probe.
        return unsafe { aes_ni_available() };
    }

    #[cfg(not(crypto_accel_zig))]
    {
        false
    }
}

pub fn sha256_digest(data: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let mut out = [0u8; SHA256_DIGEST_LEN];

    #[cfg(crypto_accel_zig)]
    {
        if sha256_available() {
            // SAFETY: pointers are derived from valid Rust slices and out buffer is sized to 32 bytes.
            let status = unsafe { sha256_ni_hash(data.as_ptr(), data.len(), out.as_mut_ptr()) };
            if status == 0 {
                return out;
            }
        }
    }

    let digest = Sha256::digest(data);
    out.copy_from_slice(&digest);
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256_digest(data);
    to_hex(&digest)
}

pub fn sha256_file_hex(path: &Path) -> Result<String, CryptoAccelError> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() <= 8 * 1024 * 1024 {
        let data = std::fs::read(path)?;
        return Ok(sha256_hex(&data));
    }

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(to_hex(&hasher.finalize()))
}

pub fn aes256_encrypt_block(
    key: &[u8; 32],
    input: &[u8; 16],
) -> Result<[u8; 16], CryptoAccelError> {
    if !aes_available() {
        return Err(CryptoAccelError::InvalidInput("aes-ni backend unavailable"));
    }

    #[cfg(crypto_accel_zig)]
    {
        let mut out = [0u8; 16];
        // SAFETY: pointers are valid and point to fixed-size arrays expected by the C ABI.
        let status =
            unsafe { aes_ni_encrypt_block(key.as_ptr(), input.as_ptr(), out.as_mut_ptr()) };
        if status == 0 {
            return Ok(out);
        }
        return Err(CryptoAccelError::ZigBackend(status));
    }

    #[cfg(not(crypto_accel_zig))]
    {
        let _ = key;
        let _ = input;
        Err(CryptoAccelError::InvalidInput("aes-ni backend unavailable"))
    }
}

pub fn verify_integrity_sha256(data: &[u8], expected_digest: &[u8; SHA256_DIGEST_LEN]) -> bool {
    #[cfg(crypto_accel_zig)]
    {
        // SAFETY: pointers are valid and expected_digest is exactly 32 bytes.
        return unsafe {
            integrity_check_sha256(data.as_ptr(), data.len(), expected_digest.as_ptr())
        };
    }

    #[cfg(not(crypto_accel_zig))]
    {
        &sha256_digest(data) == expected_digest
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        let digest = sha256_hex(b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn integrity_verification_matches_hash() {
        let digest = sha256_digest(b"eguard");
        assert!(verify_integrity_sha256(b"eguard", &digest));
        assert!(!verify_integrity_sha256(b"eguard2", &digest));
    }

    #[test]
    fn aes_block_encrypt_known_vector_or_clean_fallback() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let input = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];

        match aes256_encrypt_block(&key, &input) {
            Ok(out) => assert_eq!(
                out,
                [
                    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49,
                    0x90, 0x4b, 0x49, 0x60, 0x89,
                ]
            ),
            Err(CryptoAccelError::InvalidInput(_)) => {
                assert!(!aes_available(), "aes backend should be unavailable")
            }
            Err(other) => panic!("unexpected aes error: {other}"),
        }
    }
}
