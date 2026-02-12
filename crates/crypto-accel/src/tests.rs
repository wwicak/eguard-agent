
use super::*;

#[test]
// AC-ASM-005
fn sha256_matches_known_vector() {
    let digest = sha256_hex(b"abc");
    assert_eq!(
        digest,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
// AC-ATP-001
fn integrity_verification_matches_hash() {
    let digest = sha256_digest(b"eguard");
    assert!(verify_integrity_sha256(b"eguard", &digest));
    assert!(!verify_integrity_sha256(b"eguard2", &digest));
}

#[test]
// AC-ASM-012
fn aes_block_encrypt_known_vector_or_clean_fallback() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let input = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    match aes256_encrypt_block(&key, &input) {
        Ok(out) => assert_eq!(
            out,
            [
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89,
            ]
        ),
        Err(CryptoAccelError::InvalidInput(_)) => {
            assert!(!aes_available(), "aes backend should be unavailable")
        }
        Err(other) => panic!("unexpected aes error: {other}"),
    }
}

#[test]
// AC-ASM-005
fn sha256_file_hex_matches_in_memory_hash_for_small_file() {
    let path = std::env::temp_dir().join(format!(
        "eguard-crypto-small-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::write(&path, b"small-file-payload").expect("write small file");

    let file_hash = sha256_file_hex(&path).expect("hash small file");
    assert_eq!(file_hash, sha256_hex(b"small-file-payload"));

    let _ = std::fs::remove_file(path);
}

#[test]
// AC-ASM-005
fn sha256_file_hex_uses_streaming_path_for_large_files() {
    let path = std::env::temp_dir().join(format!(
        "eguard-crypto-large-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let payload = vec![0x5Au8; 9 * 1024 * 1024];
    std::fs::write(&path, &payload).expect("write large file");

    let file_hash = sha256_file_hex(&path).expect("hash large file");
    assert_eq!(file_hash, sha256_hex(&payload));

    let _ = std::fs::remove_file(path);
}
