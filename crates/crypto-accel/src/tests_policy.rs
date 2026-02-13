use std::path::PathBuf;

use sha2::{Digest, Sha256};

use super::*;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: impl AsRef<std::path::Path>) -> String {
    std::fs::read_to_string(path).expect("read source")
}

#[test]
// AC-ASM-001 AC-ASM-002 AC-ASM-003 AC-ASM-004 AC-ASM-010 AC-ASM-022 AC-DET-110 AC-DET-111
fn asm_primitives_exist_and_detection_logic_stays_in_rust() {
    let root = repo_root();
    let sha = read(root.join("zig/asm/sha256_ni.zig"));
    let aes = read(root.join("zig/asm/aes_ni.zig"));
    let det_engine = read(root.join("crates/detection/src/engine.rs"));

    assert!(sha.contains("pub export fn sha256_ni_available()"));
    assert!(sha.contains("pub export fn sha256_ni_hash"));
    assert!(sha.contains("cpuid"));
    assert!(aes.contains("pub export fn aes_ni_available()"));
    assert!(aes.contains("pub export fn aes_ni_encrypt_block"));
    assert!(aes.contains("cpuid"));

    // Detection decisions are made by Rust layers/policy, not asm sources.
    assert!(det_engine.contains("confidence_policy"));
    assert!(!det_engine.contains("extern \"C\""));
}

#[test]
// AC-ASM-020 AC-ASM-021 AC-ASM-023 AC-ASM-027 AC-DET-112 AC-DET-118
fn asm_build_and_abi_contract_are_declared() {
    let root = repo_root();
    let build = read(root.join("crates/crypto-accel/build.rs"));
    let ffi = read(root.join("crates/crypto-accel/src/lib.rs"));
    let asm_dir = root.join("zig/asm");

    assert!(asm_dir.join("sha256_ni.zig").exists());
    assert!(asm_dir.join("aes_ni.zig").exists());
    assert!(asm_dir.join("integrity.zig").exists());

    assert!(build.contains("zig"));
    assert!(build.contains("build-lib"));
    assert!(build.contains("ReleaseFast"));
    assert!(build.contains("cargo:rustc-link-lib=static="));

    assert!(ffi.contains("unsafe extern \"C\""));
    assert!(ffi.contains("fn sha256_ni_available() -> bool;"));
    assert!(ffi.contains("fn sha256_ni_hash(data: *const u8, len: usize, out: *mut u8) -> i32;"));
    assert!(ffi.contains("fn aes_ni_available() -> bool;"));
    assert!(ffi.contains(
        "fn aes_ni_encrypt_block(key: *const u8, input: *const u8, out: *mut u8) -> i32;"
    ));
    assert!(ffi.contains(
        "fn integrity_check_sha256(data: *const u8, len: usize, expected_digest: *const u8) -> bool;"
    ));
}

#[test]
// AC-ASM-011 AC-ASM-028 AC-ASM-029 AC-DET-113 AC-DET-114
fn runtime_feature_dispatch_and_fallback_paths_exist() {
    let root = repo_root();
    let lib = read(root.join("crates/crypto-accel/src/lib.rs"));
    let sha = read(root.join("zig/asm/sha256_ni.zig"));
    let aes = read(root.join("zig/asm/aes_ni.zig"));

    assert!(sha.contains("sha256_ni_available()"));
    assert!(sha.contains("if (!sha256_ni_available())"));
    assert!(aes.contains("aes_ni_available()"));
    assert!(aes.contains("if (!aes_ni_available())"));

    assert!(lib.contains("#[cfg(not(crypto_accel_zig))]"));
    assert!(lib.contains("let digest = Sha256::digest(data);"));
    assert!(lib.contains("Err(CryptoAccelError::InvalidInput(\"aes-ni backend unavailable\"))"));
}

#[test]
// AC-ASM-024 AC-ASM-025 AC-DET-115 AC-DET-116
fn asm_sources_forbid_heap_state_and_syscalls() {
    let root = repo_root();
    for file in ["sha256_ni.zig", "aes_ni.zig", "integrity.zig"] {
        let src = read(root.join("zig/asm").join(file));

        // No global mutable state retained by asm primitive modules.
        assert!(!src.contains("pub var "));

        // No allocator/heap APIs.
        for forbidden in ["std.heap", "allocator", "malloc", "free", "new", "delete"] {
            assert!(
                !src.contains(forbidden),
                "forbidden token in {file}: {forbidden}"
            );
        }

        // No file/network/syscall-like operations.
        for forbidden in [
            "open(", "read(", "write(", "socket(", "connect(", "bind(", "listen(", "accept(",
            "mmap(",
        ] {
            assert!(
                !src.contains(forbidden),
                "forbidden token in {file}: {forbidden}"
            );
        }
    }
}

#[test]
// AC-ASM-026 AC-DET-117
fn rust_wrappers_own_allocation_and_pass_bounded_buffers() {
    let lib = read(repo_root().join("crates/crypto-accel/src/lib.rs"));

    assert!(lib.contains("let mut out = [0u8; SHA256_DIGEST_LEN];"));
    assert!(lib.contains("let mut out = [0u8; 16];"));
    assert!(lib.contains("data.as_ptr(), data.len(), out.as_mut_ptr()"));
    assert!(lib.contains("expected_digest: &[u8; SHA256_DIGEST_LEN]"));
}

#[test]
// AC-ASM-030 AC-DET-120
fn differential_randomized_sha256_matches_reference() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;

    for n in 0..256usize {
        let len = (n * 131) % 4096;
        let mut data = vec![0u8; len];
        for byte in &mut data {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state & 0xFF) as u8;
        }

        let got = sha256_digest(&data);
        let expected = Sha256::digest(&data);
        assert_eq!(got.as_slice(), expected.as_slice());
    }
}

#[test]
// AC-ASM-031 AC-DET-121
fn ffi_boundary_randomized_lengths_alignment_and_malformed_inputs_do_not_panic() {
    let mut state: u64 = 0xD1B5_4A32_94C2_17EF;

    for i in 0..512usize {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let base_len = (state as usize) % 2048;
        let pad = i % 16;
        let mut raw = vec![0u8; base_len + pad + 1];
        for b in &mut raw {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            *b = (state & 0xFF) as u8;
        }

        let view = &raw[pad..pad + base_len];
        let digest = sha256_digest(view);
        assert!(verify_integrity_sha256(view, &digest));
        assert!(!verify_integrity_sha256(&raw[..pad], &digest));
    }
}

#[test]
// AC-ASM-032 AC-ASM-033 AC-DET-122 AC-DET-123
fn soak_and_sanitizer_harnesses_are_declared_for_ci() {
    let root = repo_root();
    let soak = read(root.join("scripts/run_asm_soak_ci.sh"));
    let asan_workflow = read(root.join(".github/workflows/asm-sanitizer.yml"));

    assert!(soak.contains("MIN_SOAK_HOURS=24"));
    assert!(soak.contains("EGUARD_SOAK_HOURS"));
    assert!(asan_workflow.contains("ASAN"));
    assert!(asan_workflow.contains("LSAN"));
}

#[test]
// AC-ASM-034 AC-ASM-040 AC-DET-124
fn symbol_audit_and_size_budget_harnesses_are_declared() {
    let root = repo_root();
    let audit = read(root.join("scripts/run_asm_symbol_audit_ci.sh"));

    for blocked in ["malloc", "free", "new", "delete"] {
        assert!(audit.contains(blocked));
    }
    assert!(audit.contains("MAX_COMPRESSED_KB=50"));
    assert!(audit.contains("nm -u"));
}
