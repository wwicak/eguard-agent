use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(crypto_accel_zig)");
    println!("cargo:rustc-check-cfg=cfg(crypto_accel_no_zig)");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let crate_dir = PathBuf::from(manifest_dir);
    let workspace_root = crate_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let zig_asm_dir = workspace_root.join("zig/asm");

    for rel in [
        "zig/asm/sha256_ni.zig",
        "zig/asm/aes_ni.zig",
        "zig/asm/integrity.zig",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            workspace_root.join(rel).display()
        );
    }
    println!("cargo:rerun-if-env-changed=EGUARD_SKIP_ZIG_ASM");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_arch != "x86_64" || target_os != "linux" {
        println!(
            "cargo:warning=crypto-accel: skipping zig asm for unsupported target {}-{}",
            target_arch, target_os
        );
        println!("cargo:rustc-cfg=crypto_accel_no_zig");
        return;
    }

    if env::var("EGUARD_SKIP_ZIG_ASM")
        .ok()
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        println!("cargo:warning=crypto-accel: zig asm disabled by EGUARD_SKIP_ZIG_ASM");
        println!("cargo:rustc-cfg=crypto_accel_no_zig");
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    let builds = [
        ("sha256_ni.zig", "libeguard_sha256_ni.a", "eguard_sha256_ni"),
        ("aes_ni.zig", "libeguard_aes_ni.a", "eguard_aes_ni"),
        ("integrity.zig", "libeguard_integrity.a", "eguard_integrity"),
    ];

    for (src_name, output_name, lib_name) in builds {
        let src_path = zig_asm_dir.join(src_name);
        let output_path = out_dir.join(output_name);

        let status = Command::new("zig")
            .arg("build-lib")
            .arg(&src_path)
            .arg("-O")
            .arg("ReleaseFast")
            .arg("-mcpu")
            .arg("x86_64+aes+sha")
            .arg("-fPIC")
            .arg(format!("-femit-bin={}", output_path.display()))
            .status();

        match status {
            Ok(exit) if exit.success() => {
                println!("cargo:rustc-link-search=native={}", out_dir.display());
                println!("cargo:rustc-link-lib=static={}", lib_name);
            }
            Ok(exit) => {
                println!(
                    "cargo:warning=crypto-accel: failed building {} (exit code {:?})",
                    src_path.display(),
                    exit.code()
                );
                println!("cargo:rustc-cfg=crypto_accel_no_zig");
                return;
            }
            Err(err) => {
                println!(
                    "cargo:warning=crypto-accel: failed invoking zig for {}: {}",
                    src_path.display(),
                    err
                );
                println!("cargo:rustc-cfg=crypto_accel_no_zig");
                return;
            }
        }
    }

    println!("cargo:rustc-cfg=crypto_accel_zig");
}
