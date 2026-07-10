use super::*;
use crate::ResponseError;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::Mutex;

#[test]
// AC-RSP-032
fn restore_quarantined_file_writes_destination() {
    let base = std::env::temp_dir().join(format!(
        "eguard-restore-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create base");

    let src = base.join("quarantine.bin");
    let dst = base.join("restored.bin");
    fs::write(&src, b"payload").expect("write src");

    let report = restore_quarantined(&src, &dst, 0o600).expect("restore file");
    assert_eq!(report.restored_path, dst);
    assert_eq!(
        fs::read(&report.restored_path).expect("read restored"),
        b"payload"
    );
    assert!(
        !src.exists(),
        "quarantine source should be removed after restore"
    );

    let _ = fs::remove_file(report.restored_path);
    let _ = fs::remove_dir(base);
}

#[test]
// AC-RSP-024
fn protected_path_is_rejected_before_quarantine() {
    let protected = ProtectedList::default_linux();
    let path = Path::new("/usr/bin/ls");
    let err =
        quarantine_file(path, "sha256-test", &protected).expect_err("protected path rejected");

    assert!(matches!(err, ResponseError::ProtectedPath(p) if p == path));
}

#[test]
#[cfg(unix)]
fn quarantine_rejects_intermediate_symlink_into_protected_root() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-symlink-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let protected_dir = base.join("protected");
    let alias_dir = base.join("alias");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&protected_dir).expect("create protected dir");
    let protected_dir = fs::canonicalize(&protected_dir).expect("canonical protected dir");
    std::os::unix::fs::symlink(&protected_dir, &alias_dir).expect("create symlink dir");

    let target = protected_dir.join("payload.bin");
    let payload = b"protected payload";
    fs::write(&target, payload).expect("write protected target");
    let alias_path = alias_dir.join("payload.bin");
    let protected = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: vec![protected_dir.clone()],
    };

    let err = quarantine_file_with_dir(&alias_path, "deadbeef", &protected, &quarantine_dir)
        .expect_err("canonical protected path rejected");

    assert!(matches!(err, ResponseError::ProtectedPath(p) if p == target));
    assert_eq!(fs::read(&target).expect("target remains"), payload);
    assert!(!quarantine_dir.join("deadbeef").exists());

    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(windows)]
fn quarantine_rejects_junction_into_protected_root() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-junction-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let protected_dir = base.join("protected");
    let alias_dir = base.join("alias");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&protected_dir).expect("create protected dir");
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&alias_dir)
        .arg(&protected_dir)
        .output()
        .expect("run mklink");
    assert!(
        output.status.success(),
        "mklink failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let target = protected_dir.join("payload.bin");
    let payload = b"protected payload";
    fs::write(&target, payload).expect("write protected target");
    let expected_path = normalize_path(&fs::canonicalize(&target).expect("canonical target"));
    let protected = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: vec![protected_dir.clone()],
    };

    let err = quarantine_file_with_dir(
        &alias_dir.join("payload.bin"),
        "deadbeef",
        &protected,
        &quarantine_dir,
    )
    .expect_err("junction target inside protected root rejected");

    assert!(matches!(err, ResponseError::ProtectedPath(p) if p == expected_path));
    assert_eq!(fs::read(&target).expect("target remains"), payload);
    assert!(!quarantine_dir.join("deadbeef").exists());

    let _ = fs::remove_dir(&alias_dir);
    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(windows)]
fn quarantine_report_uses_deverbatimized_canonical_original_path() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-windows-report-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&base).expect("create base");
    let original = base.join("payload.bin");
    fs::write(&original, b"payload").expect("write original");
    let expected_path = normalize_path(&fs::canonicalize(&original).expect("canonical original"));
    let protected = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: vec![base.join("different-protected-root")],
    };

    let report = quarantine_file_with_dir(&original, "deadbeef", &protected, &quarantine_dir)
        .expect("quarantine unprotected file");

    assert_eq!(report.original_path, expected_path);
    assert!(!report.original_path.to_string_lossy().starts_with(r"\\?\"));

    let mut permissions = fs::metadata(&report.quarantine_path)
        .expect("stat quarantined file")
        .permissions();
    permissions.set_readonly(false);
    fs::set_permissions(&report.quarantine_path, permissions).expect("restore permissions");
    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(unix)]
fn quarantine_allows_intermediate_symlink_to_unprotected_target_and_reports_canonical_path() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-symlink-happy-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let target_dir = base.join("target");
    let alias_dir = base.join("alias");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&target_dir).expect("create target dir");
    let target_dir = fs::canonicalize(&target_dir).expect("canonical target dir");
    std::os::unix::fs::symlink(&target_dir, &alias_dir).expect("create symlink dir");

    let target = target_dir.join("payload.bin");
    let payload = b"unprotected payload";
    fs::write(&target, payload).expect("write target");
    let alias_path = alias_dir.join("payload.bin");
    let protected = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: vec![base.join("different-protected-root")],
    };

    let report = quarantine_file_with_dir(&alias_path, "cafebabe", &protected, &quarantine_dir)
        .expect("unprotected canonical target quarantined");

    assert_eq!(report.original_path, target);
    assert_eq!(report.quarantine_path, quarantine_dir.join("cafebabe"));
    assert!(!target.exists());
    assert!(!alias_path.exists());
    #[cfg(unix)]
    fs::set_permissions(&report.quarantine_path, fs::Permissions::from_mode(0o600))
        .expect("restore perms for readback");
    assert_eq!(
        fs::read(&report.quarantine_path).expect("read quarantined"),
        payload
    );

    let _ = fs::remove_dir_all(base);
}

#[test]
fn macos_directory_services_record_is_rejected_before_quarantine() {
    let protected = ProtectedList::default_macos();
    let path = Path::new("/var/db/dslocal/nodes/Default/users/root.plist");
    let err = quarantine_file(path, "deadbeef", &protected).expect_err("protected path rejected");

    assert!(matches!(err, ResponseError::ProtectedPath(p) if p == path));
}

#[test]
fn quarantine_runtime_entrypoint_moves_file_and_reports_fields() {
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    struct EnvVarReset;
    impl Drop for EnvVarReset {
        fn drop(&mut self) {
            std::env::remove_var("EGUARD_TEST_QUARANTINE_DIR");
        }
    }

    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-runtime-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&base).expect("create base");

    let original = base.join("runtime.bin");
    let original_bytes = b"runtime quarantine payload".to_vec();
    fs::write(&original, &original_bytes).expect("write original");
    #[cfg(unix)]
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o640))
        .expect("chmod original");
    #[cfg(unix)]
    let metadata = fs::metadata(&original).expect("stat original");

    let protected = ProtectedList::default_linux();
    assert!(
        !protected.is_protected_path(&original),
        "test source must be outside protected paths"
    );

    let hash = "abcdef0123456789abcdef0123456789";
    std::env::set_var("EGUARD_TEST_QUARANTINE_DIR", &quarantine_dir);
    let _env_reset = EnvVarReset;
    let report = quarantine_file(&original, hash, &protected).expect("quarantine file");

    assert_eq!(report.original_path, original);
    assert!(!report.sha256.is_empty());
    assert_eq!(report.sha256, hash);
    assert_eq!(report.file_size, original_bytes.len() as u64);
    #[cfg(unix)]
    {
        assert_eq!(report.original_mode, metadata.mode());
        assert_eq!(report.owner_uid, metadata.uid());
        assert_eq!(report.owner_gid, metadata.gid());
    }
    assert_eq!(report.quarantine_path, quarantine_dir.join(hash));
    assert!(report.quarantine_path.exists());
    #[cfg(unix)]
    fs::set_permissions(&report.quarantine_path, fs::Permissions::from_mode(0o600))
        .expect("restore perms for readback");
    assert_eq!(
        fs::read(&report.quarantine_path).expect("read quarantined file"),
        original_bytes
    );
    assert!(!original.exists());

    let _ = fs::remove_dir_all(base);
}

#[test]
// AC-RSP-025 AC-RSP-026 AC-RSP-029 AC-RSP-030
fn quarantine_with_custom_dir_copies_metadata_and_removes_original() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&base).expect("create base");

    let original = base.join("sample.bin");
    let original_bytes = b"hello quarantine".to_vec();
    fs::write(&original, &original_bytes).expect("write original");
    #[cfg(unix)]
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o640))
        .expect("chmod original");

    let protected = ProtectedList::default_linux();
    let report = quarantine_file_with_dir(&original, "deadbeef", &protected, &quarantine_dir)
        .expect("quarantine file");

    assert_eq!(report.original_path, original);
    assert_eq!(report.sha256, "deadbeef");
    assert_eq!(report.file_size, original_bytes.len() as u64);
    #[cfg(unix)]
    assert!(report.original_mode & 0o777 != 0);
    assert!(!report.quarantine_path.as_os_str().is_empty());
    assert!(!original.exists());
    #[cfg(unix)]
    fs::set_permissions(&report.quarantine_path, fs::Permissions::from_mode(0o600))
        .expect("restore perms for readback");
    assert_eq!(
        fs::read(&report.quarantine_path).expect("read quarantined copy"),
        original_bytes
    );

    let _ = fs::remove_file(report.quarantine_path);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn quarantine_prefers_rename_within_same_filesystem() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-rename-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&base).expect("create base");

    let original = base.join("sample.bin");
    let original_bytes = b"rename quarantine".to_vec();
    fs::write(&original, &original_bytes).expect("write original");

    let protected = ProtectedList::default_linux();
    let report = quarantine_file_with_dir(&original, "feedface", &protected, &quarantine_dir)
        .expect("quarantine file");

    assert!(!original.exists());
    assert!(report.quarantine_path.exists());
    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(&report.quarantine_path)
                .expect("stat quarantined")
                .mode()
                & 0o777,
            0
        );
        fs::set_permissions(&report.quarantine_path, fs::Permissions::from_mode(0o600))
            .expect("restore perms for readback");
    }
    assert_eq!(
        fs::read(&report.quarantine_path).expect("read quarantined"),
        original_bytes
    );

    let _ = fs::remove_dir_all(base);
}

#[test]
// AC-RSP-028
fn overwrite_prefix_zeroes_only_first_four_kilobytes() {
    let base = std::env::temp_dir().join(format!(
        "eguard-overwrite-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create base");
    let file = base.join("payload.bin");

    let payload = vec![0xAB; 5000];
    fs::write(&file, &payload).expect("write payload");
    overwrite_file_prefix_with_zeros(&file, payload.len() as u64).expect("overwrite");
    let changed = fs::read(&file).expect("read changed payload");

    assert!(changed[..4096].iter().all(|b| *b == 0));
    assert!(changed[4096..].iter().all(|b| *b == 0xAB));

    let _ = fs::remove_file(file);
    let _ = fs::remove_dir_all(base);
}

#[test]
// AC-RSP-027
fn empty_sha256_is_rejected() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-invalid-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create base");
    let original = base.join("sample.bin");
    fs::write(&original, b"x").expect("write file");

    let protected = ProtectedList::default_linux();
    let err = quarantine_file_with_dir(&original, "  ", &protected, &base)
        .expect_err("empty hash should fail");
    assert!(matches!(err, ResponseError::InvalidInput(_)));

    let _ = fs::remove_file(original);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn quarantine_normalizes_uppercase_sha256_ids() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-normalize-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&base).expect("create base");

    let original = base.join("sample.bin");
    fs::write(&original, b"normalize me").expect("write original");

    let protected = ProtectedList::default_linux();
    let uppercase = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
    let report = quarantine_file_with_dir(&original, uppercase, &protected, &quarantine_dir)
        .expect("quarantine file with uppercase sha");

    assert_eq!(
        report.sha256,
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    );
    assert_eq!(
        report.quarantine_path,
        quarantine_dir.join("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    );

    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(target_os = "linux")]
// AC-RSP-031
fn default_quarantine_dir_matches_contract() {
    assert_eq!(DEFAULT_QUARANTINE_DIR, "/var/lib/eguard-agent/quarantine");
}
