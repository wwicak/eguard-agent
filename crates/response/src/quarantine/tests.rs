use super::*;
use crate::ResponseError;
use std::os::unix::fs::PermissionsExt;

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

    let _ = fs::remove_file(src);
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
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o640))
        .expect("chmod original");

    let protected = ProtectedList::default_linux();
    let report = quarantine_file_with_dir(&original, "deadbeef", &protected, &quarantine_dir)
        .expect("quarantine file");

    assert_eq!(report.original_path, original);
    assert_eq!(report.sha256, "deadbeef");
    assert_eq!(report.file_size, original_bytes.len() as u64);
    assert!(report.original_mode & 0o777 != 0);
    assert!(!report.quarantine_path.as_os_str().is_empty());
    assert!(!original.exists());
    assert_eq!(
        fs::read(&report.quarantine_path).expect("read quarantined copy"),
        original_bytes
    );

    let _ = fs::remove_file(report.quarantine_path);
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
// AC-RSP-031
fn default_quarantine_dir_matches_contract() {
    assert_eq!(DEFAULT_QUARANTINE_DIR, "/var/lib/eguard-agent/quarantine");
}
