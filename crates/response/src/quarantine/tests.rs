use super::*;
use crate::ResponseError;

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
