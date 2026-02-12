use super::*;
use std::io::Write;

#[test]
fn capture_current_process_metadata() {
    let pid = std::process::id();
    let capture = capture_script_content(pid).expect("capture script content");
    assert_eq!(capture.pid, pid);
}

#[test]
// AC-RSP-044
fn files_larger_than_limit_are_not_captured() {
    let base = std::env::temp_dir().join(format!(
        "eguard-capture-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create temp dir");

    let path = base.join("oversized.script");
    let mut file = std::fs::File::create(&path).expect("create temp file");
    let payload = vec![b'A'; MAX_CAPTURE_BYTES + 1];
    file.write_all(&payload).expect("write payload");

    let err =
        read_file_capped(&path, MAX_CAPTURE_BYTES).expect_err("oversized files must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    let _ = fs::remove_file(path);
    let _ = fs::remove_dir(base);
}
