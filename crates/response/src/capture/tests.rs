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

#[test]
// AC-RSP-043
fn file_exactly_at_capture_limit_is_accepted() {
    let base = std::env::temp_dir().join(format!(
        "eguard-capture-exact-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create temp dir");

    let path = base.join("exact.script");
    let mut file = std::fs::File::create(&path).expect("create temp file");
    let payload = vec![b'B'; MAX_CAPTURE_BYTES];
    file.write_all(&payload).expect("write payload");

    let captured = read_file_capped(&path, MAX_CAPTURE_BYTES).expect("limit-sized file allowed");
    assert_eq!(captured.len(), MAX_CAPTURE_BYTES);

    let _ = fs::remove_file(path);
    let _ = fs::remove_dir(base);
}

#[test]
// AC-RSP-046
fn environ_bytes_are_normalized_to_newline_pairs() {
    let raw = b"USER=root\0SHELL=/bin/bash\0PATH=/usr/bin\0\0";
    let normalized = normalize_environ_bytes(raw).expect("normalized env");
    let lines = normalized.lines().collect::<Vec<_>>();

    assert_eq!(lines, vec!["USER=root", "SHELL=/bin/bash", "PATH=/usr/bin"]);
}

#[test]
fn empty_environ_bytes_normalize_to_none() {
    assert!(normalize_environ_bytes(b"\0\0").is_none());
}

#[cfg(unix)]
#[test]
fn nonblocking_pipe_capture_returns_without_blocking_when_writer_is_open() {
    use std::os::fd::AsRawFd;

    let (read_fd, _write_fd) = nix::unistd::pipe().expect("create pipe");
    let path = std::path::PathBuf::from(format!("/proc/self/fd/{}", read_fd.as_raw_fd()));

    let captured =
        read_pipe_nonblocking_capped(&path, MAX_CAPTURE_BYTES).expect("nonblocking read works");
    assert!(captured.is_empty());
}
