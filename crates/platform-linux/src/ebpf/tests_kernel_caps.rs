use super::*;

#[test]
fn test_parse_kernel_version() {
    assert_eq!(parse_kernel_version("5.10.0"), Some((5, 10, 0)));
    assert_eq!(parse_kernel_version("6.1.0-38-amd64"), Some((6, 1, 0)));
    assert_eq!(parse_kernel_version("5.15.100"), Some((5, 15, 100)));
    assert_eq!(parse_kernel_version("invalid"), None);
}

#[test]
fn test_kernel_supports() {
    assert!(kernel_supports("5.10.0", 5, 8));
    assert!(kernel_supports("6.1.0", 5, 10));
    assert!(!kernel_supports("5.4.0", 5, 8));
    assert!(kernel_supports("5.8.0", 5, 8));
}

#[test]
fn test_detect_kernel_capabilities() {
    let mut stats = EbpfStats::default();
    detect_kernel_capabilities(&mut stats);
    assert!(!stats.kernel_version.is_empty());
}

#[test]
fn test_capability_report() {
    let mut stats = EbpfStats::default();
    stats.kernel_version = "6.1.0".to_string();
    stats.btf_available = true;
    stats.lsm_available = true;
    let report = capability_report(&stats);
    assert_eq!(report.get("kernel_version").unwrap(), "6.1.0");
    assert_eq!(report.get("ebpf_ring_buffer").unwrap(), "true");
    assert_eq!(report.get("ebpf_lsm_hooks").unwrap(), "true");
}
