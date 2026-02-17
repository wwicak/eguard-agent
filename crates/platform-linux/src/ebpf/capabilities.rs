use std::collections::HashMap;

use super::types::EbpfStats;

/// Detect kernel capabilities for eBPF features.
pub(super) fn detect_kernel_capabilities(stats: &mut EbpfStats) {
    // Read kernel version
    if let Ok(version) = std::fs::read_to_string("/proc/version") {
        let first_line = version.lines().next().unwrap_or("");
        // Extract "X.Y.Z" from "Linux version X.Y.Z ..."
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 3 {
            stats.kernel_version = parts[2].to_string();
        }
    }

    // Check BTF availability (needed for CO-RE eBPF programs)
    stats.btf_available = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();

    // Check LSM BPF availability
    if let Ok(lsm) = std::fs::read_to_string("/sys/kernel/security/lsm") {
        stats.lsm_available = lsm.contains("bpf");
    }
}

/// Parse kernel version string into (major, minor, patch).
pub(super) fn parse_kernel_version(version: &str) -> Option<(u32, u32, u32)> {
    let stripped = version.split(['-', ' ']).next()?;
    let parts: Vec<&str> = stripped.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    let major = parts[0].parse::<u32>().ok()?;
    let minor = parts[1].parse::<u32>().ok()?;
    let patch = parts
        .get(2)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    Some((major, minor, patch))
}

/// Check if kernel meets minimum version requirement for a feature.
pub(super) fn kernel_supports(version_str: &str, min_major: u32, min_minor: u32) -> bool {
    match parse_kernel_version(version_str) {
        Some((major, minor, _)) => (major, minor) >= (min_major, min_minor),
        None => false,
    }
}

/// Build a capability report suitable for telemetry.
pub(super) fn build_capability_report(stats: &EbpfStats) -> HashMap<String, String> {
    let mut report = HashMap::new();
    report.insert("kernel_version".to_string(), stats.kernel_version.clone());
    report.insert("btf_available".to_string(), stats.btf_available.to_string());
    report.insert("lsm_available".to_string(), stats.lsm_available.to_string());
    report.insert(
        "ebpf_ring_buffer".to_string(),
        kernel_supports(&stats.kernel_version, 5, 8).to_string(),
    );
    report.insert(
        "ebpf_lsm_hooks".to_string(),
        (stats.lsm_available && kernel_supports(&stats.kernel_version, 5, 7)).to_string(),
    );
    report.insert("failed_probes".to_string(), stats.failed_probes.join(","));

    for (probe, count) in &stats.per_probe_events {
        report.insert(format!("probe_{}_events", probe), count.to_string());
    }

    report
}
