use crate::types::{Confidence, DetectionSignals};

pub fn confidence_policy(s: &DetectionSignals) -> Confidence {
    if s.z1_exact_ioc {
        return Confidence::Definite;
    }
    let high_grade_signal_count = [
        s.z2_temporal,
        s.z4_kill_chain,
        s.exploit_indicator,
        s.tamper_indicator,
        s.vulnerable_software,
    ]
    .into_iter()
    .filter(|active| *active)
    .count();
    if high_grade_signal_count >= 2 || (s.z2_temporal && s.l1_prefilter_hit) {
        return Confidence::VeryHigh;
    }
    // YARA hit corroborated by another high-grade signal → VeryHigh
    if s.yara_hit && (s.z2_temporal || s.z4_kill_chain || s.exploit_indicator) {
        return Confidence::VeryHigh;
    }
    if s.z2_temporal || s.z4_kill_chain || s.exploit_indicator || s.tamper_indicator {
        return Confidence::High;
    }
    // Network IOC hit: dst_domain or dst_ip matched IOC list.
    // Connecting to a known C2/malicious domain or IP is high signal
    // even if the match was only a prefilter hit (not yet ExactMatch).
    if s.network_ioc_hit {
        return Confidence::High;
    }
    // Standalone YARA hit (file content matched a rule) → High
    if s.yara_hit {
        return Confidence::High;
    }
    // Actively-exploited CVE with CVSS >= 7.0 loaded at runtime → High
    if s.vulnerable_software {
        return Confidence::High;
    }
    // File Integrity Monitoring violation: critical file modified/deleted → High
    // Required for PCI-DSS 11.5 and HIPAA 164.312(c)(2) compliance.
    if s.fim_violation {
        return Confidence::High;
    }
    if s.kernel_integrity {
        return Confidence::Medium;
    }
    if s.z3_anomaly_high && !(s.z1_exact_ioc || s.z2_temporal || s.z4_kill_chain) {
        return Confidence::Medium;
    }
    if s.z3_anomaly_med && !(s.z1_exact_ioc || s.z2_temporal || s.z4_kill_chain) {
        return Confidence::Low;
    }
    Confidence::None
}
