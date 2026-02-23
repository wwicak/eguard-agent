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
    // Standalone YARA hit (file content matched a rule) → High
    if s.yara_hit {
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
