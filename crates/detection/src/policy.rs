use crate::types::{Confidence, DetectionSignals};

pub fn confidence_policy(s: &DetectionSignals) -> Confidence {
    if s.z1_exact_ioc {
        return Confidence::Definite;
    }
    if s.z2_temporal && (s.z4_kill_chain || s.l1_prefilter_hit) {
        return Confidence::VeryHigh;
    }
    if s.z2_temporal || s.z4_kill_chain || s.exploit_indicator {
        return Confidence::High;
    }
    if s.z3_anomaly_high && !(s.z1_exact_ioc || s.z2_temporal || s.z4_kill_chain) {
        return Confidence::Medium;
    }
    if s.z3_anomaly_med && !(s.z1_exact_ioc || s.z2_temporal || s.z4_kill_chain) {
        return Confidence::Low;
    }
    Confidence::None
}
