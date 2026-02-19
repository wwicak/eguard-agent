use crate::information;
use crate::types::{DetectionSignals, EventClass, TelemetryEvent};

use super::constants::FEATURE_COUNT;

/// Features extracted from a single event + detection signals.
#[derive(Debug, Clone)]
pub struct MlFeatures {
    pub values: [f64; FEATURE_COUNT],
}

impl MlFeatures {
    /// Extract feature vector from detection signals and event metadata.
    pub fn extract(
        event: &TelemetryEvent,
        signals: &DetectionSignals,
        temporal_hit_count: usize,
        killchain_hit_count: usize,
        yara_hit_count: usize,
        string_sig_count: usize,
    ) -> Self {
        let mut values = [0.0f64; FEATURE_COUNT];

        // Binary detection signals (0 or 1)
        values[0] = if signals.z1_exact_ioc { 1.0 } else { 0.0 };
        values[1] = (temporal_hit_count as f64).min(3.0) / 3.0; // normalized to [0,1]
        values[2] = if signals.z3_anomaly_high { 1.0 } else { 0.0 };
        values[3] = if signals.z3_anomaly_med { 1.0 } else { 0.0 };
        values[4] = (killchain_hit_count as f64).min(3.0) / 3.0;
        values[5] = (yara_hit_count as f64).min(5.0) / 5.0;
        values[6] = (string_sig_count as f64).min(5.0) / 5.0;

        // Event metadata
        values[7] = event_class_risk_score(event.event_class);
        values[8] = if event.uid == 0 { 1.0 } else { 0.0 };
        values[9] = dst_port_risk_score(event.dst_port);
        values[10] = if event.command_line.is_some() {
            1.0
        } else {
            0.0
        };
        values[11] = cmdline_length_normalized(event.command_line.as_deref());
        values[12] = if signals.l1_prefilter_hit { 1.0 } else { 0.0 };

        // Multi-layer agreement count (strong indicator of true positive)
        let layer_count = [
            signals.z1_exact_ioc,
            signals.z2_temporal,
            signals.z3_anomaly_high || signals.z3_anomaly_med,
            signals.z4_kill_chain,
            signals.exploit_indicator,
            signals.kernel_integrity,
            signals.tamper_indicator,
        ]
        .iter()
        .filter(|&&v| v)
        .count();
        values[13] = (layer_count as f64).min(4.0) / 4.0;

        // ── Information-theoretic features ──────────────────────────
        if let Some(cmd) = &event.command_line {
            let bytes = cmd.as_bytes();
            if let Some(metrics) = information::cmdline_information(bytes, 20) {
                let normalized = metrics.normalized();
                values[14] = normalized.renyi_h2;
                values[15] = normalized.compression_ratio;
                values[16] = normalized.min_entropy;
                values[17] = normalized.entropy_gap;
            }
        }

        if let Some(domain) = &event.dst_domain {
            values[18] = information::dns_entropy(domain);
        }

        Self { values }
    }
}

fn event_class_risk_score(class: EventClass) -> f64 {
    match class {
        EventClass::ModuleLoad => 0.9,
        EventClass::NetworkConnect => 0.6,
        EventClass::DnsQuery => 0.5,
        EventClass::ProcessExec => 0.5,
        EventClass::FileOpen => 0.4,
        EventClass::Login => 0.3,
        EventClass::ProcessExit => 0.1,
        EventClass::Alert => 1.0,
    }
}

fn dst_port_risk_score(port: Option<u16>) -> f64 {
    let Some(port) = port else { return 0.0 };
    match port {
        // Well-known safe ports
        80 | 443 | 22 | 53 => 0.1,
        // Common service ports
        8080 | 8443 | 3306 | 5432 | 6379 | 27017 => 0.2,
        // C2 / reverse shell common ports
        4444 | 4445 | 5555 | 1234 | 9999 | 31337 => 0.95,
        // SMB / RDP / WinRM (lateral movement)
        445 | 3389 | 5985 | 5986 => 0.8,
        // Uncommon high ports
        p if p > 10000 => 0.6,
        // Everything else
        _ => 0.3,
    }
}

fn cmdline_length_normalized(cmdline: Option<&str>) -> f64 {
    let Some(cmd) = cmdline else { return 0.0 };
    let len = cmd.len();
    // Normalize: very long cmdlines are suspicious (obfuscation, base64)
    // Cap at 500 chars for normalization
    (len as f64 / 500.0).min(1.0)
}
