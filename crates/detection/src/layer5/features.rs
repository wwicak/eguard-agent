use crate::information;
use crate::types::{DetectionSignals, EventClass, TelemetryEvent};

use super::constants::FEATURE_COUNT;

/// Additional context from external trackers for ML feature extraction.
///
/// Populated by the detection engine from behavioral/beaconing trackers.
/// Fields default to zero (safe — contributes nothing to ML score).
#[derive(Debug, Clone, Default)]
pub struct MlExtraContext {
    /// Mutual information score for C2 beaconing detection [0, 1].
    pub beacon_mi_score: f64,
}

/// Features extracted from a single event + detection signals.
#[derive(Debug, Clone)]
pub struct MlFeatures {
    pub values: [f64; FEATURE_COUNT],
}

impl MlFeatures {
    /// Extract feature vector from detection signals and event metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn extract(
        event: &TelemetryEvent,
        signals: &DetectionSignals,
        temporal_hit_count: usize,
        killchain_hit_count: usize,
        yara_hit_count: usize,
        string_sig_count: usize,
        behavioral_alarm_count: usize,
        extra: &MlExtraContext,
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
            signals.network_ioc_hit,
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

        // ── Extended features (Fix 6) ───────────────────────────────

        // Index 19: event_size_norm — normalized event size
        values[19] = event
            .event_size
            .map(|s| (s as f64 / 8192.0).min(1.0))
            .unwrap_or(0.0);

        // Index 20: container_risk
        values[20] = if event.container_escape || event.container_privileged {
            1.0
        } else if event.container_id.is_some() {
            0.5
        } else {
            0.0
        };

        // Index 21: file_path_entropy — Shannon entropy of file path
        values[21] = event
            .file_path
            .as_deref()
            .map(|p| shannon_entropy(p.as_bytes()))
            .unwrap_or(0.0);

        // Index 22: file_path_depth — normalized path depth
        values[22] = event
            .file_path
            .as_deref()
            .map(|p| (p.matches('/').count() as f64 / 10.0).min(1.0))
            .unwrap_or(0.0);

        // Index 23: behavioral_alarm_count — normalized
        values[23] = (behavioral_alarm_count as f64).min(5.0) / 5.0;

        // Index 24: z1_z2_interaction — IOC confirmed by temporal pattern
        values[24] = values[0] * values[1];

        // Index 25: z1_z4_interaction — IOC in kill chain context
        values[25] = values[0] * values[4];

        // Index 26: anomaly_behavioral — anomaly with multi-signal
        values[26] = values[2] * values[13];

        // ── Process tree + beaconing features (Phase 1.3) ───────────

        // Index 27: tree_depth_norm — process chain depth / 10.0
        // Heuristic from available pid/ppid: ppid == 0 or 1 → shallow (depth 1),
        // otherwise at least depth 2. Full tree tracking improves this later.
        values[27] = if event.ppid <= 1 {
            0.1 // depth ~1
        } else {
            0.2 // at least depth 2
        };

        // Index 28: tree_breadth_norm — sibling count / 20.0
        // Not directly available from TelemetryEvent; defaults to 0.0.
        // Populated via external process tree tracker in future iterations.
        values[28] = 0.0;

        // Index 29: child_entropy — Shannon entropy of child comm names
        // Not available per-event; defaults to 0.0.
        values[29] = 0.0;

        // Index 30: spawn_rate_norm — children spawned per minute / 10.0
        // Not available per-event; defaults to 0.0.
        values[30] = 0.0;

        // Index 31: rare_parent_child — 1.0 if parent:child pair is anomalous
        values[31] = if signals.process_tree_anomaly {
            1.0
        } else {
            0.0
        };

        // Index 32: c2_beacon_mi — mutual information score for destination
        values[32] = extra.beacon_mi_score.min(1.0);

        Self { values }
    }
}

/// Shannon entropy of a byte slice, normalized to [0, 1].
/// Maximum byte entropy is 8.0 bits (uniform distribution over 256 values).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    // Normalize to [0, 1] where 8.0 is max for byte data
    (entropy / 8.0).min(1.0)
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
