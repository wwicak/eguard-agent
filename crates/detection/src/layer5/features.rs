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
            .map(|s| clamp01(s as f64 / 4096.0))
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

        // ── v2 process tree / file / network / credential features ───

        // Process tree / lineage
        values[27] = process_tree_depth_norm(event, signals);
        values[28] = rare_parent_child_pair(event, signals);
        values[29] = parent_cmdline_hash_risk(event);
        values[30] = parent_child_cmdline_distance(event);
        values[31] = sibling_spawn_burst_norm(event, signals);

        // File mutation behavior
        values[32] = sensitive_path_write_velocity(event, signals);
        values[33] = rename_churn_norm(event);
        values[34] = extension_entropy(event.file_path.as_deref());
        values[35] = executable_write_ratio(event);
        values[36] = temp_to_system_write_ratio(event);

        // Network graph / beaconing
        values[37] = conn_fanout_norm(event, signals);
        values[38] = unique_dst_ip_norm(event);
        values[39] = unique_dst_port_norm(event);
        values[40] = beacon_periodicity_score(signals, extra);
        values[41] = network_graph_centrality(values[37], values[38], values[40]);

        // Credential access indicators
        values[42] = credential_access_indicator(event, signals);
        values[43] = lsass_access_indicator(event);
        values[44] = sam_access_indicator(event);
        values[45] = token_theft_indicator(event, signals);
        values[46] = lolbin_credential_chain(event, values[42], values[45]);

        // Cross-domain interactions
        values[47] = clamp01(values[37] * values[42]);
        values[48] = clamp01(values[27] * values[37]);
        values[49] = clamp01(values[32] * values[23]);

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

fn clamp01(v: f64) -> f64 {
    v.clamp(0.0, 1.0)
}

fn process_tree_depth_norm(event: &TelemetryEvent, signals: &DetectionSignals) -> f64 {
    if !matches!(event.event_class, EventClass::ProcessExec) && !signals.process_tree_anomaly {
        return 0.0;
    }
    let mut depth = if event.ppid <= 1 { 0.08 } else { 0.24 };
    if event.session_id != 0 && event.session_id != event.pid {
        depth += 0.12;
    }
    if signals.process_tree_anomaly {
        depth += 0.30;
    }
    if matches!(event.event_class, EventClass::ProcessExec) {
        depth += 0.08;
    }
    clamp01(depth)
}

fn rare_parent_child_pair(event: &TelemetryEvent, signals: &DetectionSignals) -> f64 {
    if !matches!(event.event_class, EventClass::ProcessExec) && !signals.process_tree_anomaly {
        return 0.0;
    }
    let parent = event.parent_process.to_ascii_lowercase();
    let child = event.process.to_ascii_lowercase();
    let uncommon_parent = matches!(parent.as_str(), "python" | "perl" | "node" | "java");
    let admin_child = matches!(
        child.as_str(),
        "sudo" | "su" | "bash" | "sh" | "powershell" | "cmd.exe"
    );
    let mut score = 0.0;
    if uncommon_parent && admin_child {
        score = 0.8;
    } else if signals.process_tree_anomaly {
        score = 0.6;
    } else if parent != child && !parent.is_empty() {
        score = 0.2;
    }
    clamp01(score)
}

fn parent_cmdline_hash_risk(event: &TelemetryEvent) -> f64 {
    if !matches!(event.event_class, EventClass::ProcessExec) {
        return 0.0;
    }
    let Some(cmd) = event.command_line.as_deref() else {
        return 0.0;
    };
    let entropy = shannon_entropy(cmd.as_bytes());
    let has_encoded = contains_any_case_insensitive(
        cmd,
        &["base64", "-enc", "frombase64string", "certutil", "xxd -r"],
    );
    let mut score = entropy * 0.7;
    if has_encoded {
        score += 0.3;
    }
    clamp01(score)
}

fn parent_child_cmdline_distance(event: &TelemetryEvent) -> f64 {
    if !matches!(event.event_class, EventClass::ProcessExec) {
        return 0.0;
    }
    let p = event.parent_process.to_ascii_lowercase();
    let c = event.process.to_ascii_lowercase();
    if p.is_empty() || c.is_empty() {
        return 0.0;
    }
    if p == c {
        return 0.0;
    }
    let max_len = p.len().max(c.len()) as f64;
    let common_prefix = p.chars().zip(c.chars()).take_while(|(a, b)| a == b).count() as f64;
    clamp01(1.0 - common_prefix / max_len)
}

fn sibling_spawn_burst_norm(event: &TelemetryEvent, signals: &DetectionSignals) -> f64 {
    if !matches!(event.event_class, EventClass::ProcessExec) && !signals.process_tree_anomaly {
        return 0.0;
    }
    let mut score = if matches!(event.event_class, EventClass::ProcessExec) {
        0.35
    } else {
        0.05
    };
    if event.ppid > 1 {
        score += 0.2;
    }
    if signals.process_tree_anomaly {
        score += 0.35;
    }
    clamp01(score)
}

fn sensitive_path_write_velocity(event: &TelemetryEvent, signals: &DetectionSignals) -> f64 {
    if !event.file_write {
        return 0.0;
    }
    let path = event
        .file_path
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let sensitive = contains_any_case_insensitive(
        &path,
        &[
            "/etc/",
            "/root/",
            "/boot/",
            "/usr/bin/",
            "/windows/system32/",
        ],
    );
    let mut score = if sensitive { 0.75 } else { 0.35 };
    if signals.tamper_indicator || signals.kernel_integrity {
        score += 0.15;
    }
    clamp01(score)
}

fn rename_churn_norm(event: &TelemetryEvent) -> f64 {
    let Some(path) = event.file_path.as_deref() else {
        return 0.0;
    };
    let lower = path.to_ascii_lowercase();
    let mut score = 0.0;
    if contains_any_case_insensitive(&lower, &[".tmp", ".swp", ".bak", ".new", ".old"]) {
        score += 0.45;
    }
    let dot_count = lower.matches('.').count();
    if dot_count >= 2 {
        score += 0.25;
    }
    if event.file_write {
        score += 0.2;
    }
    clamp01(score)
}

fn extension_entropy(path: Option<&str>) -> f64 {
    let Some(path) = path else { return 0.0 };
    let ext = path.rsplit('.').next().unwrap_or("");
    if ext == path || ext.is_empty() {
        return 0.0;
    }
    shannon_entropy(ext.as_bytes())
}

fn executable_write_ratio(event: &TelemetryEvent) -> f64 {
    if !event.file_write {
        return 0.0;
    }
    let path = event.file_path.as_deref().unwrap_or_default();
    let executable = contains_any_case_insensitive(
        path,
        &[
            ".exe", ".dll", ".so", ".dylib", ".bin", ".run", ".sh", ".ps1", ".bat",
        ],
    );
    if executable {
        1.0
    } else {
        0.2
    }
}

fn temp_to_system_write_ratio(event: &TelemetryEvent) -> f64 {
    if !event.file_write {
        return 0.0;
    }
    let path = event
        .file_path
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let temp = contains_any_case_insensitive(&path, &["/tmp/", "/var/tmp/", "/temp/"]);
    let system = contains_any_case_insensitive(
        &path,
        &["/etc/", "/usr/", "/bin/", "/sbin/", "/windows/system32/"],
    );
    match (temp, system) {
        (true, true) => 1.0,
        (true, false) => 0.85,
        (false, true) => 0.15,
        (false, false) => 0.3,
    }
}

fn conn_fanout_norm(event: &TelemetryEvent, signals: &DetectionSignals) -> f64 {
    let mut score = if matches!(
        event.event_class,
        EventClass::NetworkConnect | EventClass::DnsQuery
    ) {
        0.25
    } else {
        0.0
    };
    if event.dst_ip.is_some() {
        score += 0.2;
    }
    if event.dst_port.is_some() {
        score += 0.15;
    }
    if signals.network_ioc_hit {
        score += 0.25;
    }
    if signals.c2_beaconing_detected {
        score += 0.15;
    }
    clamp01(score)
}

fn unique_dst_ip_norm(event: &TelemetryEvent) -> f64 {
    let Some(ip) = event.dst_ip.as_deref() else {
        return 0.0;
    };
    if ip.is_empty() {
        return 0.0;
    }
    if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.") {
        0.4
    } else {
        0.9
    }
}

fn unique_dst_port_norm(event: &TelemetryEvent) -> f64 {
    let Some(port) = event.dst_port else {
        return 0.0;
    };
    clamp01(port as f64 / 65535.0)
}

fn beacon_periodicity_score(signals: &DetectionSignals, extra: &MlExtraContext) -> f64 {
    let mut score = clamp01(extra.beacon_mi_score);
    if signals.c2_beaconing_detected {
        score = score.max(0.75);
    }
    clamp01(score)
}

fn network_graph_centrality(conn_fanout: f64, unique_ip: f64, beacon_score: f64) -> f64 {
    clamp01((conn_fanout * 0.4) + (unique_ip * 0.3) + (beacon_score * 0.3))
}

fn credential_access_indicator(event: &TelemetryEvent, signals: &DetectionSignals) -> f64 {
    let cmd = event.command_line.as_deref().unwrap_or_default();
    let path = event.file_path.as_deref().unwrap_or_default();
    let process = event.process.as_str();
    let indicator =
        contains_any_case_insensitive(
            cmd,
            &[
                "credential",
                "password",
                "hashdump",
                "sekurlsa",
                "vault",
                "keychain",
            ],
        ) || contains_any_case_insensitive(path, &["shadow", "passwd", "ntds", "credentials"])
            || contains_any_case_insensitive(process, &["mimikatz", "procdump", "secretsdump"]);
    let mut score = if indicator { 1.0 } else { 0.0 };
    if signals.exploit_indicator && score > 0.0 {
        score = 1.0;
    }
    score
}

fn lsass_access_indicator(event: &TelemetryEvent) -> f64 {
    let cmd = event.command_line.as_deref().unwrap_or_default();
    let proc = event.process.as_str();
    if contains_any_case_insensitive(cmd, &["lsass", "comsvcs.dll", "minidump"])
        || contains_any_case_insensitive(proc, &["procdump", "rundll32"])
    {
        1.0
    } else {
        0.0
    }
}

fn sam_access_indicator(event: &TelemetryEvent) -> f64 {
    let cmd = event.command_line.as_deref().unwrap_or_default();
    let path = event.file_path.as_deref().unwrap_or_default();
    if contains_any_case_insensitive(cmd, &["sam", "reg save", "hklm\\sam"])
        || contains_any_case_insensitive(path, &["/etc/shadow", "windows/system32/config/sam"])
    {
        1.0
    } else {
        0.0
    }
}

fn token_theft_indicator(event: &TelemetryEvent, signals: &DetectionSignals) -> f64 {
    let cmd = event.command_line.as_deref().unwrap_or_default();
    if contains_any_case_insensitive(
        cmd,
        &[
            "token",
            "impersonat",
            "seassignprimarytoken",
            "seimpersonate",
        ],
    ) || signals.exploit_indicator
    {
        1.0
    } else {
        0.0
    }
}

fn lolbin_credential_chain(
    event: &TelemetryEvent,
    credential_access: f64,
    token_theft: f64,
) -> f64 {
    let process = event.process.to_ascii_lowercase();
    let lolbin = matches!(
        process.as_str(),
        "powershell" | "pwsh" | "cmd.exe" | "wmic" | "rundll32" | "mshta" | "regsvr32" | "certutil"
    );
    if lolbin {
        clamp01(0.5 * credential_access + 0.5 * token_theft)
    } else {
        0.0
    }
}

fn contains_any_case_insensitive(haystack: &str, needles: &[&str]) -> bool {
    let lower = haystack.to_ascii_lowercase();
    needles
        .iter()
        .any(|n| lower.contains(&n.to_ascii_lowercase()))
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
