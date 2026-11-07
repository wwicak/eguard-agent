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
        // Enriched command lines on network/file events are process metadata, not new executions.
        let command_line = event
            .command_line
            .as_deref()
            .filter(|_| event.event_class == EventClass::ProcessExec);

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
        // Windows ETW uses uid=0 as unavailable, not UNIX root.
        let windows = event.process.to_ascii_lowercase().ends_with(".exe")
            || event.file_path.as_deref().is_some_and(|p| p.contains('\\'));
        values[8] = if event.uid == 0 && !windows { 1.0 } else { 0.0 };
        values[9] = dst_port_risk_score(event.dst_port);
        values[10] = if command_line.is_some() { 1.0 } else { 0.0 };
        values[11] = cmdline_length_normalized(command_line);
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

        // Index 14 retains its slot for model compatibility, but measures an
        // encoded token rather than near-constant entropy of every command.
        values[14] = if crate::behavioral::encoded_blob(event) {
            1.0
        } else {
            0.0
        };
        // Slots 15-17 remain zero until a discriminative feature is qualified.

        if let Some(domain) = &event.dst_domain {
            values[18] = information::dns_entropy(domain);
        }

        // ── Extended features (Fix 6) ───────────────────────────────

        // Index 20: container_risk
        values[20] = if event.container_escape || event.container_privileged {
            1.0
        } else if event.container_id.is_some() {
            0.5
        } else {
            0.0
        };

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
        values[28] = rare_parent_child_pair(event, signals);

        // File mutation behavior
        values[32] = sensitive_path_write_velocity(event, signals);
        values[33] = rename_churn_norm(event);
        values[34] = extension_entropy(event.file_path.as_deref());
        values[35] = executable_write_ratio(event);
        values[36] = temp_to_system_write_ratio(event);

        // Network graph / beaconing
        values[38] = unique_dst_ip_norm(event);
        values[40] = beacon_periodicity_score(signals, extra);

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

fn rare_parent_child_pair(event: &TelemetryEvent, signals: &DetectionSignals) -> f64 {
    if !matches!(event.event_class, EventClass::ProcessExec) && !signals.process_tree_anomaly {
        return 0.0;
    }
    let parent = crate::behavioral::basename(&event.parent_process);
    let child = crate::behavioral::basename(&event.process);
    let uncommon_parent = parent.starts_with("python")
        || matches!(
            parent.as_str(),
            "perl" | "node" | "java" | "w3wp" | "winword" | "excel" | "outlook"
        );
    let admin_child = matches!(
        child.as_str(),
        "sudo" | "su" | "bash" | "sh" | "dash" | "powershell" | "pwsh" | "cmd"
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

fn sensitive_path_write_velocity(event: &TelemetryEvent, signals: &DetectionSignals) -> f64 {
    if !event.file_write {
        return 0.0;
    }
    let path = event
        .file_path
        .as_deref()
        .unwrap_or_default()
        .replace('\\', "/")
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
    if !event.file_write {
        return 0.0;
    }
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
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let extension = std::path::Path::new(&normalized)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if matches!(
        extension,
        "exe"
            | "dll"
            | "so"
            | "dylib"
            | "sys"
            | "scr"
            | "ps1"
            | "bat"
            | "cmd"
            | "vbs"
            | "js"
            | "sh"
    ) {
        1.0
    } else {
        0.0
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
        .replace('\\', "/")
        .to_ascii_lowercase();
    let temp = contains_any_case_insensitive(
        &path,
        &[
            "/tmp/",
            "/var/tmp/",
            "/appdata/local/temp/",
            "/windows/temp/",
        ],
    );
    let system = contains_any_case_insensitive(
        &path,
        &[
            "/etc/",
            "/usr/",
            "/bin/",
            "/sbin/",
            "/windows/system32/",
            "/windows/syswow64/",
        ],
    );
    match (temp, system) {
        (true, true) => 1.0,
        (true, false) => 0.85,
        (false, true) => 0.15,
        (false, false) => 0.3,
    }
}

fn unique_dst_ip_norm(event: &TelemetryEvent) -> f64 {
    let public = match event
        .dst_ip
        .as_deref()
        .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
    {
        Some(std::net::IpAddr::V4(ip)) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast())
        }
        Some(std::net::IpAddr::V6(ip)) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast())
        }
        None => false,
    };
    if public {
        1.0
    } else {
        0.0
    }
}

fn beacon_periodicity_score(signals: &DetectionSignals, extra: &MlExtraContext) -> f64 {
    let mut score = clamp01(extra.beacon_mi_score);
    if signals.c2_beaconing_detected {
        score = score.max(0.75);
    }
    clamp01(score)
}

fn credential_access_indicator(event: &TelemetryEvent, _signals: &DetectionSignals) -> f64 {
    let process = crate::behavioral::basename(&event.process);
    let hit = if event.event_class == EventClass::ProcessExec {
        contains_any_case_insensitive(
            event.command_line.as_deref().unwrap_or(""),
            &[
                "sekurlsa::",
                "lsadump::",
                "hashdump",
                "vaultcmd /list",
                "security dump-keychain",
                "findstr /si password",
                "secretsdump",
            ],
        ) || matches!(
            process.as_str(),
            "mimikatz" | "procdump" | "procdump64" | "secretsdump"
        )
    } else if event.event_class == EventClass::FileOpen {
        let path = event
            .file_path
            .as_deref()
            .unwrap_or("")
            .replace('\\', "/")
            .to_ascii_lowercase();
        (matches!(path.as_str(), "/etc/shadow" | "/etc/gshadow")
            && !matches!(
                process.as_str(),
                "unix_chkpwd" | "sshd" | "passwd" | "chage" | "sudo" | "login"
            ))
            || path.ends_with("/ntds.dit")
            || (path.ends_with("/.aws/credentials")
                && !matches!(
                    process.as_str(),
                    "aws" | "terraform" | "kubectl" | "python3"
                ))
    } else {
        false
    };
    if hit {
        1.0
    } else {
        0.0
    }
}
fn lsass_access_indicator(event: &TelemetryEvent) -> f64 {
    if event.event_class != EventClass::ProcessExec {
        return 0.0;
    }
    let cmd = event
        .command_line
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let dump = cmd.contains("lsass")
        && ["minidump", "-ma ", "comsvcs", "sekurlsa"]
            .iter()
            .any(|s| cmd.contains(s));
    if dump || (cmd.contains("comsvcs.dll") && cmd.contains("minidump")) {
        1.0
    } else {
        0.0
    }
}
fn sam_access_indicator(event: &TelemetryEvent) -> f64 {
    let path = event
        .file_path
        .as_deref()
        .unwrap_or("")
        .replace('\\', "/")
        .to_ascii_lowercase();
    let cmd = event
        .command_line
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let exec = event.event_class == EventClass::ProcessExec
        && ([
            "reg save hklm\\sam",
            "reg.exe save hklm\\sam",
            "\\config\\sam",
            "hklm\\security",
        ]
        .iter()
        .any(|s| cmd.contains(s))
            || (cmd.contains("esentutl") && cmd.contains("\\sam")));
    if exec || (event.event_class == EventClass::FileOpen && path.ends_with("/system32/config/sam"))
    {
        1.0
    } else {
        0.0
    }
}
fn token_theft_indicator(event: &TelemetryEvent, _signals: &DetectionSignals) -> f64 {
    if event.event_class == EventClass::ProcessExec
        && contains_any_case_insensitive(
            event.command_line.as_deref().unwrap_or(""),
            &[
                "seimpersonateprivilege",
                "seassignprimarytoken",
                "token::elevate",
                "invoke-tokenmanipulation",
                "incognito.exe",
                "impersonate-user",
            ],
        )
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
    let process = crate::behavioral::basename(&event.process);
    let lolbin = matches!(
        process.as_str(),
        "powershell" | "pwsh" | "cmd" | "wmic" | "rundll32" | "mshta" | "regsvr32" | "certutil"
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
        4444 | 4445 | 31337 => 0.95,
        // SMB / RDP / WinRM (lateral movement)
        445 | 3389 | 5985 | 5986 => 0.3,
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
