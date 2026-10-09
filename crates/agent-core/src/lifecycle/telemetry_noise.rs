use std::collections::HashMap;

use detection::{Confidence, DetectionOutcome, EventClass, TelemetryEvent};
use sha2::{Digest, Sha256};

use super::AgentRuntime;

const KEY_LIMIT: usize = 8_192;
const WINDOW_SECS: i64 = 3_600;

#[derive(Default)]
pub(super) struct TelemetryNoiseFilter {
    window_start: Option<i64>,
    repeats: HashMap<[u8; 32], u8>,
    pub(super) static_reads: u64,
    pub(super) negative_ml: u64,
    pub(super) repeated: u64,
}

impl TelemetryNoiseFilter {
    fn should_send(
        &mut self,
        enabled: bool,
        event: &TelemetryEvent,
        outcome: &DetectionOutcome,
        severity: &str,
        rule: &str,
        now: i64,
    ) -> bool {
        if !enabled {
            self.repeats.clear();
            self.window_start = None;
            return true;
        }
        if self
            .window_start
            .is_none_or(|start| now < start || now.saturating_sub(start) >= WINDOW_SECS)
        {
            self.repeats.clear();
            self.window_start = Some(now);
        }

        // Never trade containment evidence, mutations or credential access for volume.
        if matches!(severity, "high" | "critical")
            || outcome.confidence >= Confidence::High
            || event.event_class == EventClass::Alert
            || event.file_write
            || event.file_path.as_deref().is_some_and(sensitive_path)
        {
            return true;
        }

        let evidence = has_evidence(event, outcome);
        if event.event_class == EventClass::FileOpen
            && event.file_path.as_deref().is_some_and(static_system_path)
            && !evidence
            && !matches!(severity, "medium")
            && outcome.confidence < Confidence::Medium
        {
            self.static_reads = self.static_reads.saturating_add(1);
            return false;
        }
        if severity == "info"
            && outcome
                .ml_score
                .as_ref()
                .is_some_and(|score| !score.positive)
            && !evidence
        {
            self.negative_ml = self.negative_ml.saturating_add(1);
            return false;
        }

        // Fixed-size digests bound memory even for arbitrarily long command lines.
        // Length prefixes preserve tuple boundaries; PID deliberately isn't a key.
        let mut digest = Sha256::new();
        let rule = if rule.is_empty() {
            AgentRuntime::detection_rule_type(outcome)
        } else {
            rule
        };
        for value in [
            event.event_class.as_str(),
            rule,
            &event.process,
            &event.parent_process,
            event.command_line.as_deref().unwrap_or_default(),
            event.file_path.as_deref().unwrap_or_default(),
            event.dst_ip.as_deref().unwrap_or_default(),
            event.dst_domain.as_deref().unwrap_or_default(),
        ] {
            digest.update((value.len() as u64).to_le_bytes());
            digest.update(value.as_bytes());
        }
        digest.update(event.dst_port.unwrap_or_default().to_le_bytes());
        let key: [u8; 32] = digest.finalize().into();
        if let Some(count) = self.repeats.get_mut(&key) {
            if *count >= 3 {
                self.repeated = self.repeated.saturating_add(1);
                return false;
            }
            *count += 1;
        } else if self.repeats.len() < KEY_LIMIT {
            self.repeats.insert(key, 1);
        }
        // At capacity, unknown keys fail open instead of evicting an attack's evidence.
        true
    }
}

fn has_evidence(event: &TelemetryEvent, outcome: &DetectionOutcome) -> bool {
    let s = &outcome.signals;
    s.z1_exact_ioc
        || s.yara_hit
        || s.z2_temporal
        || s.z3_anomaly_high
        || s.z3_anomaly_med
        || s.z4_kill_chain
        || s.l1_prefilter_hit
        || s.exploit_indicator
        || s.kernel_integrity
        || s.tamper_indicator
        || s.c2_beaconing_detected
        || s.process_tree_anomaly
        || s.campaign_correlated
        || s.network_ioc_hit
        || s.vulnerable_software
        || s.fim_violation
        || s.lateral_movement
        || s.usb_violation
        || s.deception_triggered
        || !outcome.layer1.matched_signatures.is_empty()
        || !outcome.layer1.matched_fields.is_empty()
        || !outcome.temporal_hits.is_empty()
        || !outcome.kill_chain_hits.is_empty()
        || !outcome.exploit_indicators.is_empty()
        || !outcome.kernel_integrity_indicators.is_empty()
        || !outcome.tamper_indicators.is_empty()
        || !outcome.yara_hits.is_empty()
        || !outcome.behavioral_alarms.is_empty()
        || outcome.anomaly.as_ref().is_some_and(|a| a.high || a.medium)
        || outcome
            .ml_score
            .as_ref()
            .is_some_and(|score| score.positive)
        || !AgentRuntime::mitre_techniques(event, outcome).is_empty()
}

fn sensitive_path(path: &str) -> bool {
    // Exclusions win over library/locale prefixes, including unusual store locations.
    let lower = path.to_ascii_lowercase();
    let sensitive = [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/master.passwd",
        "/etc/passwd",
        "/etc/krb5.keytab",
        "/etc/sudoers",
        "/etc/security",
        "/etc/ld.so.preload",
        "/etc/ssh",
        "/etc/ssl/private",
        "/etc/eguard-agent",
        "/usr/local/eg",
        "/usr/lib/eguard-agent",
        "/var/lib/eguard-agent",
        "/var/log/eguard-agent",
        "/run/eguard-agent",
        "/opt/eguard-agent",
    ];
    sensitive
        .iter()
        .any(|prefix| lower == *prefix || lower.starts_with(&format!("{prefix}/")))
        || lower.split('/').any(|part| {
            matches!(
                part,
                ".." | ".ssh"
                    | "shadow"
                    | "gshadow"
                    | "authorized_keys"
                    | "master.passwd"
                    | ".netrc"
                    | ".git-credentials"
                    | ".npmrc"
                    | ".env"
                    | ".docker"
                    | "gcloud"
                    | ".password-store"
                    | ".gnupg"
                    | ".aws"
                    | ".azure"
                    | ".kube"
                    | ".mozilla"
                    | ".pki"
                    | "chromium"
                    | "google-chrome"
                    | "brave-browser"
                    | "credentials"
                    | "keyrings"
                    | "login data"
                    | "cookies"
                    | "cookies.sqlite"
                    | "web data"
                    | "logins.json"
                    | "key3.db"
                    | "key4.db"
            )
        })
        || lower.ends_with(".key")
        || lower.ends_with(".pem")
        || lower.ends_with(".keytab")
        || lower.contains("credential")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("/id_rsa")
        || lower.contains("/id_ed25519")
}

fn static_system_path(path: &str) -> bool {
    if path.split('/').any(|part| part == "..") {
        return false;
    }
    if matches!(path, "/etc/ld.so.cache" | "/usr/share/locale/locale.alias") {
        return true;
    }
    if [
        "/usr/share/locale/",
        "/usr/share/coreutils/locales/",
        "/usr/lib/locale/",
    ]
    .iter()
    .any(|p| path.starts_with(p))
    {
        return true;
    }
    let system_lib = [
        "/lib/",
        "/lib64/",
        "/lib32/",
        "/usr/lib/",
        "/usr/lib64/",
        "/usr/lib32/",
        "/usr/libexec/",
    ]
    .iter()
    .any(|p| path.starts_with(p));
    let name = path.rsplit('/').next().unwrap_or_default();
    system_lib && (name.ends_with(".so") || name.contains(".so."))
}

impl AgentRuntime {
    // The noise filter is Linux-only (and sensitive_config_paths is unix-only), so other targets always send.
    #[cfg(not(target_os = "linux"))]
    pub(super) fn should_send_evaluation(&mut self, _evaluation: &super::TickEvaluation) -> bool {
        true
    }

    #[cfg(target_os = "linux")]
    pub(super) fn should_send_evaluation(&mut self, evaluation: &super::TickEvaluation) -> bool {
        if evaluation
            .detection_event
            .file_path
            .as_deref()
            .is_some_and(|path| {
                self.config
                    .sensitive_config_paths()
                    .iter()
                    .any(|protected| protected == std::path::Path::new(path))
                    || [
                        self.config.detection_sigma_rules_dir.as_str(),
                        self.config.detection_yara_rules_dir.as_str(),
                        self.config.detection_ioc_dir.as_str(),
                        self.config.detection_bundle_path.as_str(),
                        self.config.offline_buffer_path.as_str(),
                    ]
                    .iter()
                    .any(|protected| {
                        !protected.is_empty() && std::path::Path::new(path).starts_with(protected)
                    })
            })
        {
            return true;
        }
        self.telemetry_noise.should_send(
            cfg!(target_os = "linux") && self.config.telemetry_noise_filter,
            &evaluation.detection_event,
            &evaluation.detection_outcome,
            &evaluation.event_envelope.severity,
            &evaluation.event_envelope.rule_name,
            evaluation.event_envelope.created_at_unix,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_paths_do_not_blanket_allowlist_library_trees() {
        for path in [
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/libtest.so",
            "/etc/ld.so.cache",
            "/usr/share/coreutils/locales/en-US/coreutils.ftl",
        ] {
            assert!(static_system_path(path), "{path}");
        }
        for path in [
            "/usr/lib/credentials",
            "/usr/lib/../etc/shadow",
            "/tmp/libbad.so",
            "/etc/shadow",
        ] {
            assert!(!static_system_path(path), "{path}");
        }
        for path in [
            "/etc/shadow",
            "/home/user/.ssh/id_rsa",
            "/usr/lib/eguard-agent/test.so",
            "/usr/share/locale/.aws/credentials",
        ] {
            assert!(sensitive_path(path), "{path}");
        }
    }
}
