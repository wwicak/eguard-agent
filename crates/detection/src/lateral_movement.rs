//! Lateral Movement Detection — pattern matching on process and login
//! behaviour to detect attacker movement between hosts.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::{EventClass, TelemetryEvent};

// ── Thresholds ───────────────────────────────────────────────────────
const SSH_BRUTE_FORCE_COUNT: usize = 5;
const SSH_BRUTE_FORCE_WINDOW_SECS: i64 = 300; // 5 minutes
const UNUSUAL_LOGIN_BASELINE_SECS: i64 = 7 * 86_400; // 7 days

// ── Known lateral-movement tool names (lowercase) ────────────────────
const REMOTE_TOOLS: &[&str] = &[
    "psexec", "psexec64", "psexesvc",
    "wmic", "winrm", "winrs",
    "ncat", "socat", "chisel", "ligolo",
    "schtasks",   // Windows scheduled task creation
    "mstsc",      // RDP client (unusual if spawned by script)
    "wmiexec",    // Impacket
    "smbexec",    // Impacket
    "atexec",     // Impacket
];

const CREDENTIAL_TOOLS: &[&str] = &[
    "mimikatz", "secretsdump", "hashdump",
    "procdump", "lsass",
];

// ── Platform-specific credential store paths ─────────────────────────

#[cfg(target_os = "linux")]
const CREDENTIAL_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
];

#[cfg(target_os = "windows")]
const CREDENTIAL_PATHS: &[&str] = &[
    "\\windows\\system32\\config\\sam",
    "\\windows\\system32\\config\\security",
    "\\windows\\ntds\\ntds.dit",
    "\\windows\\system32\\config\\system",
];

#[cfg(target_os = "macos")]
const CREDENTIAL_PATHS: &[&str] = &[
    "/var/db/dslocal/",
    "/library/keychains/",
    "/etc/shadow",
];

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
const CREDENTIAL_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
];

/// Port used for RDP brute force detection.
const RDP_PORT: u16 = 3389;

/// Substrings in command_line that indicate SSH tunnelling.
const SSH_TUNNEL_FLAGS: &[&str] = &[
    " -L ", " -R ", " -D ",
    " -L\t", " -R\t", " -D\t",
];

// ── Public types ─────────────────────────────────────────────────────

/// Classification of the lateral-movement technique detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LateralTechnique {
    /// 5+ auth failures from same source in 5 min.
    SshBruteForce,
    /// 5+ failed RDP login attempts from same source in 5 min.
    RdpBruteForce,
    /// Execution of known remote-admin / tunnelling tools.
    RemoteToolExecution,
    /// Access to credential stores or credential-dumping binaries.
    CredentialDumping,
    /// NTLM hash reuse patterns (reserved).
    PassTheHash,
    /// Login from a source IP not seen in the 7-day baseline.
    UnusualRemoteLogin,
}

/// A single lateral-movement alert produced by the detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementAlert {
    pub technique: LateralTechnique,
    /// Confidence in the detection, 0.0..=1.0.
    pub confidence: f64,
    /// Source IP if available.
    pub source_ip: Option<String>,
    /// Human-readable explanation.
    pub detail: String,
}

/// Stateful lateral-movement detector.
///
/// Tracks SSH/RDP auth failures and known-good login sources to detect brute
/// force, credential dumping, and unusual remote logins.
pub struct LateralMovementDetector {
    /// `source_ip -> Vec<timestamp>` for failed SSH auth events.
    ssh_auth_failures: HashMap<String, Vec<i64>>,
    /// `source_ip -> Vec<timestamp>` for failed RDP auth events (port 3389).
    rdp_auth_failures: HashMap<String, Vec<i64>>,
    /// `source_ip -> last_seen_timestamp` for successful logins.
    known_login_sources: HashMap<String, i64>,
}

impl LateralMovementDetector {
    pub fn new() -> Self {
        Self {
            ssh_auth_failures: HashMap::new(),
            rdp_auth_failures: HashMap::new(),
            known_login_sources: HashMap::new(),
        }
    }

    /// Evaluate a single telemetry event for lateral-movement indicators.
    ///
    /// Returns `Some(alert)` if a technique is detected, `None` otherwise.
    pub fn check_event(&mut self, event: &TelemetryEvent) -> Option<LateralMovementAlert> {
        // Check each detection pattern in priority order; return the first
        // match so callers get the highest-signal alert.
        if let Some(alert) = self.check_credential_access(event) {
            return Some(alert);
        }
        if let Some(alert) = self.check_remote_tools(event) {
            return Some(alert);
        }
        if let Some(alert) = self.check_ssh_brute_force(event) {
            return Some(alert);
        }
        if let Some(alert) = self.check_rdp_brute_force(event) {
            return Some(alert);
        }
        if let Some(alert) = self.check_unusual_login(event) {
            return Some(alert);
        }
        None
    }

    // ── Internal detectors ───────────────────────────────────────────

    /// Detect SSH brute-force: 5+ login failures from the same source IP
    /// within a 5-minute window. Skips events on the RDP port (3389) which
    /// are handled by [`check_rdp_brute_force`].
    fn check_ssh_brute_force(&mut self, event: &TelemetryEvent) -> Option<LateralMovementAlert> {
        // Only consider Login events with a source IP (dst_ip on Login events
        // represents the remote source in the existing telemetry model).
        if event.event_class != EventClass::Login {
            return None;
        }
        // Skip RDP-targeted events — handled by check_rdp_brute_force.
        if event.dst_port == Some(RDP_PORT) {
            return None;
        }
        let src_ip = event.dst_ip.as_deref()?;

        // A "failed" SSH auth is indicated by uid == u32::MAX (no valid user
        // was resolved). Only track failures for brute-force detection.
        if event.uid != u32::MAX {
            return None;
        }

        let timestamps = self.ssh_auth_failures.entry(src_ip.to_string()).or_default();
        timestamps.push(event.ts_unix);

        // Evict entries outside the window.
        let cutoff = event.ts_unix - SSH_BRUTE_FORCE_WINDOW_SECS;
        timestamps.retain(|&ts| ts > cutoff);

        if timestamps.len() >= SSH_BRUTE_FORCE_COUNT {
            return Some(LateralMovementAlert {
                technique: LateralTechnique::SshBruteForce,
                confidence: 0.9,
                source_ip: Some(src_ip.to_string()),
                detail: format!(
                    "{} SSH auth failures from {} in {}s",
                    timestamps.len(),
                    src_ip,
                    SSH_BRUTE_FORCE_WINDOW_SECS,
                ),
            });
        }
        None
    }

    /// Detect RDP brute-force: 5+ login failures on port 3389 from the same
    /// source IP within a 5-minute window.
    fn check_rdp_brute_force(&mut self, event: &TelemetryEvent) -> Option<LateralMovementAlert> {
        if event.event_class != EventClass::Login {
            return None;
        }
        // Only consider events targeting the RDP port.
        if event.dst_port != Some(RDP_PORT) {
            return None;
        }
        let src_ip = event.dst_ip.as_deref()?;

        // Only track failures (uid == u32::MAX).
        if event.uid != u32::MAX {
            return None;
        }

        let timestamps = self.rdp_auth_failures.entry(src_ip.to_string()).or_default();
        timestamps.push(event.ts_unix);

        // Evict entries outside the window.
        let cutoff = event.ts_unix - SSH_BRUTE_FORCE_WINDOW_SECS;
        timestamps.retain(|&ts| ts > cutoff);

        if timestamps.len() >= SSH_BRUTE_FORCE_COUNT {
            return Some(LateralMovementAlert {
                technique: LateralTechnique::RdpBruteForce,
                confidence: 0.9,
                source_ip: Some(src_ip.to_string()),
                detail: format!(
                    "{} RDP auth failures from {} in {}s",
                    timestamps.len(),
                    src_ip,
                    SSH_BRUTE_FORCE_WINDOW_SECS,
                ),
            });
        }
        None
    }

    /// Detect execution of known remote-admin / tunnelling tools.
    fn check_remote_tools(&self, event: &TelemetryEvent) -> Option<LateralMovementAlert> {
        if event.event_class != EventClass::ProcessExec {
            return None;
        }
        let proc_lower = event.process.to_lowercase();

        // Check binary name against the known-tools list.
        if REMOTE_TOOLS.iter().any(|t| proc_lower == *t) {
            return Some(LateralMovementAlert {
                technique: LateralTechnique::RemoteToolExecution,
                confidence: 0.85,
                source_ip: event.dst_ip.clone(),
                detail: format!("Lateral movement tool executed: {}", event.process),
            });
        }

        // Check command_line for SSH tunnelling flags.
        if let Some(ref cmdline) = event.command_line {
            if SSH_TUNNEL_FLAGS.iter().any(|flag| cmdline.contains(flag)) {
                return Some(LateralMovementAlert {
                    technique: LateralTechnique::RemoteToolExecution,
                    confidence: 0.80,
                    source_ip: event.dst_ip.clone(),
                    detail: format!("SSH tunnel detected: {}", cmdline),
                });
            }
        }

        None
    }

    /// Detect access to credential stores or credential-dumping binaries.
    fn check_credential_access(&self, event: &TelemetryEvent) -> Option<LateralMovementAlert> {
        // Process name matching (mimikatz, secretsdump, etc.)
        if event.event_class == EventClass::ProcessExec {
            let proc_lower = event.process.to_lowercase();
            if CREDENTIAL_TOOLS.iter().any(|t| proc_lower.contains(t)) {
                return Some(LateralMovementAlert {
                    technique: LateralTechnique::CredentialDumping,
                    confidence: 0.95,
                    source_ip: None,
                    detail: format!("Credential dumping tool: {}", event.process),
                });
            }
        }

        // File access to credential stores (case-insensitive for Windows/macOS).
        if event.event_class == EventClass::FileOpen {
            if let Some(ref path) = event.file_path {
                let normalized = path.replace('\\', "/").to_ascii_lowercase();
                if CREDENTIAL_PATHS
                    .iter()
                    .any(|p| normalized.contains(&p.replace('\\', "/").to_ascii_lowercase()))
                {
                    return Some(LateralMovementAlert {
                        technique: LateralTechnique::CredentialDumping,
                        confidence: 0.75,
                        source_ip: None,
                        detail: format!("Credential file accessed: {}", path),
                    });
                }
            }
        }

        None
    }

    /// Detect logins from a source IP not seen in the 7-day baseline.
    /// Only evaluates successful logins (uid != u32::MAX); failed attempts
    /// are handled by `check_ssh_brute_force`.
    fn check_unusual_login(&mut self, event: &TelemetryEvent) -> Option<LateralMovementAlert> {
        if event.event_class != EventClass::Login {
            return None;
        }
        // Skip failed auth attempts — they are handled by brute-force detection.
        if event.uid == u32::MAX {
            return None;
        }
        let src_ip = event.dst_ip.as_deref()?;

        let cutoff = event.ts_unix - UNUSUAL_LOGIN_BASELINE_SECS;

        if let Some(&last_seen) = self.known_login_sources.get(src_ip) {
            if last_seen >= cutoff {
                // Known recent source — update timestamp and move on.
                self.known_login_sources.insert(src_ip.to_string(), event.ts_unix);
                return None;
            }
        }

        // First time or stale — flag and record.
        let alert = LateralMovementAlert {
            technique: LateralTechnique::UnusualRemoteLogin,
            confidence: 0.60,
            source_ip: Some(src_ip.to_string()),
            detail: format!("Login from previously unseen source: {}", src_ip),
        };

        self.known_login_sources.insert(src_ip.to_string(), event.ts_unix);
        Some(alert)
    }
}

impl Default for LateralMovementDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a minimal TelemetryEvent.
    fn make_event(
        ts: i64,
        class: EventClass,
        process: &str,
        dst_ip: Option<&str>,
        file_path: Option<&str>,
        command_line: Option<&str>,
        uid: u32,
    ) -> TelemetryEvent {
        TelemetryEvent {
            ts_unix: ts,
            event_class: class,
            pid: 100,
            ppid: 10,
            uid,
            process: process.to_string(),
            parent_process: "init".to_string(),
            session_id: 1,
            file_path: file_path.map(|s| s.to_string()),
            file_write: false,
            file_hash: None,
            dst_port: None,
            dst_ip: dst_ip.map(|s| s.to_string()),
            dst_domain: None,
            command_line: command_line.map(|s| s.to_string()),
            event_size: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        }
    }

    fn ssh_failure(ts: i64, src_ip: &str) -> TelemetryEvent {
        make_event(ts, EventClass::Login, "sshd", Some(src_ip), None, None, u32::MAX)
    }

    #[test]
    fn ssh_brute_force_detected_at_threshold() {
        let mut det = LateralMovementDetector::new();
        let base_ts = 1_700_000_000;
        let ip = "10.0.0.1";

        // First 4 should not trigger.
        for i in 0..4 {
            let ev = ssh_failure(base_ts + i * 10, ip);
            assert!(det.check_event(&ev).is_none(), "unexpected alert at failure #{}", i + 1);
        }

        // 5th triggers brute-force.
        let ev5 = ssh_failure(base_ts + 40, ip);
        let alert = det.check_event(&ev5).unwrap();
        assert_eq!(alert.technique, LateralTechnique::SshBruteForce);
        assert_eq!(alert.source_ip.as_deref(), Some(ip));
    }

    #[test]
    fn ssh_three_failures_no_detection() {
        let mut det = LateralMovementDetector::new();
        let base_ts = 1_700_000_000;

        for i in 0..3 {
            let ev = ssh_failure(base_ts + i, "10.0.0.2");
            assert!(det.check_event(&ev).is_none());
        }
    }

    #[test]
    fn psexec_triggers_remote_tool() {
        let mut det = LateralMovementDetector::new();
        let ev = make_event(1_700_000_000, EventClass::ProcessExec, "PsExec", None, None, None, 0);
        let alert = det.check_event(&ev).unwrap();
        assert_eq!(alert.technique, LateralTechnique::RemoteToolExecution);
    }

    #[test]
    fn mimikatz_triggers_credential_dumping() {
        let mut det = LateralMovementDetector::new();
        let ev = make_event(1_700_000_000, EventClass::ProcessExec, "mimikatz.exe", None, None, None, 0);
        let alert = det.check_event(&ev).unwrap();
        assert_eq!(alert.technique, LateralTechnique::CredentialDumping);
    }

    #[test]
    fn credential_path_access_triggers_credential_dumping() {
        let mut det = LateralMovementDetector::new();
        // Use the first credential path for the current platform.
        let cred_path = CREDENTIAL_PATHS[0];
        let ev = make_event(
            1_700_000_000,
            EventClass::FileOpen,
            "cat",
            None,
            Some(cred_path),
            None,
            0,
        );
        let alert = det.check_event(&ev).unwrap();
        assert_eq!(alert.technique, LateralTechnique::CredentialDumping);
    }

    #[test]
    fn rdp_brute_force_detected_at_threshold() {
        let mut det = LateralMovementDetector::new();
        let base_ts = 1_700_000_000;
        let ip = "10.0.0.5";

        // Build RDP failure events (Login on port 3389, uid=MAX).
        let rdp_failure = |ts: i64, src: &str| -> TelemetryEvent {
            let mut ev = make_event(ts, EventClass::Login, "svchost", Some(src), None, None, u32::MAX);
            ev.dst_port = Some(3389);
            ev
        };

        // First 4 should not trigger.
        for i in 0..4 {
            let ev = rdp_failure(base_ts + i * 10, ip);
            assert!(det.check_event(&ev).is_none(), "unexpected alert at failure #{}", i + 1);
        }

        // 5th triggers RDP brute-force.
        let ev5 = rdp_failure(base_ts + 40, ip);
        let alert = det.check_event(&ev5).unwrap();
        assert_eq!(alert.technique, LateralTechnique::RdpBruteForce);
        assert_eq!(alert.source_ip.as_deref(), Some(ip));
    }

    #[test]
    fn winrs_triggers_remote_tool() {
        let mut det = LateralMovementDetector::new();
        let ev = make_event(1_700_000_000, EventClass::ProcessExec, "winrs", None, None, None, 0);
        let alert = det.check_event(&ev).unwrap();
        assert_eq!(alert.technique, LateralTechnique::RemoteToolExecution);
    }

    #[test]
    fn smbexec_triggers_remote_tool() {
        let mut det = LateralMovementDetector::new();
        let ev = make_event(1_700_000_000, EventClass::ProcessExec, "smbexec", None, None, None, 0);
        let alert = det.check_event(&ev).unwrap();
        assert_eq!(alert.technique, LateralTechnique::RemoteToolExecution);
    }

    #[test]
    fn normal_ssh_login_no_detection_after_baseline() {
        let mut det = LateralMovementDetector::new();
        let ip = "192.168.1.100";
        let base_ts = 1_700_000_000;

        // First login from this IP: unusual (will trigger).
        let ev1 = make_event(base_ts, EventClass::Login, "sshd", Some(ip), None, None, 1000);
        let first = det.check_event(&ev1);
        assert!(first.is_some()); // First time = unusual

        // Second login within 7 days: should NOT trigger.
        let ev2 = make_event(base_ts + 3600, EventClass::Login, "sshd", Some(ip), None, None, 1000);
        let second = det.check_event(&ev2);
        assert!(second.is_none());
    }

    #[test]
    fn ssh_tunnel_flag_triggers_remote_tool() {
        let mut det = LateralMovementDetector::new();
        let ev = make_event(
            1_700_000_000,
            EventClass::ProcessExec,
            "ssh",
            None,
            None,
            Some("ssh -L 8080:internal:80 user@remote"),
            0,
        );
        let alert = det.check_event(&ev).unwrap();
        assert_eq!(alert.technique, LateralTechnique::RemoteToolExecution);
    }

    #[test]
    fn unrelated_process_no_detection() {
        let mut det = LateralMovementDetector::new();
        let ev = make_event(1_700_000_000, EventClass::ProcessExec, "ls", None, None, None, 0);
        assert!(det.check_event(&ev).is_none());
    }
}
