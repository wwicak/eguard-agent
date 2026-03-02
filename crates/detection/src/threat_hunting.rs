//! Threat Hunting Automation
//!
//! Scheduled hunting queries that run periodically and surface anomalies.
//! Each query maps to a MITRE ATT&CK technique and produces structured
//! findings that the lifecycle layer can forward to the control plane.
//!
//! The engine itself performs **no I/O** -- it evaluates abstract checks
//! against data supplied by the caller (platform layer / lifecycle).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The kind of check a hunting query performs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HuntingCheck {
    /// Check if any process matching pattern is running.
    ProcessPattern {
        /// Pipe-delimited substrings, e.g. `"xmrig|minerd|cpuminer"`.
        pattern: String,
        min_count: usize,
    },
    /// Check if files exist or were modified recently.
    FilePresence {
        paths: Vec<String>,
        /// `true` = alert when missing, `false` = alert when present.
        must_exist: bool,
    },
    /// Check for unusual network listeners.
    ListeningPorts { suspicious_ports: Vec<u16> },
    /// Check for persistence mechanisms.
    PersistenceMechanism { locations: Vec<String> },
    /// Custom command output check.
    CommandCheck {
        command: String,
        expect_pattern: String,
    },
}

/// A single scheduled hunting query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingQuery {
    pub name: String,
    pub description: String,
    pub technique_id: Option<String>,
    /// How often (in seconds) this query should execute.
    pub interval_secs: u64,
    pub check: HuntingCheck,
    /// Unix timestamp of last execution (0 = never run).
    pub last_run: i64,
    pub findings_count: u64,
}

/// A single finding produced by a hunting query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingFinding {
    pub query_name: String,
    pub technique_id: Option<String>,
    pub severity: &'static str,
    pub detail: String,
    pub found_at: i64,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Manages a set of [`HuntingQuery`]s, determines when they are due,
/// and evaluates checks against caller-supplied data.
pub struct HuntingEngine {
    queries: Vec<HuntingQuery>,
}

impl HuntingEngine {
    /// Create an engine pre-loaded with [`default_hunting_queries`].
    pub fn new() -> Self {
        Self {
            queries: default_hunting_queries(),
        }
    }

    /// Return references to queries that are due for execution at `now`.
    ///
    /// A query with `last_run == 0` is considered "never run" and is
    /// always due regardless of the current time.
    pub fn queries_due(&self, now: i64) -> Vec<&HuntingQuery> {
        self.queries
            .iter()
            .filter(|q| {
                if q.last_run == 0 {
                    return true; // never run yet
                }
                let next_run = q.last_run + q.interval_secs as i64;
                now >= next_run
            })
            .collect()
    }

    /// Record that a query was executed at `now` with `findings` results.
    pub fn record_run(&mut self, query_name: &str, now: i64, findings: usize) {
        if let Some(q) = self.queries.iter_mut().find(|q| q.name == query_name) {
            q.last_run = now;
            q.findings_count += findings as u64;
        }
    }

    /// Read-only access to all queries.
    pub fn queries(&self) -> &[HuntingQuery] {
        &self.queries
    }
}

impl Default for HuntingEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Check evaluation helpers (no I/O -- pure logic)
// ---------------------------------------------------------------------------

/// Simple pipe-delimited substring matching (no regex dependency).
///
/// Returns `true` if `process_name` contains any substring from the
/// pipe-separated `pattern`.
pub fn match_process_pattern(pattern: &str, process_name: &str) -> bool {
    let lower = process_name.to_ascii_lowercase();
    pattern
        .split('|')
        .any(|sub| !sub.is_empty() && lower.contains(&sub.to_ascii_lowercase()))
}

/// Evaluate a [`HuntingCheck::ProcessPattern`] against a list of running
/// process names.
pub fn evaluate_process_check(
    pattern: &str,
    min_count: usize,
    running_processes: &[&str],
    query_name: &str,
    technique_id: Option<&str>,
    now: i64,
) -> Vec<HuntingFinding> {
    let matches: Vec<&str> = running_processes
        .iter()
        .copied()
        .filter(|p| match_process_pattern(pattern, p))
        .collect();

    if matches.len() >= min_count {
        vec![HuntingFinding {
            query_name: query_name.to_owned(),
            technique_id: technique_id.map(str::to_owned),
            severity: "high",
            detail: format!(
                "Matched {} process(es): {}",
                matches.len(),
                matches.join(", ")
            ),
            found_at: now,
        }]
    } else {
        Vec::new()
    }
}

/// Evaluate a [`HuntingCheck::ListeningPorts`] against a list of ports
/// currently in LISTEN state.
pub fn evaluate_port_check(
    suspicious_ports: &[u16],
    active_ports: &[u16],
    query_name: &str,
    technique_id: Option<&str>,
    now: i64,
) -> Vec<HuntingFinding> {
    let mut findings = Vec::new();
    for &port in suspicious_ports {
        if active_ports.contains(&port) {
            findings.push(HuntingFinding {
                query_name: query_name.to_owned(),
                technique_id: technique_id.map(str::to_owned),
                severity: "high",
                detail: format!("Suspicious listener on port {port}"),
                found_at: now,
            });
        }
    }
    findings
}

/// Evaluate a [`HuntingCheck::FilePresence`] against a list of paths that
/// currently exist on the filesystem.
pub fn evaluate_file_presence_check(
    watched_paths: &[String],
    must_exist: bool,
    existing_paths: &[&str],
    query_name: &str,
    technique_id: Option<&str>,
    now: i64,
) -> Vec<HuntingFinding> {
    let mut findings = Vec::new();
    for path in watched_paths {
        let exists = existing_paths.contains(&path.as_str());
        let alert = if must_exist { !exists } else { exists };
        if alert {
            let action = if must_exist { "missing" } else { "present" };
            findings.push(HuntingFinding {
                query_name: query_name.to_owned(),
                technique_id: technique_id.map(str::to_owned),
                severity: "medium",
                detail: format!("Watched path {action}: {path}"),
                found_at: now,
            });
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Default queries
// ---------------------------------------------------------------------------

/// Return the default set of hunting queries. Cross-platform queries are
/// always included; platform-specific queries are added via cfg gates.
pub fn default_hunting_queries() -> Vec<HuntingQuery> {
    let mut queries = cross_platform_queries();
    queries.extend(platform_queries());
    queries
}

/// Queries that apply to all platforms (cryptominer, reverse shell ports).
fn cross_platform_queries() -> Vec<HuntingQuery> {
    vec![
        HuntingQuery {
            name: "cryptominer_detection".into(),
            description: "Detect cryptocurrency mining processes".into(),
            technique_id: Some("T1496".into()),
            interval_secs: 3600,
            check: HuntingCheck::ProcessPattern {
                pattern: "xmrig|minerd|cpuminer|cgminer|bfgminer|ethminer".into(),
                min_count: 1,
            },
            last_run: 0,
            findings_count: 0,
        },
        HuntingQuery {
            name: "reverse_shell_listener".into(),
            description: "Detect common reverse shell ports".into(),
            technique_id: Some("T1059.004".into()),
            interval_secs: 1800,
            check: HuntingCheck::ListeningPorts {
                suspicious_ports: vec![4444, 4445, 5555, 6666, 7777, 8888, 9999, 1337, 31337],
            },
            last_run: 0,
            findings_count: 0,
        },
    ]
}

/// Platform-specific hunting queries.
#[cfg(target_os = "linux")]
fn platform_queries() -> Vec<HuntingQuery> {
    vec![
        HuntingQuery {
            name: "cron_persistence".into(),
            description: "Detect unauthorized cron jobs".into(),
            technique_id: Some("T1053.003".into()),
            interval_secs: 3600,
            check: HuntingCheck::PersistenceMechanism {
                locations: vec![
                    "/etc/crontab".into(),
                    "/var/spool/cron/".into(),
                    "/etc/cron.d/".into(),
                    "/etc/systemd/system/".into(),
                ],
            },
            last_run: 0,
            findings_count: 0,
        },
        HuntingQuery {
            name: "webshell_detection".into(),
            description: "Detect web shells in common locations".into(),
            technique_id: Some("T1505.003".into()),
            interval_secs: 3600,
            check: HuntingCheck::FilePresence {
                paths: vec![
                    "/var/www/html/.hidden.php".into(),
                    "/var/www/html/cmd.php".into(),
                    "/var/www/html/shell.php".into(),
                    "/tmp/backdoor.php".into(),
                ],
                must_exist: false,
            },
            last_run: 0,
            findings_count: 0,
        },
        HuntingQuery {
            name: "rootkit_indicators".into(),
            description: "Detect hidden processes and modules".into(),
            technique_id: Some("T1014".into()),
            interval_secs: 3600,
            check: HuntingCheck::FilePresence {
                paths: vec![
                    "/dev/shm/.hidden.so".into(),
                    "/tmp/.X11-unix/.hidden.so".into(),
                    "/usr/lib/.hidden/".into(),
                ],
                must_exist: false,
            },
            last_run: 0,
            findings_count: 0,
        },
    ]
}

/// Platform-specific hunting queries for Windows.
#[cfg(target_os = "windows")]
fn platform_queries() -> Vec<HuntingQuery> {
    vec![
        HuntingQuery {
            name: "scheduled_task_persistence".into(),
            description: "Detect suspicious scheduled tasks".into(),
            technique_id: Some("T1053.005".into()),
            interval_secs: 3600,
            check: HuntingCheck::PersistenceMechanism {
                locations: vec![
                    "C:\\Windows\\System32\\Tasks\\".into(),
                    "C:\\Windows\\SysWOW64\\Tasks\\".into(),
                ],
            },
            last_run: 0,
            findings_count: 0,
        },
        HuntingQuery {
            name: "run_key_persistence".into(),
            description: "Detect suspicious Run/RunOnce registry persistence via hive files".into(),
            technique_id: Some("T1547.001".into()),
            interval_secs: 3600,
            check: HuntingCheck::FilePresence {
                paths: vec![
                    "C:\\Windows\\System32\\config\\SOFTWARE".into(),
                    "C:\\Windows\\System32\\config\\NTUSER.DAT".into(),
                ],
                // These files should always exist; alert if missing (tampered/deleted).
                must_exist: true,
            },
            last_run: 0,
            findings_count: 0,
        },
        HuntingQuery {
            name: "service_persistence".into(),
            description: "Detect unusual services via SYSTEM hive".into(),
            technique_id: Some("T1543.003".into()),
            interval_secs: 3600,
            check: HuntingCheck::PersistenceMechanism {
                locations: vec!["C:\\Windows\\System32\\config\\SYSTEM".into()],
            },
            last_run: 0,
            findings_count: 0,
        },
        HuntingQuery {
            name: "webshell_detection_iis".into(),
            description: "Detect web shells in IIS wwwroot".into(),
            technique_id: Some("T1505.003".into()),
            interval_secs: 3600,
            check: HuntingCheck::FilePresence {
                paths: vec![
                    "C:\\inetpub\\wwwroot\\cmd.aspx".into(),
                    "C:\\inetpub\\wwwroot\\shell.aspx".into(),
                    "C:\\inetpub\\wwwroot\\.hidden.aspx".into(),
                ],
                must_exist: false,
            },
            last_run: 0,
            findings_count: 0,
        },
    ]
}

/// Platform-specific hunting queries for macOS.
#[cfg(target_os = "macos")]
fn platform_queries() -> Vec<HuntingQuery> {
    vec![
        HuntingQuery {
            name: "launch_agent_persistence".into(),
            description: "Detect suspicious LaunchAgent/LaunchDaemon plists".into(),
            technique_id: Some("T1543.004".into()),
            interval_secs: 3600,
            check: HuntingCheck::PersistenceMechanism {
                locations: vec![
                    "/Library/LaunchDaemons/".into(),
                    "/Library/LaunchAgents/".into(),
                    "~/Library/LaunchAgents/".into(),
                ],
            },
            last_run: 0,
            findings_count: 0,
        },
        HuntingQuery {
            name: "login_items_persistence".into(),
            description: "Detect suspicious login items".into(),
            technique_id: Some("T1547.015".into()),
            interval_secs: 3600,
            check: HuntingCheck::PersistenceMechanism {
                locations: vec!["~/Library/Application Support/com.apple.sharedfilelist/".into()],
            },
            last_run: 0,
            findings_count: 0,
        },
        HuntingQuery {
            name: "kernel_extension_detection".into(),
            description: "Detect suspicious kernel extensions".into(),
            technique_id: Some("T1547.006".into()),
            interval_secs: 3600,
            check: HuntingCheck::PersistenceMechanism {
                locations: vec![
                    "/Library/Extensions/".into(),
                    "/System/Library/Extensions/".into(),
                ],
            },
            last_run: 0,
            findings_count: 0,
        },
    ]
}

/// Fallback for platforms that are not Linux, Windows, or macOS.
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn platform_queries() -> Vec<HuntingQuery> {
    vec![HuntingQuery {
        name: "cron_persistence".into(),
        description: "Detect unauthorized cron jobs".into(),
        technique_id: Some("T1053.003".into()),
        interval_secs: 3600,
        check: HuntingCheck::PersistenceMechanism {
            locations: vec!["/etc/crontab".into(), "/var/spool/cron/".into()],
        },
        last_run: 0,
        findings_count: 0,
    }]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cryptominer_pattern_matches_xmrig() {
        assert!(match_process_pattern("xmrig|minerd|cpuminer", "xmrig"));
        assert!(match_process_pattern(
            "xmrig|minerd|cpuminer",
            "/usr/bin/xmrig"
        ));
        assert!(match_process_pattern("xmrig|minerd|cpuminer", "XMRIG"));
        assert!(!match_process_pattern("xmrig|minerd|cpuminer", "firefox"));
    }

    #[test]
    fn reverse_shell_port_detection() {
        let findings = evaluate_port_check(
            &[4444, 5555, 31337],
            &[80, 443, 4444, 22],
            "reverse_shell_listener",
            Some("T1059.004"),
            1_700_000_000,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("4444"));
    }

    #[test]
    fn query_due_respects_interval() {
        let mut engine = HuntingEngine::new();
        // All queries have last_run=0, so at t=0 they are all due.
        assert!(!engine.queries_due(0).is_empty());

        // Record a run at t=100 for cryptominer (interval=3600).
        engine.record_run("cryptominer_detection", 100, 0);

        // At t=200, cryptominer should NOT be due yet.
        let due_at_200 = engine.queries_due(200);
        assert!(due_at_200.iter().all(|q| q.name != "cryptominer_detection"));

        // At t=3701 it should be due again.
        let due_at_3701 = engine.queries_due(3701);
        assert!(due_at_3701
            .iter()
            .any(|q| q.name == "cryptominer_detection"));
    }

    #[test]
    fn record_run_updates_last_run_and_findings_count() {
        let mut engine = HuntingEngine::new();
        engine.record_run("cryptominer_detection", 5000, 3);
        let q = engine
            .queries()
            .iter()
            .find(|q| q.name == "cryptominer_detection")
            .unwrap();
        assert_eq!(q.last_run, 5000);
        assert_eq!(q.findings_count, 3);

        // Second run accumulates.
        engine.record_run("cryptominer_detection", 9000, 2);
        let q = engine
            .queries()
            .iter()
            .find(|q| q.name == "cryptominer_detection")
            .unwrap();
        assert_eq!(q.last_run, 9000);
        assert_eq!(q.findings_count, 5);
    }

    #[test]
    fn default_queries_cover_key_attack_techniques() {
        let queries = default_hunting_queries();
        let techniques: Vec<&str> = queries
            .iter()
            .filter_map(|q| q.technique_id.as_deref())
            .collect();
        assert!(techniques.contains(&"T1496")); // Cryptomining
        assert!(techniques.contains(&"T1059.004")); // Reverse shell
                                                    // Platform-specific technique IDs vary, but at least the cross-platform
                                                    // ones are always present.
    }

    #[test]
    fn default_queries_include_platform_specific() {
        let queries = default_hunting_queries();
        // Cross-platform queries are always present.
        assert!(queries.iter().any(|q| q.name == "cryptominer_detection"));
        assert!(queries.iter().any(|q| q.name == "reverse_shell_listener"));
        // Platform-specific queries should also be present (at least one).
        let platform_count = queries.len() - 2; // subtract cross-platform
        assert!(
            platform_count >= 1,
            "expected at least 1 platform-specific query"
        );
    }

    #[test]
    fn process_check_finds_miners() {
        let processes = vec!["systemd", "sshd", "xmrig", "cron"];
        let findings = evaluate_process_check(
            "xmrig|minerd",
            1,
            &processes,
            "cryptominer_detection",
            Some("T1496"),
            1_700_000_000,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("xmrig"));
        assert_eq!(findings[0].severity, "high");
    }

    #[test]
    fn process_check_min_count_respected() {
        let processes = vec!["sshd", "xmrig"];
        // Require at least 2 matches, but only 1 is present.
        let findings = evaluate_process_check("xmrig|minerd", 2, &processes, "test", None, 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn file_presence_detects_webshell() {
        let existing = vec!["/var/www/html/cmd.php"];
        let findings = evaluate_file_presence_check(
            &[
                "/var/www/html/cmd.php".into(),
                "/var/www/html/shell.php".into(),
            ],
            false, // alert when present
            &existing,
            "webshell_detection",
            Some("T1505.003"),
            1_700_000_000,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("cmd.php"));
    }

    #[test]
    fn empty_pattern_does_not_match() {
        assert!(!match_process_pattern("", "anything"));
        assert!(!match_process_pattern("||", "anything"));
    }
}
