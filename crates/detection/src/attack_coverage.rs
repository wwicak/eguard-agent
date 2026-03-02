//! MITRE ATT&CK Coverage Report
//!
//! Auto-generate a report showing which ATT&CK techniques are detected
//! by the current detection ruleset. Maps eGuard's multi-layer detection
//! engine to the ATT&CK framework so SOC analysts can quantify coverage
//! and prioritise gap remediation.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackCoverageReport {
    pub total_techniques: usize,
    pub covered_techniques: usize,
    pub coverage_percent: f64,
    pub tactics: Vec<TacticCoverage>,
    /// High-priority technique IDs that have no detection rule.
    pub uncovered_critical: Vec<String>,
    /// Unix timestamp when the report was generated.
    pub generated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticCoverage {
    pub tactic_id: String,
    pub tactic_name: String,
    pub total: usize,
    pub covered: usize,
    pub techniques: Vec<TechniqueCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueCoverage {
    pub technique_id: String,
    pub technique_name: String,
    pub covered: bool,
    pub rule_count: usize,
    pub rule_sources: Vec<String>,
}

// ---------------------------------------------------------------------------
// Technique catalog
// ---------------------------------------------------------------------------

/// `(tactic_id, technique_id, technique_name)`
const CRITICAL_TECHNIQUES: &[(&str, &str, &str)] = &[
    // TA0001 - Initial Access
    ("TA0001", "T1190", "Exploit Public-Facing Application"),
    ("TA0001", "T1133", "External Remote Services"),
    ("TA0001", "T1566", "Phishing"),
    // TA0002 - Execution
    ("TA0002", "T1059", "Command and Scripting Interpreter"),
    ("TA0002", "T1059.001", "PowerShell"),
    ("TA0002", "T1059.004", "Unix Shell"),
    ("TA0002", "T1204", "User Execution"),
    ("TA0002", "T1203", "Exploitation for Client Execution"),
    // TA0003 - Persistence
    ("TA0003", "T1053", "Scheduled Task/Job"),
    ("TA0003", "T1053.003", "Cron"),
    ("TA0003", "T1136", "Create Account"),
    ("TA0003", "T1505.003", "Web Shell"),
    ("TA0003", "T1543", "Create or Modify System Process"),
    // TA0004 - Privilege Escalation
    ("TA0004", "T1548", "Abuse Elevation Control"),
    ("TA0004", "T1068", "Exploitation for Privilege Escalation"),
    ("TA0004", "T1055", "Process Injection"),
    // TA0005 - Defense Evasion
    ("TA0005", "T1070", "Indicator Removal"),
    ("TA0005", "T1562", "Impair Defenses"),
    ("TA0005", "T1014", "Rootkit"),
    ("TA0005", "T1036", "Masquerading"),
    ("TA0005", "T1027", "Obfuscated Files or Information"),
    // TA0006 - Credential Access
    ("TA0006", "T1003", "OS Credential Dumping"),
    ("TA0006", "T1110", "Brute Force"),
    ("TA0006", "T1552", "Unsecured Credentials"),
    ("TA0006", "T1558", "Steal or Forge Kerberos Tickets"),
    // TA0007 - Discovery
    ("TA0007", "T1087", "Account Discovery"),
    ("TA0007", "T1046", "Network Service Discovery"),
    ("TA0007", "T1083", "File and Directory Discovery"),
    ("TA0007", "T1057", "Process Discovery"),
    // TA0008 - Lateral Movement
    ("TA0008", "T1021", "Remote Services"),
    ("TA0008", "T1021.004", "SSH"),
    ("TA0008", "T1570", "Lateral Tool Transfer"),
    // TA0009 - Collection
    ("TA0009", "T1005", "Data from Local System"),
    ("TA0009", "T1074", "Data Staged"),
    ("TA0009", "T1119", "Automated Collection"),
    // TA0010 - Exfiltration
    ("TA0010", "T1041", "Exfiltration Over C2 Channel"),
    ("TA0010", "T1052", "Exfiltration Over Physical Medium"),
    ("TA0010", "T1048", "Exfiltration Over Alternative Protocol"),
    // TA0011 - Command and Control
    ("TA0011", "T1071", "Application Layer Protocol"),
    ("TA0011", "T1573", "Encrypted Channel"),
    ("TA0011", "T1105", "Ingress Tool Transfer"),
    ("TA0011", "T1571", "Non-Standard Port"),
    // TA0040 - Impact
    ("TA0040", "T1486", "Data Encrypted for Impact"),
    ("TA0040", "T1489", "Service Stop"),
    ("TA0040", "T1496", "Resource Hijacking"),
    ("TA0040", "T1531", "Account Access Removal"),
];

/// Tactic metadata: `(tactic_id, tactic_name)`.
const TACTICS: &[(&str, &str)] = &[
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0010", "Exfiltration"),
    ("TA0011", "Command and Control"),
    ("TA0040", "Impact"),
];

// ---------------------------------------------------------------------------
// Built-in detection layer coverage map
// ---------------------------------------------------------------------------

/// Techniques covered by eGuard's built-in detection layers
/// (independent of dynamically loaded SIGMA rules).
///
/// `(technique_id, layer_source)`
const BUILTIN_COVERAGE: &[(&str, &str)] = &[
    // L1 IOC layer
    ("T1071", "L1 IOC"),
    ("T1041", "L1 IOC"),
    ("T1573", "L1 IOC"),
    // L3 Anomaly engine
    ("T1059", "L3 Anomaly"),
    ("T1059.001", "L3 Anomaly"),
    ("T1059.004", "L3 Anomaly"),
    ("T1053", "L3 Anomaly"),
    ("T1053.003", "L3 Anomaly"),
    // L4 Kill chain engine
    ("T1548", "L4 Kill Chain"),
    ("T1068", "L4 Kill Chain"),
    ("T1055", "L4 Kill Chain"),
    // Behavioral engine
    ("T1110", "Behavioral"),
    ("T1486", "Behavioral"),
    ("T1496", "Behavioral"),
    ("T1489", "Behavioral"),
    // CVE / Vulnerability scanner
    ("T1190", "CVE Scanner"),
    ("T1203", "CVE Scanner"),
    // Lateral movement detector
    ("T1021", "Lateral Movement"),
    ("T1021.004", "Lateral Movement"),
    ("T1003", "Lateral Movement"),
    ("T1570", "Lateral Movement"),
    // FIM (File Integrity Monitoring)
    ("T1070", "FIM"),
    ("T1562", "FIM"),
    ("T1543", "FIM"),
    // USB control
    ("T1052", "USB Control"),
    // Deception tokens
    ("T1005", "Deception"),
    ("T1083", "Deception"),
    ("T1552", "Deception"),
    // Kernel integrity scanner
    ("T1014", "Kernel Integrity"),
    // Memory / YARA scanner
    ("T1027", "YARA / Memory"),
    ("T1036", "YARA / Memory"),
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a coverage report given a set of technique IDs detected by
/// dynamically-loaded rules (e.g., SIGMA rules). The built-in detection
/// layers are always included.
pub fn generate_coverage(detected_techniques: &HashSet<String>, now: i64) -> AttackCoverageReport {
    // Merge built-in and dynamic coverage.
    let mut coverage_map: HashMap<String, Vec<String>> = HashMap::new();
    for &(tid, source) in BUILTIN_COVERAGE {
        coverage_map
            .entry(tid.to_owned())
            .or_default()
            .push(source.to_owned());
    }
    for tid in detected_techniques {
        coverage_map
            .entry(tid.clone())
            .or_default()
            .push("SIGMA Rules".to_owned());
    }

    // Group techniques by tactic.
    let mut tactic_map: HashMap<&str, Vec<(&str, &str)>> = HashMap::new();
    for &(tactic, tech_id, tech_name) in CRITICAL_TECHNIQUES {
        tactic_map
            .entry(tactic)
            .or_default()
            .push((tech_id, tech_name));
    }

    let mut tactics = Vec::new();
    let mut total_techniques = 0usize;
    let mut covered_techniques = 0usize;

    for &(tactic_id, tactic_name) in TACTICS {
        let techs = match tactic_map.get(tactic_id) {
            Some(t) => t,
            None => continue,
        };
        let mut technique_coverage = Vec::new();
        for &(tech_id, tech_name) in techs {
            let sources = coverage_map.get(tech_id);
            let covered = sources.is_some();
            let rule_count = sources.map_or(0, |s| s.len());
            let rule_sources = sources.cloned().unwrap_or_default();
            if covered {
                covered_techniques += 1;
            }
            total_techniques += 1;
            technique_coverage.push(TechniqueCoverage {
                technique_id: tech_id.to_owned(),
                technique_name: tech_name.to_owned(),
                covered,
                rule_count,
                rule_sources,
            });
        }
        let tactic_covered = technique_coverage.iter().filter(|t| t.covered).count();
        tactics.push(TacticCoverage {
            tactic_id: tactic_id.to_owned(),
            tactic_name: tactic_name.to_owned(),
            total: technique_coverage.len(),
            covered: tactic_covered,
            techniques: technique_coverage,
        });
    }

    let coverage_percent = if total_techniques > 0 {
        (covered_techniques as f64 / total_techniques as f64) * 100.0
    } else {
        0.0
    };

    let uncovered_critical = critical_gaps_from_map(&coverage_map);

    AttackCoverageReport {
        total_techniques,
        covered_techniques,
        coverage_percent,
        tactics,
        uncovered_critical,
        generated_at: now,
    }
}

/// Return technique IDs from the critical catalog that have zero coverage.
pub fn critical_gaps(report: &AttackCoverageReport) -> Vec<String> {
    report.uncovered_critical.clone()
}

/// Internal: compute uncovered critical techniques.
fn critical_gaps_from_map(coverage_map: &HashMap<String, Vec<String>>) -> Vec<String> {
    CRITICAL_TECHNIQUES
        .iter()
        .filter(|&(_, tid, _)| !coverage_map.contains_key(*tid))
        .map(|&(_, tid, _)| tid.to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_coverage_yields_100_percent() {
        // Provide every technique in the catalog as detected.
        let all: HashSet<String> = CRITICAL_TECHNIQUES
            .iter()
            .map(|&(_, tid, _)| tid.to_owned())
            .collect();
        let report = generate_coverage(&all, 1_700_000_000);
        assert_eq!(report.covered_techniques, report.total_techniques);
        assert!((report.coverage_percent - 100.0).abs() < f64::EPSILON);
        assert!(report.uncovered_critical.is_empty());
    }

    #[test]
    fn partial_coverage_calculates_correctly() {
        // Only provide built-in coverage, no SIGMA rules.
        let empty: HashSet<String> = HashSet::new();
        let report = generate_coverage(&empty, 1_700_000_000);

        // Built-in coverage should cover a subset of the catalog.
        assert!(report.covered_techniques > 0);
        assert!(report.covered_techniques < report.total_techniques);
        assert!(report.coverage_percent > 0.0);
        assert!(report.coverage_percent < 100.0);
    }

    #[test]
    fn critical_gaps_identified_when_missing() {
        let empty: HashSet<String> = HashSet::new();
        let report = generate_coverage(&empty, 1_700_000_000);
        let gaps = critical_gaps(&report);
        // At least some techniques should be uncovered without SIGMA rules.
        assert!(!gaps.is_empty());
        // Every gap should be a valid technique ID from the catalog.
        let catalog: HashSet<&str> = CRITICAL_TECHNIQUES.iter().map(|&(_, tid, _)| tid).collect();
        for gap in &gaps {
            assert!(catalog.contains(gap.as_str()), "unexpected gap: {gap}");
        }
    }

    #[test]
    fn tactics_cover_all_twelve() {
        let empty: HashSet<String> = HashSet::new();
        let report = generate_coverage(&empty, 0);
        assert_eq!(report.tactics.len(), TACTICS.len());
    }

    #[test]
    fn sigma_rules_add_to_coverage() {
        let empty: HashSet<String> = HashSet::new();
        let base = generate_coverage(&empty, 0);

        // Add a technique that is NOT already covered by built-in layers.
        let gaps = critical_gaps(&base);
        assert!(!gaps.is_empty());
        let extra_tech = gaps[0].clone();

        let mut sigma_set: HashSet<String> = HashSet::new();
        sigma_set.insert(extra_tech.clone());
        let enriched = generate_coverage(&sigma_set, 0);
        assert!(enriched.covered_techniques > base.covered_techniques);
        assert!(!critical_gaps(&enriched).contains(&extra_tech));
    }
}
