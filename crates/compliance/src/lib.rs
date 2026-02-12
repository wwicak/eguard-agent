use std::collections::HashSet;
use std::fmt;
use std::fs;

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum ComplianceError {
    PolicyParse(String),
    Probe(String),
}

impl fmt::Display for ComplianceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyParse(msg) => write!(f, "failed parsing compliance policy: {}", msg),
            Self::Probe(msg) => write!(f, "failed probing compliance state: {}", msg),
        }
    }
}

impl std::error::Error for ComplianceError {}

pub type Result<T> = std::result::Result<T, ComplianceError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePolicy {
    #[serde(default)]
    pub firewall_required: bool,
    #[serde(default)]
    pub min_kernel_prefix: Option<String>,
    #[serde(default)]
    pub os_version_prefix: Option<String>,
    #[serde(default)]
    pub disk_encryption_required: bool,
    #[serde(default)]
    pub require_ssh_root_login_disabled: bool,
    #[serde(default)]
    pub required_packages: Vec<String>,
    #[serde(default)]
    pub forbidden_packages: Vec<String>,
}

impl Default for CompliancePolicy {
    fn default() -> Self {
        Self {
            firewall_required: false,
            min_kernel_prefix: None,
            os_version_prefix: None,
            disk_encryption_required: false,
            require_ssh_root_login_disabled: false,
            required_packages: Vec::new(),
            forbidden_packages: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheck {
    pub check: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub status: String,
    pub detail: String,
    pub checks: Vec<ComplianceCheck>,
}

#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    pub firewall_enabled: bool,
    pub kernel_version: String,
    pub os_version: Option<String>,
    pub root_fs_encrypted: Option<bool>,
    pub ssh_root_login_permitted: Option<bool>,
    pub installed_packages: Option<HashSet<String>>,
}

impl SystemSnapshot {
    pub fn minimal(firewall_enabled: bool, kernel_version: &str) -> Self {
        Self {
            firewall_enabled,
            kernel_version: kernel_version.to_string(),
            os_version: None,
            root_fs_encrypted: None,
            ssh_root_login_permitted: None,
            installed_packages: None,
        }
    }
}

pub fn parse_policy_json(raw: &str) -> Result<CompliancePolicy> {
    serde_json::from_str(raw).map_err(|err| ComplianceError::PolicyParse(err.to_string()))
}

pub fn evaluate(
    policy: &CompliancePolicy,
    firewall_enabled: bool,
    kernel_version: &str,
) -> ComplianceResult {
    evaluate_snapshot(
        policy,
        &SystemSnapshot::minimal(firewall_enabled, kernel_version),
    )
}

pub fn evaluate_linux(policy: &CompliancePolicy) -> Result<ComplianceResult> {
    let snapshot = collect_linux_snapshot()?;
    Ok(evaluate_snapshot(policy, &snapshot))
}

pub fn evaluate_snapshot(policy: &CompliancePolicy, snapshot: &SystemSnapshot) -> ComplianceResult {
    let mut checks = Vec::new();

    if policy.firewall_required {
        checks.push(check_result(
            "firewall_required",
            snapshot.firewall_enabled,
            if snapshot.firewall_enabled {
                "firewall appears active"
            } else {
                "firewall appears inactive"
            },
        ));
    }

    if let Some(prefix) = &policy.min_kernel_prefix {
        checks.push(check_result(
            "kernel_prefix",
            snapshot.kernel_version.starts_with(prefix),
            format!(
                "kernel {} {} required prefix {}",
                snapshot.kernel_version,
                if snapshot.kernel_version.starts_with(prefix) {
                    "matches"
                } else {
                    "does not match"
                },
                prefix
            ),
        ));
    }

    if let Some(prefix) = &policy.os_version_prefix {
        let passed = snapshot
            .os_version
            .as_ref()
            .map(|v| v.starts_with(prefix))
            .unwrap_or(false);
        let detail = match snapshot.os_version.as_ref() {
            Some(version) => format!(
                "os {} {} required prefix {}",
                version,
                if passed { "matches" } else { "does not match" },
                prefix
            ),
            None => "os version unavailable".to_string(),
        };
        checks.push(check_result("os_version_prefix", passed, detail));
    }

    if policy.disk_encryption_required {
        let passed = snapshot.root_fs_encrypted.unwrap_or(false);
        let detail = if passed {
            "root filesystem appears encrypted".to_string()
        } else {
            "root filesystem encryption not detected".to_string()
        };
        checks.push(check_result("disk_encryption", passed, detail));
    }

    if policy.require_ssh_root_login_disabled {
        let passed = snapshot
            .ssh_root_login_permitted
            .map(|v| !v)
            .unwrap_or(false);
        let detail = match snapshot.ssh_root_login_permitted {
            Some(true) => "PermitRootLogin allows root login".to_string(),
            Some(false) => "PermitRootLogin does not allow root login".to_string(),
            None => "unable to determine PermitRootLogin".to_string(),
        };
        checks.push(check_result("ssh_root_login", passed, detail));
    }

    if !policy.required_packages.is_empty() {
        for package in &policy.required_packages {
            let passed = snapshot
                .installed_packages
                .as_ref()
                .map(|installed| installed.contains(&package.to_ascii_lowercase()))
                .unwrap_or(false);
            checks.push(check_result(
                format!("package_present:{}", package),
                passed,
                if passed {
                    format!("required package {} is installed", package)
                } else {
                    format!("required package {} is missing", package)
                },
            ));
        }
    }

    if !policy.forbidden_packages.is_empty() {
        for package in &policy.forbidden_packages {
            let installed = snapshot
                .installed_packages
                .as_ref()
                .map(|set| set.contains(&package.to_ascii_lowercase()))
                .unwrap_or(false);
            checks.push(check_result(
                format!("package_absent:{}", package),
                !installed,
                if installed {
                    format!("forbidden package {} is installed", package)
                } else {
                    format!("forbidden package {} is not installed", package)
                },
            ));
        }
    }

    let failing: Vec<&ComplianceCheck> = checks
        .iter()
        .filter(|check| check.status == "fail")
        .collect();
    if failing.is_empty() {
        ComplianceResult {
            status: "pass".to_string(),
            detail: "policy checks passed".to_string(),
            checks,
        }
    } else {
        let failed_checks = failing
            .iter()
            .map(|check| check.check.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        ComplianceResult {
            status: "fail".to_string(),
            detail: format!("{} check(s) failed: {}", failing.len(), failed_checks),
            checks,
        }
    }
}

fn check_result(
    check: impl Into<String>,
    passed: bool,
    detail: impl Into<String>,
) -> ComplianceCheck {
    ComplianceCheck {
        check: check.into(),
        status: if passed { "pass" } else { "fail" }.to_string(),
        detail: detail.into(),
    }
}

fn collect_linux_snapshot() -> Result<SystemSnapshot> {
    let kernel_version = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|v| v.trim().to_string())
        .map_err(|err| ComplianceError::Probe(format!("kernel version probe failed: {}", err)))?;

    Ok(SystemSnapshot {
        firewall_enabled: detect_firewall_enabled(),
        kernel_version,
        os_version: detect_os_version(),
        root_fs_encrypted: detect_root_fs_encrypted(),
        ssh_root_login_permitted: detect_ssh_root_login_permitted(),
        installed_packages: detect_installed_packages(),
    })
}

fn detect_firewall_enabled() -> bool {
    for path in [
        "/proc/net/ip_tables_names",
        "/proc/net/ip6_tables_names",
        "/proc/net/nf_tables",
    ] {
        if let Ok(raw) = fs::read_to_string(path) {
            if raw.lines().any(|line| !line.trim().is_empty()) {
                return true;
            }
        }
    }
    false
}

fn detect_os_version() -> Option<String> {
    let raw = fs::read_to_string("/etc/os-release").ok()?;
    let mut pretty_name = None;
    let mut version_id = None;

    for line in raw.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
            pretty_name = Some(value.trim_matches('"').to_string());
        } else if let Some(value) = line.strip_prefix("VERSION_ID=") {
            version_id = Some(value.trim_matches('"').to_string());
        }
    }

    pretty_name.or(version_id)
}

fn detect_root_fs_encrypted() -> Option<bool> {
    let raw = fs::read_to_string("/proc/mounts").ok()?;
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let source = parts.next()?;
        let mountpoint = parts.next()?;
        if mountpoint == "/" {
            if source.starts_with("/dev/mapper/") {
                return Some(true);
            }
            if source.contains("crypt") || source.contains("luks") {
                return Some(true);
            }
            return Some(false);
        }
    }
    None
}

fn detect_ssh_root_login_permitted() -> Option<bool> {
    let raw = fs::read_to_string("/etc/ssh/sshd_config").ok()?;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(value) = line.strip_prefix("PermitRootLogin") {
            let value = value.trim().to_ascii_lowercase();
            return Some(matches!(value.as_str(), "yes" | "without-password"));
        }
    }
    Some(false)
}

fn detect_installed_packages() -> Option<HashSet<String>> {
    if let Some(pkgs) = parse_dpkg_status("/var/lib/dpkg/status") {
        return Some(pkgs);
    }
    None
}

fn parse_dpkg_status(path: &str) -> Option<HashSet<String>> {
    let raw = fs::read_to_string(path).ok()?;
    let mut installed = HashSet::new();

    let mut current_package: Option<String> = None;
    let mut current_installed = false;
    for line in raw.lines() {
        if line.is_empty() {
            if current_installed {
                if let Some(name) = current_package.take() {
                    installed.insert(name.to_ascii_lowercase());
                }
            }
            current_package = None;
            current_installed = false;
            continue;
        }

        if let Some(value) = line.strip_prefix("Package:") {
            current_package = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Status:") {
            current_installed = value.trim().eq_ignore_ascii_case("install ok installed");
        }
    }

    if current_installed {
        if let Some(name) = current_package {
            installed.insert(name.to_ascii_lowercase());
        }
    }

    Some(installed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_policy_json_handles_extended_fields() {
        let raw = r#"{
            "firewall_required": true,
            "min_kernel_prefix": "6.",
            "os_version_prefix": "Ubuntu",
            "disk_encryption_required": true,
            "require_ssh_root_login_disabled": true,
            "required_packages": ["auditd"],
            "forbidden_packages": ["telnetd"]
        }"#;

        let policy = parse_policy_json(raw).expect("parse policy");
        assert!(policy.firewall_required);
        assert_eq!(policy.min_kernel_prefix.as_deref(), Some("6."));
        assert_eq!(policy.os_version_prefix.as_deref(), Some("Ubuntu"));
        assert!(policy.disk_encryption_required);
        assert!(policy.require_ssh_root_login_disabled);
        assert_eq!(policy.required_packages, vec!["auditd"]);
        assert_eq!(policy.forbidden_packages, vec!["telnetd"]);
    }

    #[test]
    fn evaluate_snapshot_reports_package_and_kernel_failures() {
        let policy = CompliancePolicy {
            firewall_required: true,
            min_kernel_prefix: Some("6.8".to_string()),
            required_packages: vec!["auditd".to_string()],
            forbidden_packages: vec!["telnetd".to_string()],
            ..CompliancePolicy::default()
        };

        let mut installed = HashSet::new();
        installed.insert("telnetd".to_string());

        let snapshot = SystemSnapshot {
            firewall_enabled: false,
            kernel_version: "6.1.0".to_string(),
            os_version: Some("Ubuntu 22.04".to_string()),
            root_fs_encrypted: Some(true),
            ssh_root_login_permitted: Some(false),
            installed_packages: Some(installed),
        };

        let result = evaluate_snapshot(&policy, &snapshot);
        assert_eq!(result.status, "fail");
        assert!(result
            .checks
            .iter()
            .any(|check| { check.check == "firewall_required" && check.status == "fail" }));
        assert!(result
            .checks
            .iter()
            .any(|check| { check.check.starts_with("package_absent:") && check.status == "fail" }));
    }

    #[test]
    fn parse_dpkg_status_extracts_installed_packages() {
        let path = std::env::temp_dir().join(format!(
            "eguard-dpkg-status-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));

        fs::write(
            &path,
            "Package: auditd\nStatus: install ok installed\n\nPackage: telnetd\nStatus: purge ok not-installed\n",
        )
        .expect("write status file");

        let installed = parse_dpkg_status(path.to_string_lossy().as_ref()).expect("parse dpkg");
        assert!(installed.contains("auditd"));
        assert!(!installed.contains("telnetd"));

        let _ = fs::remove_file(path);
    }
}
