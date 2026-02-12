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
    pub min_os_version: Option<String>,
    #[serde(default)]
    pub disk_encryption_required: bool,
    #[serde(default)]
    pub require_ssh_root_login_disabled: bool,
    #[serde(default)]
    pub required_packages: Vec<String>,
    #[serde(default)]
    pub forbidden_packages: Vec<String>,
    #[serde(default)]
    pub required_services: Vec<String>,
    #[serde(default)]
    pub password_policy_required: bool,
    #[serde(default)]
    pub screen_lock_required: bool,
    #[serde(default)]
    pub auto_updates_required: bool,
    #[serde(default)]
    pub antivirus_required: bool,
    #[serde(default)]
    pub check_interval_secs: Option<u64>,
    #[serde(default)]
    pub grace_period_secs: Option<u64>,
    #[serde(default)]
    pub auto_remediate: Option<bool>,
}

impl Default for CompliancePolicy {
    fn default() -> Self {
        Self {
            firewall_required: false,
            min_kernel_prefix: None,
            os_version_prefix: None,
            min_os_version: None,
            disk_encryption_required: false,
            require_ssh_root_login_disabled: false,
            required_packages: Vec::new(),
            forbidden_packages: Vec::new(),
            required_services: Vec::new(),
            password_policy_required: false,
            screen_lock_required: false,
            auto_updates_required: false,
            antivirus_required: false,
            check_interval_secs: None,
            grace_period_secs: None,
            auto_remediate: None,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationAction {
    pub action_id: String,
    pub command: String,
    pub args: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationOutcome {
    pub action_id: String,
    pub success: bool,
    pub detail: String,
}

pub trait CommandRunner {
    fn run(&self, command: &str, args: &[String]) -> std::io::Result<()>;
}

#[derive(Debug, Default)]
pub struct ShellCommandRunner;

impl CommandRunner for ShellCommandRunner {
    fn run(&self, command: &str, args: &[String]) -> std::io::Result<()> {
        let status = std::process::Command::new(command).args(args).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "command exited with status {}",
                status
            )))
        }
    }
}

#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    pub firewall_enabled: bool,
    pub kernel_version: String,
    pub os_version: Option<String>,
    pub root_fs_encrypted: Option<bool>,
    pub ssh_root_login_permitted: Option<bool>,
    pub installed_packages: Option<HashSet<String>>,
    pub running_services: Option<HashSet<String>>,
    pub password_policy_hardened: Option<bool>,
    pub screen_lock_enabled: Option<bool>,
    pub auto_updates_enabled: Option<bool>,
    pub antivirus_running: Option<bool>,
    pub agent_version: String,
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
            running_services: None,
            password_policy_hardened: None,
            screen_lock_enabled: None,
            auto_updates_enabled: None,
            antivirus_running: None,
            agent_version: current_agent_version().to_string(),
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

    if let Some(min_version) = &policy.min_os_version {
        let passed = snapshot
            .os_version
            .as_ref()
            .and_then(|v| version_number_prefix(v))
            .map(|v| version_gte(&v, min_version))
            .unwrap_or(false);
        let detail = match snapshot.os_version.as_ref() {
            Some(version) => format!(
                "os {} {} minimum {}",
                version,
                if passed { "meets" } else { "below" },
                min_version
            ),
            None => "os version unavailable".to_string(),
        };
        checks.push(check_result("os_version_gte", passed, detail));
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

    if !policy.required_services.is_empty() {
        for service in &policy.required_services {
            let running = snapshot
                .running_services
                .as_ref()
                .map(|services| services.contains(&service.to_ascii_lowercase()))
                .unwrap_or(false);
            checks.push(check_result(
                format!("service_running:{}", service),
                running,
                if running {
                    format!("required service {} is running", service)
                } else {
                    format!("required service {} is not running", service)
                },
            ));
        }
    }

    if policy.password_policy_required {
        let passed = snapshot.password_policy_hardened.unwrap_or(false);
        checks.push(check_result(
            "password_policy",
            passed,
            if passed {
                "password policy appears hardened".to_string()
            } else {
                "password policy not hardened".to_string()
            },
        ));
    }

    if policy.screen_lock_required {
        let passed = snapshot.screen_lock_enabled.unwrap_or(false);
        checks.push(check_result(
            "screen_lock_enabled",
            passed,
            if passed {
                "screen lock appears enabled".to_string()
            } else {
                "screen lock appears disabled".to_string()
            },
        ));
    }

    if policy.auto_updates_required {
        let passed = snapshot.auto_updates_enabled.unwrap_or(false);
        checks.push(check_result(
            "auto_updates",
            passed,
            if passed {
                "automatic updates appear enabled".to_string()
            } else {
                "automatic updates appear disabled".to_string()
            },
        ));
    }

    if policy.antivirus_required {
        let passed = snapshot.antivirus_running.unwrap_or(false);
        checks.push(check_result(
            "antivirus_running",
            passed,
            if passed {
                "antivirus process detected".to_string()
            } else {
                "antivirus process not detected".to_string()
            },
        ));
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

pub fn plan_remediation_actions(
    policy: &CompliancePolicy,
    snapshot: &SystemSnapshot,
) -> Vec<RemediationAction> {
    let mut actions = Vec::new();

    if policy.firewall_required && !snapshot.firewall_enabled {
        actions.push(RemediationAction {
            action_id: "enable_firewall".to_string(),
            command: "ufw".to_string(),
            args: vec!["--force".to_string(), "enable".to_string()],
            reason: "firewall_required policy is enabled".to_string(),
        });
    }

    if policy.require_ssh_root_login_disabled && snapshot.ssh_root_login_permitted == Some(true) {
        actions.push(RemediationAction {
            action_id: "disable_ssh_root_login".to_string(),
            command: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "grep -q '^PermitRootLogin' /etc/ssh/sshd_config && sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && systemctl reload ssh || systemctl reload sshd".to_string(),
            ],
            reason: "require_ssh_root_login_disabled policy is enabled".to_string(),
        });
    }

    for package in &policy.required_packages {
        if !package_installed(snapshot, package) {
            actions.push(RemediationAction {
                action_id: format!("install_package:{}", package),
                command: "apt-get".to_string(),
                args: vec!["install".to_string(), "-y".to_string(), package.to_string()],
                reason: format!("required package {} is missing", package),
            });
        }
    }

    for package in &policy.forbidden_packages {
        if package_installed(snapshot, package) {
            actions.push(RemediationAction {
                action_id: format!("remove_package:{}", package),
                command: "apt-get".to_string(),
                args: vec!["remove".to_string(), "-y".to_string(), package.to_string()],
                reason: format!("forbidden package {} is installed", package),
            });
        }
    }

    actions
}

pub fn execute_remediation_actions<R: CommandRunner>(
    runner: &R,
    actions: &[RemediationAction],
) -> Vec<RemediationOutcome> {
    let mut outcomes = Vec::with_capacity(actions.len());
    for action in actions {
        match runner.run(&action.command, &action.args) {
            Ok(()) => outcomes.push(RemediationOutcome {
                action_id: action.action_id.clone(),
                success: true,
                detail: "ok".to_string(),
            }),
            Err(err) => outcomes.push(RemediationOutcome {
                action_id: action.action_id.clone(),
                success: false,
                detail: err.to_string(),
            }),
        }
    }
    outcomes
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

fn package_installed(snapshot: &SystemSnapshot, package: &str) -> bool {
    snapshot
        .installed_packages
        .as_ref()
        .map(|installed| installed.contains(&package.to_ascii_lowercase()))
        .unwrap_or(false)
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
        running_services: detect_running_services(),
        password_policy_hardened: detect_password_policy_hardened(),
        screen_lock_enabled: detect_screen_lock_enabled(),
        auto_updates_enabled: detect_auto_updates_enabled(),
        antivirus_running: detect_antivirus_running(),
        agent_version: current_agent_version().to_string(),
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
    parse_root_fs_encrypted_from_mounts(&raw)
}

fn detect_ssh_root_login_permitted() -> Option<bool> {
    let raw = fs::read_to_string("/etc/ssh/sshd_config").ok()?;
    parse_ssh_root_login_from_config(&raw)
}

fn parse_root_fs_encrypted_from_mounts(raw: &str) -> Option<bool> {
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

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

fn parse_ssh_root_login_from_config(raw: &str) -> Option<bool> {
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let value = line
            .strip_prefix("PermitRootLogin")
            .map(|v| v.trim())
            .or_else(|| line.strip_prefix("permitrootlogin").map(|v| v.trim()));

        if let Some(value) = value {
            let value = value.to_ascii_lowercase();
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

fn detect_running_services() -> Option<HashSet<String>> {
    let output = std::process::Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--no-pager",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_running_services_output(std::str::from_utf8(&output.stdout).ok()?)
}

fn parse_running_services_output(raw: &str) -> Option<HashSet<String>> {
    let mut out = HashSet::new();
    for line in raw.lines() {
        let Some(unit) = line.split_whitespace().next() else {
            continue;
        };
        if unit.ends_with(".service") {
            out.insert(unit.trim_end_matches(".service").to_ascii_lowercase());
        } else {
            out.insert(unit.to_ascii_lowercase());
        }
    }
    Some(out)
}

fn detect_password_policy_hardened() -> Option<bool> {
    let login_defs = fs::read_to_string("/etc/login.defs").ok();
    let common_password = fs::read_to_string("/etc/pam.d/common-password").ok();
    parse_password_policy(login_defs.as_deref(), common_password.as_deref())
}

fn parse_password_policy(
    login_defs: Option<&str>,
    pam_common_password: Option<&str>,
) -> Option<bool> {
    let mut max_days_ok = false;
    if let Some(raw) = login_defs {
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(v) = line.strip_prefix("PASS_MAX_DAYS") {
                let days = v.trim().split_whitespace().next()?.parse::<u64>().ok()?;
                max_days_ok = days <= 90;
            }
        }
    }

    let mut pam_quality_ok = false;
    if let Some(raw) = pam_common_password {
        let lower = raw.to_ascii_lowercase();
        pam_quality_ok = lower.contains("pam_pwquality.so") || lower.contains("pam_cracklib.so");
    }

    Some(max_days_ok && pam_quality_ok)
}

fn detect_screen_lock_enabled() -> Option<bool> {
    for path in [
        "/etc/dconf/db/local.d/00-security-settings",
        "/etc/dconf/db/local.d/01-screensaver",
    ] {
        if let Ok(raw) = fs::read_to_string(path) {
            let lower = raw.to_ascii_lowercase();
            if lower.contains("lock-enabled=true") || lower.contains("idle-delay") {
                return Some(true);
            }
        }
    }
    None
}

fn detect_auto_updates_enabled() -> Option<bool> {
    let installed = detect_installed_packages()
        .map(|pkgs| pkgs.contains("unattended-upgrades"))
        .unwrap_or(false);
    let apt_cfg = fs::read_to_string("/etc/apt/apt.conf.d/20auto-upgrades")
        .ok()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let enabled = apt_cfg.contains("apt::periodic::unattended-upgrade \"1\"");
    Some(installed && enabled)
}

fn detect_antivirus_running() -> Option<bool> {
    let proc_entries = fs::read_dir("/proc").ok()?;
    let known = ["clamd", "freshclam", "sav-protect", "falcon-sensor"];
    for entry in proc_entries.flatten() {
        let name = entry.file_name();
        let pid = name.to_string_lossy();
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let comm_path = entry.path().join("comm");
        if let Ok(raw) = fs::read_to_string(comm_path) {
            let comm = raw.trim().to_ascii_lowercase();
            if known.iter().any(|k| comm.contains(k)) {
                return Some(true);
            }
        }
    }
    Some(false)
}

pub fn current_agent_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn default_runtime_settings() -> (u64, bool) {
    (300, false)
}

fn version_number_prefix(raw: &str) -> Option<String> {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            out.push(ch);
        } else if !out.is_empty() {
            break;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn version_gte(current: &str, minimum: &str) -> bool {
    fn parse_parts(raw: &str) -> Vec<u64> {
        raw.split('.')
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    }

    let a = parse_parts(current);
    let b = parse_parts(minimum);
    let len = a.len().max(b.len());
    for i in 0..len {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        if av > bv {
            return true;
        }
        if av < bv {
            return false;
        }
    }
    true
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
mod tests;
