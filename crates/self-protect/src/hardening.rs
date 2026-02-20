#[cfg(target_os = "linux")]
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct LinuxHardeningConfig {
    pub set_dumpable_zero: bool,
    pub restrict_ptrace: bool,
    pub set_no_new_privs: bool,
    pub drop_capability_bounding_set: bool,
    pub retained_capability_names: Vec<String>,
    pub enable_seccomp_strict: bool,
}

impl Default for LinuxHardeningConfig {
    fn default() -> Self {
        Self {
            set_dumpable_zero: env_bool("EGUARD_SELF_PROTECT_SET_DUMPABLE", true),
            restrict_ptrace: env_bool("EGUARD_SELF_PROTECT_RESTRICT_PTRACE", true),
            set_no_new_privs: env_bool("EGUARD_SELF_PROTECT_SET_NO_NEW_PRIVS", true),
            drop_capability_bounding_set: env_bool("EGUARD_SELF_PROTECT_DROP_CAPS", true),
            retained_capability_names: default_retained_capabilities(),
            enable_seccomp_strict: env_bool("EGUARD_SELF_PROTECT_ENABLE_SECCOMP_STRICT", false),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxHardeningStepStatus {
    Applied,
    Skipped,
    Failed,
}

#[derive(Debug, Clone)]
pub struct LinuxHardeningStep {
    pub name: &'static str,
    pub status: LinuxHardeningStepStatus,
    pub detail: String,
}

impl LinuxHardeningStep {
    #[cfg(target_os = "linux")]
    fn applied(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: LinuxHardeningStepStatus::Applied,
            detail: detail.into(),
        }
    }

    fn skipped(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: LinuxHardeningStepStatus::Skipped,
            detail: detail.into(),
        }
    }

    #[cfg(target_os = "linux")]
    fn failed(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: LinuxHardeningStepStatus::Failed,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinuxHardeningReport {
    pub steps: Vec<LinuxHardeningStep>,
    pub retained_capability_names: Vec<String>,
    pub dropped_capability_count: usize,
}

impl LinuxHardeningReport {
    pub fn has_failures(&self) -> bool {
        self.steps
            .iter()
            .any(|step| matches!(step.status, LinuxHardeningStepStatus::Failed))
    }

    pub fn failed_step_names(&self) -> Vec<&'static str> {
        self.steps
            .iter()
            .filter(|step| matches!(step.status, LinuxHardeningStepStatus::Failed))
            .map(|step| step.name)
            .collect()
    }
}

pub fn default_retained_capabilities() -> Vec<String> {
    [
        "CAP_BPF",
        "CAP_SYS_ADMIN",
        "CAP_NET_ADMIN",
        "CAP_DAC_READ_SEARCH",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

pub fn capability_number(name: &str) -> Option<u32> {
    match name.trim().to_ascii_uppercase().as_str() {
        "CAP_CHOWN" => Some(0),
        "CAP_DAC_OVERRIDE" => Some(1),
        "CAP_DAC_READ_SEARCH" => Some(2),
        "CAP_FOWNER" => Some(3),
        "CAP_FSETID" => Some(4),
        "CAP_KILL" => Some(5),
        "CAP_SETGID" => Some(6),
        "CAP_SETUID" => Some(7),
        "CAP_SETPCAP" => Some(8),
        "CAP_LINUX_IMMUTABLE" => Some(9),
        "CAP_NET_BIND_SERVICE" => Some(10),
        "CAP_NET_BROADCAST" => Some(11),
        "CAP_NET_ADMIN" => Some(12),
        "CAP_NET_RAW" => Some(13),
        "CAP_IPC_LOCK" => Some(14),
        "CAP_IPC_OWNER" => Some(15),
        "CAP_SYS_MODULE" => Some(16),
        "CAP_SYS_RAWIO" => Some(17),
        "CAP_SYS_CHROOT" => Some(18),
        "CAP_SYS_PTRACE" => Some(19),
        "CAP_SYS_PACCT" => Some(20),
        "CAP_SYS_ADMIN" => Some(21),
        "CAP_SYS_BOOT" => Some(22),
        "CAP_SYS_NICE" => Some(23),
        "CAP_SYS_RESOURCE" => Some(24),
        "CAP_SYS_TIME" => Some(25),
        "CAP_SYS_TTY_CONFIG" => Some(26),
        "CAP_MKNOD" => Some(27),
        "CAP_LEASE" => Some(28),
        "CAP_AUDIT_WRITE" => Some(29),
        "CAP_AUDIT_CONTROL" => Some(30),
        "CAP_SETFCAP" => Some(31),
        "CAP_MAC_OVERRIDE" => Some(32),
        "CAP_MAC_ADMIN" => Some(33),
        "CAP_SYSLOG" => Some(34),
        "CAP_WAKE_ALARM" => Some(35),
        "CAP_BLOCK_SUSPEND" => Some(36),
        "CAP_AUDIT_READ" => Some(37),
        "CAP_PERFMON" => Some(38),
        "CAP_BPF" => Some(39),
        "CAP_CHECKPOINT_RESTORE" => Some(40),
        _ => None,
    }
}

pub fn apply_linux_hardening(config: &LinuxHardeningConfig) -> LinuxHardeningReport {
    let mut report = LinuxHardeningReport {
        steps: Vec::new(),
        retained_capability_names: config.retained_capability_names.clone(),
        dropped_capability_count: 0,
    };

    #[cfg(not(target_os = "linux"))]
    {
        report.steps.push(LinuxHardeningStep::skipped(
            "platform",
            "linux hardening is only supported on linux",
        ));
    }

    #[cfg(target_os = "linux")]
    {
        if config.set_dumpable_zero {
            match set_dumpable_zero() {
                Ok(()) => report
                    .steps
                    .push(LinuxHardeningStep::applied("prctl_dumpable", "set to 0")),
                Err(err) => report
                    .steps
                    .push(LinuxHardeningStep::failed("prctl_dumpable", err)),
            }
        } else {
            report.steps.push(LinuxHardeningStep::skipped(
                "prctl_dumpable",
                "disabled by configuration",
            ));
        }

        if config.restrict_ptrace {
            match restrict_ptrace() {
                Ok(()) => report.steps.push(LinuxHardeningStep::applied(
                    "prctl_ptracer",
                    "restricted to self (pid 0)",
                )),
                Err(err) => report
                    .steps
                    .push(LinuxHardeningStep::failed("prctl_ptracer", err)),
            }
        } else {
            report.steps.push(LinuxHardeningStep::skipped(
                "prctl_ptracer",
                "disabled by configuration",
            ));
        }

        if config.set_no_new_privs {
            match set_no_new_privs() {
                Ok(()) => report.steps.push(LinuxHardeningStep::applied(
                    "prctl_no_new_privs",
                    "set to 1",
                )),
                Err(err) => report
                    .steps
                    .push(LinuxHardeningStep::failed("prctl_no_new_privs", err)),
            }
        } else {
            report.steps.push(LinuxHardeningStep::skipped(
                "prctl_no_new_privs",
                "disabled by configuration",
            ));
        }

        if config.drop_capability_bounding_set {
            match drop_capability_bounding_set(&config.retained_capability_names) {
                Ok(dropped) => {
                    report.dropped_capability_count = dropped;
                    report.steps.push(LinuxHardeningStep::applied(
                        "capability_bounding_set",
                        format!("dropped {} capabilities", dropped),
                    ));
                }
                Err(err) => report
                    .steps
                    .push(LinuxHardeningStep::failed("capability_bounding_set", err)),
            }
        } else {
            report.steps.push(LinuxHardeningStep::skipped(
                "capability_bounding_set",
                "disabled by configuration",
            ));
        }

        if config.enable_seccomp_strict {
            match set_seccomp_strict() {
                Ok(()) => report.steps.push(LinuxHardeningStep::applied(
                    "seccomp_strict",
                    "enabled strict seccomp mode",
                )),
                Err(err) => report
                    .steps
                    .push(LinuxHardeningStep::failed("seccomp_strict", err)),
            }
        } else {
            report.steps.push(LinuxHardeningStep::skipped(
                "seccomp_strict",
                "disabled by configuration (use dedicated allowlist filter profile)",
            ));
        }
    }

    report
}

#[cfg(target_os = "linux")]
fn set_dumpable_zero() -> Result<(), String> {
    run_prctl("PR_SET_DUMPABLE", libc::PR_SET_DUMPABLE, 0)
}

#[cfg(target_os = "linux")]
fn restrict_ptrace() -> Result<(), String> {
    run_prctl("PR_SET_PTRACER", libc::PR_SET_PTRACER, 0)
}

#[cfg(target_os = "linux")]
fn set_no_new_privs() -> Result<(), String> {
    run_prctl("PR_SET_NO_NEW_PRIVS", libc::PR_SET_NO_NEW_PRIVS, 1)
}

#[cfg(target_os = "linux")]
fn set_seccomp_strict() -> Result<(), String> {
    run_prctl(
        "PR_SET_SECCOMP",
        libc::PR_SET_SECCOMP,
        libc::SECCOMP_MODE_STRICT as libc::c_ulong,
    )
}

#[cfg(target_os = "linux")]
fn drop_capability_bounding_set(retained_names: &[String]) -> Result<usize, String> {
    let mut retained_numbers = BTreeSet::new();
    let mut unknown = Vec::new();
    for name in retained_names {
        match capability_number(name) {
            Some(number) => {
                retained_numbers.insert(number);
            }
            None => unknown.push(name.clone()),
        }
    }
    if !unknown.is_empty() {
        return Err(format!(
            "unknown retained capability names: {}",
            unknown.join(", ")
        ));
    }

    let mut dropped = 0usize;
    for cap in 0u32..=63 {
        if retained_numbers.contains(&cap) {
            continue;
        }

        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if rc == 0 {
            dropped += 1;
            continue;
        }

        let io_err = std::io::Error::last_os_error();
        match io_err.raw_os_error() {
            Some(code) if code == libc::EINVAL => {
                continue;
            }
            Some(code) if code == libc::EPERM => {
                return Err(
                    "insufficient privileges for PR_CAPBSET_DROP (CAP_SETPCAP required)"
                        .to_string(),
                );
            }
            _ => {
                return Err(format!("PR_CAPBSET_DROP({}) failed: {}", cap, io_err));
            }
        }
    }

    Ok(dropped)
}

#[cfg(target_os = "linux")]
fn run_prctl(name: &'static str, option: libc::c_int, arg2: libc::c_ulong) -> Result<(), String> {
    let rc = unsafe { libc::prctl(option, arg2, 0, 0, 0) };
    if rc == 0 {
        return Ok(());
    }

    Err(format!(
        "{} failed: {}",
        name,
        std::io::Error::last_os_error()
    ))
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(raw) => matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "enabled" | "on"
        ),
        Err(_) => default,
    }
}
