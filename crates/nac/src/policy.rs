use serde::{Deserialize, Serialize};

pub const LEARNING_PERIOD_SECS: u64 = 7 * 24 * 60 * 60;
pub const DEFAULT_DEAD_HEARTBEAT_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Posture {
    Compliant,
    NonCompliant,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlanAssignment {
    Registration,
    AgentLearning,
    Production,
    Restricted,
    Quarantine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallTarget {
    LinuxDeb,
    LinuxRpm,
    WindowsExe,
    MacosPkg,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptivePortalInstall {
    pub target: InstallTarget,
    pub install_endpoint: &'static str,
    pub enrollment_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessContext {
    pub agent_installed: bool,
    pub enrollment_complete: bool,
    pub first_heartbeat_seen: bool,
    pub learning_started_unix: Option<u64>,
    pub now_unix: u64,
    pub compliance: Posture,
    pub critical_alert_active: bool,
    pub last_heartbeat_unix: Option<u64>,
    pub dead_heartbeat_timeout_secs: u64,
}

impl Default for AccessContext {
    fn default() -> Self {
        Self {
            agent_installed: false,
            enrollment_complete: false,
            first_heartbeat_seen: false,
            learning_started_unix: None,
            now_unix: 0,
            compliance: Posture::Unknown,
            critical_alert_active: false,
            last_heartbeat_unix: None,
            dead_heartbeat_timeout_secs: DEFAULT_DEAD_HEARTBEAT_TIMEOUT_SECS,
        }
    }
}

pub fn posture_from_compliance(status: &str) -> Posture {
    match status {
        "pass" | "compliant" => Posture::Compliant,
        "fail" | "non_compliant" => Posture::NonCompliant,
        _ => Posture::Unknown,
    }
}

pub fn detect_install_target(user_agent: &str) -> InstallTarget {
    let ua = user_agent.to_ascii_lowercase();
    if ua.contains("windows") || ua.contains("win64") || ua.contains("wow64") {
        InstallTarget::WindowsExe
    } else if ua.contains("macintosh") || ua.contains("mac os x") || ua.contains("darwin") {
        InstallTarget::MacosPkg
    } else if ua.contains("ubuntu") || ua.contains("debian") {
        InstallTarget::LinuxDeb
    } else if ua.contains("fedora")
        || ua.contains("centos")
        || ua.contains("rhel")
        || ua.contains("rocky")
        || ua.contains("alma")
        || ua.contains("suse")
    {
        InstallTarget::LinuxRpm
    } else {
        InstallTarget::Unknown
    }
}

pub fn build_captive_portal_install(
    user_agent: &str,
    enrollment_token: &str,
) -> CaptivePortalInstall {
    let target = detect_install_target(user_agent);
    let install_endpoint = match target {
        InstallTarget::LinuxDeb => "/api/v1/agent-install/linux-deb",
        InstallTarget::LinuxRpm => "/api/v1/agent-install/linux-rpm",
        InstallTarget::WindowsExe => "/api/v1/agent-install/windows-exe",
        InstallTarget::MacosPkg => "/api/v1/agent-install/macos",
        InstallTarget::Unknown => "/api/v1/agent-install",
    };

    CaptivePortalInstall {
        target,
        install_endpoint,
        enrollment_token: enrollment_token.to_string(),
    }
}

pub fn assign_vlan(ctx: &AccessContext) -> VlanAssignment {
    if !ctx.agent_installed {
        return VlanAssignment::Registration;
    }

    if ctx.critical_alert_active || is_agent_dead(ctx) {
        return VlanAssignment::Quarantine;
    }

    if !ctx.enrollment_complete || !ctx.first_heartbeat_seen {
        return VlanAssignment::Registration;
    }

    if !learning_complete(ctx) {
        return VlanAssignment::AgentLearning;
    }

    match ctx.compliance {
        Posture::Compliant => VlanAssignment::Production,
        Posture::NonCompliant | Posture::Unknown => VlanAssignment::Restricted,
    }
}

fn learning_complete(ctx: &AccessContext) -> bool {
    let Some(started) = ctx.learning_started_unix else {
        return false;
    };
    ctx.now_unix.saturating_sub(started) >= LEARNING_PERIOD_SECS
}

fn is_agent_dead(ctx: &AccessContext) -> bool {
    let Some(last_hb) = ctx.last_heartbeat_unix else {
        return false;
    };
    ctx.now_unix.saturating_sub(last_hb) > ctx.dead_heartbeat_timeout_secs
}
