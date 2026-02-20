#[cfg(not(target_os = "windows"))]
pub(super) const AGENT_CONFIG_CANDIDATES: [&str; 3] = [
    "/etc/eguard-agent/agent.conf",
    "./conf/agent.conf",
    "./agent.conf",
];

#[cfg(target_os = "windows")]
pub(super) const AGENT_CONFIG_CANDIDATES: [&str; 3] = [
    r"C:\ProgramData\eGuard\agent.conf",
    r".\conf\agent.conf",
    r".\agent.conf",
];

#[cfg(not(target_os = "windows"))]
pub(super) const BOOTSTRAP_CONFIG_CANDIDATES: [&str; 3] = [
    "/etc/eguard-agent/bootstrap.conf",
    "./conf/bootstrap.conf",
    "./bootstrap.conf",
];

#[cfg(target_os = "windows")]
pub(super) const BOOTSTRAP_CONFIG_CANDIDATES: [&str; 3] = [
    r"C:\ProgramData\eGuard\bootstrap.conf",
    r".\conf\bootstrap.conf",
    r".\bootstrap.conf",
];

pub(super) const DEFAULT_SERVER_ADDR: &str = "eguard-server:50052";
pub(super) const ENCRYPTED_CONFIG_PREFIX: &str = "eguardcfg:v1:";
pub(super) const ENCRYPTED_CONFIG_AAD: &[u8] = b"eguard-agent-config-v1";
pub(super) const MACHINE_ID_PATH_ENV: &str = "EGUARD_MACHINE_ID_PATH";
pub(super) const TPM2_MATERIAL_ENV: &str = "EGUARD_CONFIG_TPM2_SEAL";
