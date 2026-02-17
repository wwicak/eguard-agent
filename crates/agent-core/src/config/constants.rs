pub(super) const AGENT_CONFIG_CANDIDATES: [&str; 3] = [
    "/etc/eguard-agent/agent.conf",
    "./conf/agent.conf",
    "./agent.conf",
];

pub(super) const BOOTSTRAP_CONFIG_CANDIDATES: [&str; 3] = [
    "/etc/eguard-agent/bootstrap.conf",
    "./conf/bootstrap.conf",
    "./bootstrap.conf",
];

pub(super) const DEFAULT_SERVER_ADDR: &str = "eguard-server:50052";
pub(super) const ENCRYPTED_CONFIG_PREFIX: &str = "eguardcfg:v1:";
pub(super) const ENCRYPTED_CONFIG_AAD: &[u8] = b"eguard-agent-config-v1";
pub(super) const MACHINE_ID_PATH_ENV: &str = "EGUARD_MACHINE_ID_PATH";
pub(super) const TPM2_MATERIAL_ENV: &str = "EGUARD_CONFIG_TPM2_SEAL";
