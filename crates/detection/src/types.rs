use serde::{Deserialize, Serialize};

pub(crate) const EVENT_CLASSES: [EventClass; 8] = [
    EventClass::ProcessExec,
    EventClass::ProcessExit,
    EventClass::FileOpen,
    EventClass::NetworkConnect,
    EventClass::DnsQuery,
    EventClass::ModuleLoad,
    EventClass::Login,
    EventClass::Alert,
];
pub(crate) const EVENT_CLASS_COUNT: usize = EVENT_CLASSES.len();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventClass {
    ProcessExec,
    ProcessExit,
    FileOpen,
    NetworkConnect,
    DnsQuery,
    ModuleLoad,
    Login,
    Alert,
}

impl EventClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::ProcessExit => "process_exit",
            Self::FileOpen => "file_open",
            Self::NetworkConnect => "network_connect",
            Self::DnsQuery => "dns_query",
            Self::ModuleLoad => "module_load",
            Self::Login => "login",
            Self::Alert => "alert",
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::ProcessExec => 0,
            Self::ProcessExit => 1,
            Self::FileOpen => 2,
            Self::NetworkConnect => 3,
            Self::DnsQuery => 4,
            Self::ModuleLoad => 5,
            Self::Login => 6,
            Self::Alert => 7,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub ts_unix: i64,
    pub event_class: EventClass,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub process: String,
    pub parent_process: String,
    /// Top-level ancestor (session-like) PID for correlation.
    pub session_id: u32,
    pub file_path: Option<String>,
    pub file_write: bool,
    pub file_hash: Option<String>,
    pub dst_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_domain: Option<String>,
    pub command_line: Option<String>,
    pub event_size: Option<u64>,
    pub container_runtime: Option<String>,
    pub container_id: Option<String>,
    pub container_escape: bool,
    pub container_privileged: bool,
}

impl TelemetryEvent {
    pub fn entity_key(&self) -> String {
        self.session_id.to_string()
    }

    pub fn process_key(&self) -> String {
        format!("{}:{}", self.process, self.parent_process)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    None,
    Low,
    Medium,
    High,
    VeryHigh,
    Definite,
}

impl PartialOrd for Confidence {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Confidence {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.numeric().cmp(&other.numeric())
    }
}

impl Confidence {
    /// Numeric severity level for ordering (0=None, 5=Definite).
    pub fn numeric(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::VeryHigh => 4,
            Self::Definite => 5,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectionSignals {
    pub z1_exact_ioc: bool,
    pub yara_hit: bool,
    pub z2_temporal: bool,
    pub z3_anomaly_high: bool,
    pub z3_anomaly_med: bool,
    pub z4_kill_chain: bool,
    pub l1_prefilter_hit: bool,
    pub exploit_indicator: bool,
    pub kernel_integrity: bool,
    pub tamper_indicator: bool,
    pub c2_beaconing_detected: bool,
    pub process_tree_anomaly: bool,
}
