use std::fmt;

pub(super) const EVENT_HEADER_SIZE: usize = 1 + 4 + 4 + 4 + 8;

#[cfg(any(test, feature = "ebpf-libbpf"))]
pub(super) const FALLBACK_LAST_EVENT_DATA_SIZE: usize = 512;

#[cfg(any(test, feature = "ebpf-libbpf"))]
pub(super) const FALLBACK_DROPPED_OFFSET: usize =
    std::mem::size_of::<u32>() + FALLBACK_LAST_EVENT_DATA_SIZE;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EbpfStats {
    pub events_received: u64,
    pub events_dropped: u64,
    pub parse_errors: u64,
    /// Per-probe event counters (event_type → count).
    pub per_probe_events: std::collections::HashMap<String, u64>,
    /// Per-probe error counters (event_type → error_count).
    pub per_probe_errors: std::collections::HashMap<String, u64>,
    /// List of probes that failed to attach (graceful degradation).
    pub failed_probes: Vec<String>,
    /// Number of BPF programs successfully attached in the kernel.
    pub attached_program_count: usize,
    /// Names of BPF programs successfully attached.
    pub attached_program_names: Vec<String>,
    /// Kernel version string (for capability reporting).
    pub kernel_version: String,
    /// Whether BTF (BPF Type Format) is available.
    pub btf_available: bool,
    /// Whether LSM BPF is available.
    pub lsm_available: bool,
}

#[derive(Debug)]
pub enum EbpfError {
    FeatureDisabled(&'static str),
    Backend(String),
    Parse(String),
}

impl fmt::Display for EbpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FeatureDisabled(feature) => {
                write!(f, "feature '{}' is disabled in this build", feature)
            }
            Self::Backend(msg) => write!(f, "eBPF backend error: {}", msg),
            Self::Parse(msg) => write!(f, "eBPF parse error: {}", msg),
        }
    }
}

impl std::error::Error for EbpfError {}

pub type Result<T> = std::result::Result<T, EbpfError>;

#[derive(Debug, Default)]
pub struct PollBatch {
    pub records: Vec<Vec<u8>>,
    pub dropped: u64,
}
