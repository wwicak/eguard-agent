mod backend;
mod capabilities;
mod codec;
mod engine;
mod replay;
mod replay_codec;
mod types;

#[cfg(feature = "ebpf-libbpf")]
mod libbpf_backend;

pub use engine::EbpfEngine;
pub use types::{EbpfError, EbpfStats};
#[allow(dead_code)]
pub type Result<T> = types::Result<T>;

#[allow(unused_imports)]
use backend::RingBufferBackend;
#[allow(unused_imports)]
use capabilities::{
    build_capability_report, detect_kernel_capabilities, kernel_supports, parse_kernel_version,
};
#[cfg(any(test, feature = "ebpf-libbpf"))]
#[allow(unused_imports)]
use codec::parse_fallback_dropped_events;
#[allow(unused_imports)]
use codec::{parse_event_type, parse_raw_event};
#[allow(unused_imports)]
use replay_codec::encode_replay_event;
#[allow(unused_imports)]
use types::{PollBatch, EVENT_HEADER_SIZE};
#[cfg(any(test, feature = "ebpf-libbpf"))]
#[allow(unused_imports)]
use types::{FALLBACK_DROPPED_OFFSET, FALLBACK_LAST_EVENT_DATA_SIZE};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_ring_contract;

#[cfg(test)]
mod tests_kernel_caps;
