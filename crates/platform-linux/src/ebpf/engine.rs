use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{EventType, RawEvent};

use super::backend::{NoopRingBufferBackend, RingBufferBackend};
use super::capabilities::{build_capability_report, detect_kernel_capabilities};
use super::codec::parse_raw_event;
use super::replay::ReplayBackend;
use super::types::{EbpfError, EbpfStats, Result, EVENT_HEADER_SIZE};

#[cfg(feature = "ebpf-libbpf")]
use super::libbpf_backend::LibbpfRingBufferBackend;

pub struct EbpfEngine {
    pub(super) backend: Box<dyn RingBufferBackend>,
    pub(super) stats: EbpfStats,
}

impl EbpfEngine {
    pub fn disabled() -> Self {
        let mut stats = EbpfStats::default();
        detect_kernel_capabilities(&mut stats);
        Self {
            backend: Box::<NoopRingBufferBackend>::default(),
            stats,
        }
    }

    #[cfg(feature = "ebpf-libbpf")]
    pub fn from_elf(elf_path: &Path, ring_buffer_map: &str) -> Result<Self> {
        let backend = LibbpfRingBufferBackend::new(elf_path.to_path_buf(), ring_buffer_map)?;
        let mut stats = EbpfStats::default();
        detect_kernel_capabilities(&mut stats);
        stats.failed_probes = backend.failed_probes();
        Ok(Self {
            backend: Box::new(backend),
            stats,
        })
    }

    #[cfg(feature = "ebpf-libbpf")]
    pub fn from_elfs(elf_paths: &[PathBuf], ring_buffer_map: &str) -> Result<Self> {
        let backend = LibbpfRingBufferBackend::new_many(elf_paths, ring_buffer_map)?;
        let mut stats = EbpfStats::default();
        detect_kernel_capabilities(&mut stats);
        stats.failed_probes = backend.failed_probes();
        Ok(Self {
            backend: Box::new(backend),
            stats,
        })
    }

    #[cfg(not(feature = "ebpf-libbpf"))]
    pub fn from_elf(_elf_path: &Path, _ring_buffer_map: &str) -> Result<Self> {
        Err(EbpfError::FeatureDisabled("ebpf-libbpf"))
    }

    #[cfg(not(feature = "ebpf-libbpf"))]
    pub fn from_elfs(_elf_paths: &[PathBuf], _ring_buffer_map: &str) -> Result<Self> {
        Err(EbpfError::FeatureDisabled("ebpf-libbpf"))
    }

    /// Create an engine that reads NDJSON events from a file or FIFO.
    ///
    /// Each line is a JSON object with fields matching the eBPF event schema.
    /// Useful for detection-pipeline testing without kernel hooks.
    pub fn from_replay(path: &Path) -> Result<Self> {
        let backend = ReplayBackend::open(path)?;
        let mut stats = EbpfStats::default();
        detect_kernel_capabilities(&mut stats);
        Ok(Self {
            backend: Box::new(backend),
            stats,
        })
    }

    pub fn poll_once(&mut self, timeout: Duration) -> Result<Vec<RawEvent>> {
        let batch = self.backend.poll_raw_events(timeout)?;
        self.stats.events_dropped = self.stats.events_dropped.saturating_add(batch.dropped);

        let mut records = batch.records;
        let mut events = Vec::with_capacity(records.len());
        for record in &records {
            self.stats.events_received = self.stats.events_received.saturating_add(1);
            match parse_raw_event(record) {
                Ok(event) => {
                    // Track per-probe event counts
                    let probe_name = match event.event_type {
                        EventType::ProcessExec => "process_exec",
                        EventType::ProcessExit => "process_exit",
                        EventType::FileOpen => "file_open",
                        EventType::FileWrite => "file_write",
                        EventType::FileRename => "file_rename",
                        EventType::FileUnlink => "file_unlink",
                        EventType::TcpConnect => "tcp_connect",
                        EventType::DnsQuery => "dns_query",
                        EventType::ModuleLoad => "module_load",
                        EventType::LsmBlock => "lsm_block",
                    };
                    *self
                        .stats
                        .per_probe_events
                        .entry(probe_name.to_string())
                        .or_insert(0) += 1;
                    events.push(event);
                }
                Err(_e) => {
                    self.stats.parse_errors = self.stats.parse_errors.saturating_add(1);
                    // Track which probe type failed if we can determine it
                    if record.len() >= EVENT_HEADER_SIZE {
                        let probe_name = match record[0] {
                            1 => "process_exec",
                            2 => "file_open",
                            3 => "tcp_connect",
                            4 => "dns_query",
                            5 => "module_load",
                            6 => "lsm_block",
                            7 => "process_exit",
                            8 => "file_write",
                            9 => "file_rename",
                            10 => "file_unlink",
                            _ => "unknown",
                        };
                        *self
                            .stats
                            .per_probe_errors
                            .entry(probe_name.to_string())
                            .or_insert(0) += 1;
                    }
                }
            }
        }

        self.backend
            .reclaim_raw_records(std::mem::take(&mut records));
        Ok(events)
    }

    pub fn poll_and_forward(
        &mut self,
        timeout: Duration,
        sender: &std::sync::mpsc::Sender<RawEvent>,
    ) -> Result<usize> {
        let events = self.poll_once(timeout)?;
        let mut forwarded = 0usize;
        for event in events {
            sender
                .send(event)
                .map_err(|_| EbpfError::Backend("event channel closed".to_string()))?;
            forwarded += 1;
        }
        Ok(forwarded)
    }

    pub fn stats(&self) -> EbpfStats {
        self.stats.clone()
    }

    pub fn capability_report(&self) -> std::collections::HashMap<String, String> {
        build_capability_report(&self.stats)
    }
}
