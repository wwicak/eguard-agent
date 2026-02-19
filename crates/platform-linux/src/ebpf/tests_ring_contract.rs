use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::{EventType, RawEvent};

#[derive(Default)]
struct QueueRingBufferBackend {
    queue: VecDeque<Vec<u8>>,
}

impl QueueRingBufferBackend {
    fn push_event(&mut self, event: Vec<u8>) {
        self.queue.push_back(event);
    }
}

impl RingBufferBackend for QueueRingBufferBackend {
    fn poll_raw_events(&mut self, _timeout: Duration) -> Result<PollBatch> {
        let records = self.queue.drain(..).collect();
        Ok(PollBatch {
            records,
            dropped: 0,
        })
    }
}

#[derive(Default)]
struct PollObservation {
    calls: usize,
    seen_timeouts: Vec<Duration>,
}

#[derive(Default)]
struct RecycleObservation {
    reclaimed_records: usize,
    reclaimed_bytes: usize,
}

struct RecyclingBackend {
    queue: VecDeque<Vec<u8>>,
    observation: Arc<Mutex<RecycleObservation>>,
}

impl RecyclingBackend {
    fn new(observation: Arc<Mutex<RecycleObservation>>) -> Self {
        Self {
            queue: VecDeque::new(),
            observation,
        }
    }
}

impl RingBufferBackend for RecyclingBackend {
    fn poll_raw_events(&mut self, _timeout: Duration) -> Result<PollBatch> {
        let records = self.queue.drain(..).collect();
        Ok(PollBatch {
            records,
            dropped: 0,
        })
    }

    fn reclaim_raw_records(&mut self, records: Vec<Vec<u8>>) {
        let mut guard = self.observation.lock().expect("recycle observation");
        guard.reclaimed_records = guard.reclaimed_records.saturating_add(records.len());
        guard.reclaimed_bytes = guard
            .reclaimed_bytes
            .saturating_add(records.iter().map(|r| r.len()).sum::<usize>());
    }
}

#[derive(Clone)]
struct ObservedPollBackend {
    state: Arc<Mutex<PollObservation>>,
}

impl ObservedPollBackend {
    fn new(state: Arc<Mutex<PollObservation>>) -> Self {
        Self { state }
    }
}

impl RingBufferBackend for ObservedPollBackend {
    fn poll_raw_events(&mut self, timeout: Duration) -> Result<PollBatch> {
        let mut guard = self.state.lock().expect("lock observation");
        guard.calls += 1;
        guard.seen_timeouts.push(timeout);
        Ok(PollBatch::default())
    }
}

fn encode_event(event_type: u8, pid: u32, uid: u32, ts_ns: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(EVENT_HEADER_SIZE + payload.len());
    out.push(event_type);
    out.extend_from_slice(&pid.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&uid.to_le_bytes());
    out.extend_from_slice(&ts_ns.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
// AC-EBP-010 AC-EBP-011 AC-EBP-101
fn zig_ebpf_programs_share_single_default_8mb_ring_buffer_definition() {
    let root = workspace_root();
    let helpers =
        std::fs::read_to_string(root.join("zig/ebpf/bpf_helpers.h")).expect("read bpf_helpers.h");
    assert!(helpers.contains("#define BPF_MAP_TYPE_RINGBUF 27"));
    assert!(helpers.contains("FALLBACK_LAST_EVENT_DATA_SIZE 512"));
    assert!(helpers.contains("struct event_hdr"));
    assert!(helpers.contains("struct fallback_ringbuf_state"));

    for program in [
        "process_exec.c",
        "file_open.c",
        "file_write.c",
        "file_rename.c",
        "file_unlink.c",
        "tcp_connect.c",
        "dns_query.c",
        "module_load.c",
        "lsm_block.c",
    ] {
        let source = std::fs::read_to_string(root.join("zig/ebpf").join(program))
            .unwrap_or_else(|err| panic!("read {program}: {err}"));
        assert!(
            source.contains("#include \"bpf_helpers.h\""),
            "{program} must include bpf_helpers.h"
        );
        assert!(
            source.contains("bpf_ringbuf_reserve"),
            "{program} must reserve ring buffer"
        );
        assert!(
            !source.contains("pub export var events"),
            "{program} must not define a separate ring buffer map"
        );
    }
}

#[test]
// AC-EBP-012 AC-RES-020
fn rust_ebpf_backend_uses_libbpf_ringbuffer_poll_path_without_read_syscall_api() {
    let source =
        std::fs::read_to_string(workspace_root().join("crates/platform-linux/src/ebpf.rs"))
            .expect("read ebpf backend source");

    assert!(source.contains("libbpf_rs::RingBuffer"));
    assert!(source.contains(".poll(timeout)"));
    assert!(!source.contains("libc::read("));
    assert!(!source.contains("nix::unistd::read("));
    assert!(!source.contains("std::io::Read"));
}

#[test]
// AC-EBP-013
fn poll_and_forward_sends_polled_events_to_mpsc_sender() {
    let mut backend = QueueRingBufferBackend::default();
    backend.push_event(encode_event(1, 4242, 1000, 55, b"/usr/bin/bash"));
    backend.push_event(encode_event(2, 4242, 1000, 56, b"/tmp/file"));

    let mut engine = EbpfEngine {
        backend: Box::new(backend),
        stats: EbpfStats::default(),
    };

    let (tx, rx) = std::sync::mpsc::channel();
    let forwarded = engine
        .poll_and_forward(Duration::from_millis(10), &tx)
        .expect("forward events");
    assert_eq!(forwarded, 2);

    let first = rx.recv_timeout(Duration::from_millis(20)).expect("first");
    let second = rx.recv_timeout(Duration::from_millis(20)).expect("second");

    assert!(matches!(first.event_type, EventType::ProcessExec));
    assert!(matches!(second.event_type, EventType::FileOpen));
}

#[test]
// AC-EBP-013
fn poll_and_forward_returns_error_when_receiver_is_closed() {
    let mut backend = QueueRingBufferBackend::default();
    backend.push_event(encode_event(1, 7, 8, 9, b"/usr/bin/bash"));

    let mut engine = EbpfEngine {
        backend: Box::new(backend),
        stats: EbpfStats::default(),
    };

    let (tx, rx) = std::sync::mpsc::channel::<RawEvent>();
    drop(rx);
    let err = engine
        .poll_and_forward(Duration::from_millis(10), &tx)
        .expect_err("closed channel must fail");
    assert!(matches!(err, EbpfError::Backend(_)));
}

#[test]
// AC-EBP-014
fn poll_once_uses_single_blocking_backend_poll_invocation_per_call() {
    let observation = Arc::new(Mutex::new(PollObservation::default()));
    let mut engine = EbpfEngine {
        backend: Box::new(ObservedPollBackend::new(observation.clone())),
        stats: EbpfStats::default(),
    };

    let timeout = Duration::from_millis(37);
    let events = engine.poll_once(timeout).expect("poll");
    assert!(events.is_empty());

    let guard = observation.lock().expect("lock observation");
    assert_eq!(guard.calls, 1);
    assert_eq!(guard.seen_timeouts, vec![timeout]);
}

#[test]
// AC-EBP-015
fn poll_once_reclaims_raw_record_buffers_for_backend_pooling() {
    let observation = Arc::new(Mutex::new(RecycleObservation::default()));
    let mut backend = RecyclingBackend::new(observation.clone());
    backend
        .queue
        .push_back(encode_event(1, 4242, 1000, 55, b"/usr/bin/bash"));
    backend
        .queue
        .push_back(encode_event(2, 4242, 1000, 56, b"/tmp/file"));

    let mut engine = EbpfEngine {
        backend: Box::new(backend),
        stats: EbpfStats::default(),
    };

    let events = engine
        .poll_once(Duration::from_millis(10))
        .expect("poll once with recycling");
    assert_eq!(events.len(), 2);

    let guard = observation.lock().expect("recycle observation");
    assert_eq!(guard.reclaimed_records, 2);
    assert!(guard.reclaimed_bytes > 0);
}

#[test]
// AC-EBP-005 AC-EBP-008 AC-RES-019
fn zig_programs_apply_kernel_side_filters_for_new_connections_and_file_open_scope() {
    let root = workspace_root();

    let tcp =
        std::fs::read_to_string(root.join("zig/ebpf/tcp_connect.c")).expect("read tcp_connect.c");
    assert!(tcp.contains("tracepoint/sock/inet_sock_set_state"));
    assert!(tcp.contains("TCP_SYN_SENT"));
    assert!(tcp.contains("TCP_ESTABLISHED"));

    let file_open =
        std::fs::read_to_string(root.join("zig/ebpf/file_open.c")).expect("read file_open.c");
    assert!(file_open.contains("tracepoint/syscalls/sys_enter_openat"));
    assert!(file_open.contains("FILE_PATH_SZ"));
}

#[test]
// AC-EBP-190 AC-EBP-191 AC-EBP-192
fn ebpf_file_event_sources_include_write_rename_unlink_probes() {
    let root = workspace_root();

    let write =
        std::fs::read_to_string(root.join("zig/ebpf/file_write.c")).expect("read file_write.c");
    assert!(write.contains("tracepoint/syscalls/sys_enter_write"));
    assert!(write.contains("EVENT_FILE_WRITE"));

    let rename =
        std::fs::read_to_string(root.join("zig/ebpf/file_rename.c")).expect("read file_rename.c");
    assert!(rename.contains("tracepoint/syscalls/sys_enter_renameat2"));
    assert!(rename.contains("EVENT_FILE_RENAME"));

    let unlink =
        std::fs::read_to_string(root.join("zig/ebpf/file_unlink.c")).expect("read file_unlink.c");
    assert!(unlink.contains("tracepoint/syscalls/sys_enter_unlinkat"));
    assert!(unlink.contains("EVENT_FILE_UNLINK"));
}
