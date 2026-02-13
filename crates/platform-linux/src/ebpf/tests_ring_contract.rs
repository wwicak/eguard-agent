use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;

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
    let common = std::fs::read_to_string(root.join("zig/ebpf/common.zig")).expect("read common");
    assert!(common.contains("pub const DEFAULT_RINGBUF_CAPACITY: u32 = 8 * 1024 * 1024;"));
    assert!(common.contains("pub const RINGBUF_CAPACITY: u32 = resolveRingbufCapacity();"));
    assert!(common.contains("@hasDecl(root, \"RINGBUF_CAPACITY\")"));
    assert!(common.contains("return DEFAULT_RINGBUF_CAPACITY;"));
    assert!(common.contains("pub export var events: MapDef"));
    assert!(common.contains(".max_entries = RINGBUF_CAPACITY"));

    for program in [
        "process_exec.zig",
        "file_open.zig",
        "tcp_connect.zig",
        "dns_query.zig",
        "module_load.zig",
        "lsm_block.zig",
    ] {
        let source = std::fs::read_to_string(root.join("zig/ebpf").join(program))
            .unwrap_or_else(|err| panic!("read {program}: {err}"));
        assert!(
            source.contains("@import(\"common.zig\")"),
            "{program} must use common"
        );
        assert!(
            source.contains("common.emitRecord"),
            "{program} must emit via common ring map"
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
// AC-EBP-005 AC-EBP-008 AC-RES-019
fn zig_programs_apply_kernel_side_filters_for_new_connections_and_file_open_scope() {
    let root = workspace_root();

    let tcp = std::fs::read_to_string(root.join("zig/ebpf/tcp_connect.zig"))
        .expect("read tcp_connect.zig");
    assert!(tcp.contains("pub export fn kprobe_tcp_v4_connect"));
    assert!(tcp.contains("_ = ctx;\n    return 0;"));
    assert!(tcp.contains("pub export fn kretprobe_tcp_v4_connect"));
    assert!(tcp.contains("return emitTcpConnect(ctx);"));
    assert!(tcp.contains("pub export fn kprobe_tcp_v6_connect"));
    assert!(tcp.contains("pub export fn kretprobe_tcp_v6_connect"));

    let file_open =
        std::fs::read_to_string(root.join("zig/ebpf/file_open.zig")).expect("read file_open.zig");
    assert!(file_open.contains("if (!shouldEmitFileOpen(ctx, event.path[0..]))"));
    assert!(file_open.contains("(ctx.mode & 0o111) != 0"));
    assert!(file_open.contains("hasPrefix(path, \"/etc/eguard-agent/\")"));
    assert!(file_open.contains("hasPrefix(path, \"/var/lib/eguard-agent/\")"));
    assert!(file_open.contains("hasPrefix(path, \"/opt/eguard-agent/\")"));
}
