use std::collections::VecDeque;

use super::*;

#[derive(Default)]
struct InMemoryRingBufferBackend {
    queue: VecDeque<Vec<u8>>,
}

impl InMemoryRingBufferBackend {
    fn push_event(&mut self, event: Vec<u8>) {
        self.queue.push_back(event);
    }
}

impl RingBufferBackend for InMemoryRingBufferBackend {
    fn poll_raw_events(&mut self, _timeout: Duration) -> Result<PollBatch> {
        let records: Vec<Vec<u8>> = self.queue.drain(..).collect();
        Ok(PollBatch {
            records,
            dropped: 0,
        })
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

#[test]
// AC-EBP-020 AC-EBP-021 AC-EBP-030
fn parses_valid_raw_event() {
    let event = parse_raw_event(&encode_event(1, 4242, 1000, 99, b"/usr/bin/bash"))
        .expect("parse raw event");

    assert!(matches!(event.event_type, EventType::ProcessExec));
    assert_eq!(event.pid, 4242);
    assert_eq!(event.uid, 1000);
    assert_eq!(event.ts_ns, 99);
    assert_eq!(event.payload, "/usr/bin/bash");
}

#[test]
// AC-EBP-015 AC-EBP-131
fn poll_updates_parser_stats() {
    let mut backend = InMemoryRingBufferBackend::default();
    backend.push_event(encode_event(2, 7, 8, 9, b"/tmp/x"));
    backend.push_event(vec![1, 2, 3]);

    let mut engine = EbpfEngine {
        backend: Box::new(backend),
        stats: EbpfStats::default(),
    };
    let events = engine.poll_once(Duration::from_millis(10)).expect("poll");

    assert_eq!(events.len(), 1);
    assert!(matches!(events[0].event_type, EventType::FileOpen));

    let stats = engine.stats();
    assert_eq!(stats.events_received, 2);
    assert_eq!(stats.parse_errors, 1);
}

#[test]
// AC-EBP-130
fn poll_preserves_backend_record_order_for_timestamped_events() {
    let mut backend = InMemoryRingBufferBackend::default();
    backend.push_event(encode_event(1, 7, 8, 100, b"/usr/bin/bash"));
    backend.push_event(encode_event(2, 7, 8, 101, b"/tmp/x"));

    let mut engine = EbpfEngine {
        backend: Box::new(backend),
        stats: EbpfStats::default(),
    };

    let events = engine.poll_once(Duration::from_millis(10)).expect("poll");
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0].event_type, EventType::ProcessExec));
    assert_eq!(events[0].ts_ns, 100);
    assert!(matches!(events[1].event_type, EventType::FileOpen));
    assert_eq!(events[1].ts_ns, 101);
}

#[test]
// AC-EBP-003 AC-EBP-030
fn parses_structured_file_open_payload() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0x1234u32.to_le_bytes());
    payload.extend_from_slice(&0o755u32.to_le_bytes());
    payload.extend_from_slice(b"/tmp/dropper.sh\0");

    let event = parse_raw_event(&encode_event(2, 400, 1000, 88, &payload)).expect("parse event");
    assert!(matches!(event.event_type, EventType::FileOpen));
    assert!(event.payload.contains("path=/tmp/dropper.sh"));
    assert!(event.payload.contains("flags=4660"));
    assert!(event.payload.contains("mode=493"));
}

#[test]
// AC-EBP-120 AC-EBP-121 AC-EBP-122
fn parses_structured_lsm_block_payload() {
    let mut payload = Vec::new();
    payload.push(1);
    payload.extend_from_slice(&[0, 0, 0]);
    payload.extend_from_slice(b"/tmp/eguard-malware-test-marker\0");

    let event = parse_raw_event(&encode_event(6, 77, 0, 123, &payload)).expect("parse lsm event");
    assert!(matches!(event.event_type, EventType::LsmBlock));
    assert!(event.payload.contains("reason=1"));
    assert!(event
        .payload
        .contains("subject=/tmp/eguard-malware-test-marker"));
}

#[test]
// AC-EBP-002 AC-EBP-030
fn parses_structured_process_exec_payload() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&321u32.to_le_bytes());
    payload.extend_from_slice(&777u64.to_le_bytes());

    let mut comm = [0u8; 32];
    comm[..5].copy_from_slice(b"bash\0");
    payload.extend_from_slice(&comm);

    let mut filename = [0u8; 160];
    filename[..14].copy_from_slice(b"/usr/bin/bash\0");
    payload.extend_from_slice(&filename);

    let mut argv = [0u8; 160];
    argv[..16].copy_from_slice(b"bash -lc whoami\0");
    payload.extend_from_slice(&argv);

    let event = parse_raw_event(&encode_event(1, 900, 1000, 22, &payload)).expect("parse process");
    assert!(matches!(event.event_type, EventType::ProcessExec));
    assert!(event.payload.contains("ppid=321"));
    assert!(event.payload.contains("cgroup_id=777"));
    assert!(event.payload.contains("comm=bash"));
    assert!(event.payload.contains("path=/usr/bin/bash"));
    assert!(event.payload.contains("cmdline=bash -lc whoami"));
}

#[test]
// AC-EBP-004 AC-EBP-030
fn parses_structured_tcp_connect_payload() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&2u16.to_le_bytes());
    payload.extend_from_slice(&12345u16.to_le_bytes());
    payload.extend_from_slice(&4444u16.to_le_bytes());
    payload.push(6u8);
    payload.push(0u8);
    payload.extend_from_slice(&0x0A000001u32.to_le_bytes());
    payload.extend_from_slice(&0xC0A8012Au32.to_le_bytes());
    payload.extend_from_slice(&[0u8; 16]);
    payload.extend_from_slice(&[0u8; 16]);

    let event = parse_raw_event(&encode_event(3, 901, 1001, 23, &payload)).expect("parse tcp");
    assert!(matches!(event.event_type, EventType::TcpConnect));
    assert!(event.payload.contains("family=2"));
    assert!(event.payload.contains("protocol=6"));
    assert!(event.payload.contains("src_ip=10.0.0.1"));
    assert!(event.payload.contains("dst_ip=192.168.1.42"));
    assert!(event.payload.contains("dst_port=4444"));
}

#[test]
// AC-EBP-004 AC-EBP-030
fn parses_structured_tcp_connect_payload_ipv6() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&10u16.to_le_bytes());
    payload.extend_from_slice(&12345u16.to_le_bytes());
    payload.extend_from_slice(&4444u16.to_le_bytes());
    payload.push(6u8);
    payload.push(0u8);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());

    let src = std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).octets();
    let dst = std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2).octets();
    payload.extend_from_slice(&src);
    payload.extend_from_slice(&dst);

    let event = parse_raw_event(&encode_event(3, 901, 1001, 23, &payload)).expect("parse tcp");
    assert!(matches!(event.event_type, EventType::TcpConnect));
    assert!(event.payload.contains("family=10"));
    assert!(event.payload.contains("src_ip=2001:db8::1"));
    assert!(event.payload.contains("dst_ip=2001:db8::2"));
    assert!(event.payload.contains("dst_port=4444"));
}

#[test]
// AC-EBP-006 AC-EBP-007 AC-EBP-030
fn parses_structured_dns_and_module_payloads() {
    let mut dns = Vec::new();
    dns.extend_from_slice(&1u16.to_le_bytes());
    dns.extend_from_slice(&1u16.to_le_bytes());
    dns.extend_from_slice(b"c2.bad.example\0");

    let dns_event = parse_raw_event(&encode_event(4, 902, 1002, 24, &dns)).expect("dns");
    assert!(matches!(dns_event.event_type, EventType::DnsQuery));
    assert!(dns_event.payload.contains("qname=c2.bad.example"));
    assert!(dns_event.payload.contains("qtype=1"));

    let module_event =
        parse_raw_event(&encode_event(5, 903, 1003, 25, b"kernel_rootkit\0")).expect("module");
    assert!(matches!(module_event.event_type, EventType::ModuleLoad));
    assert!(module_event.payload.contains("module=kernel_rootkit"));
}

#[test]
// AC-EBP-015 AC-EBP-131
fn parses_fallback_drop_counter_from_bss_buffer() {
    let mut raw = vec![0u8; FALLBACK_DROPPED_OFFSET + std::mem::size_of::<u64>()];
    raw[FALLBACK_DROPPED_OFFSET..FALLBACK_DROPPED_OFFSET + std::mem::size_of::<u64>()]
        .copy_from_slice(&42u64.to_le_bytes());

    assert_eq!(parse_fallback_dropped_events(&raw), Some(42));
    assert_eq!(
        parse_fallback_dropped_events(&raw[..FALLBACK_DROPPED_OFFSET]),
        None
    );
}

#[test]
// AC-EBP-021
fn rejects_unknown_event_type() {
    let err = parse_raw_event(&encode_event(99, 1, 1, 1, b"x")).expect_err("parse error");
    assert!(matches!(err, EbpfError::Parse(_)));
}

#[test]
// AC-EBP-050
fn disabled_engine_poll_returns_no_events() {
    let mut engine = EbpfEngine::disabled();
    let events = engine
        .poll_once(Duration::from_millis(1))
        .expect("poll disabled backend");
    assert!(events.is_empty());
    assert_eq!(engine.stats(), EbpfStats::default());
}

#[test]
// AC-EBP-009
fn from_elf_requires_feature_flag_when_disabled() {
    let out = EbpfEngine::from_elf(Path::new("/tmp/nonexistent.o"), "events");
    assert!(matches!(
        out,
        Err(EbpfError::FeatureDisabled("ebpf-libbpf"))
    ));
}

#[test]
// AC-EBP-021
fn parse_event_type_maps_known_ids() {
    assert!(matches!(
        parse_event_type(1).expect("process"),
        EventType::ProcessExec
    ));
    assert!(matches!(
        parse_event_type(2).expect("file"),
        EventType::FileOpen
    ));
    assert!(matches!(
        parse_event_type(3).expect("tcp"),
        EventType::TcpConnect
    ));
    assert!(matches!(
        parse_event_type(4).expect("dns"),
        EventType::DnsQuery
    ));
}
