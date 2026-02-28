//! ESF (Endpoint Security Framework) subsystem.
//!
//! Provides macOS telemetry collection via a backend stack:
//! - `eslogger --json` ingestion (primary on macOS)
//! - NDJSON replay backend (`EGUARD_ESF_REPLAY_PATH`)
//! - process polling fallback (macOS)
//!
//! This keeps the collector functional even when Endpoint Security entitlements
//! are unavailable during development environments.

use std::collections::VecDeque;
use std::fmt;
use std::io::BufRead;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "macos")]
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "macos")]
use std::sync::mpsc::{sync_channel, Receiver, TryRecvError, TrySendError};
#[cfg(target_os = "macos")]
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::thread::JoinHandle;
#[cfg(target_os = "macos")]
use std::time::Instant;

use serde_json::Value;

const REPLAY_PATH_ENV: &str = "EGUARD_ESF_REPLAY_PATH";

#[cfg(target_os = "macos")]
const ESLOGGER_BIN_ENV: &str = "EGUARD_ESLOGGER_BIN";
#[cfg(target_os = "macos")]
const ESLOGGER_ARGS_ENV: &str = "EGUARD_ESLOGGER_ARGS";
#[cfg(target_os = "macos")]
const ESLOGGER_DISABLE_ENV: &str = "EGUARD_ESLOGGER_DISABLE";
#[cfg(target_os = "macos")]
const PROCESS_POLL_INTERVAL_MS_ENV: &str = "EGUARD_ESF_PROCESS_POLL_INTERVAL_MS";

/// Core ESF telemetry engine, analogous to `EbpfEngine` on Linux.
pub struct EsfEngine {
    enabled: bool,
    backend: EsfBackend,
    stats: EsfStats,
}

impl EsfEngine {
    /// Create a new ESF engine (not yet started).
    pub fn new() -> Self {
        Self {
            enabled: false,
            backend: EsfBackend::Disabled,
            stats: EsfStats::default(),
        }
    }

    /// Start telemetry collection and select the best available backend.
    pub fn start(&mut self) -> Result<(), EsfError> {
        if self.enabled {
            return Ok(());
        }

        if let Some(path) = replay_path_from_env() {
            let replay = ReplayBackend::open(&path)?;
            self.backend = EsfBackend::Replay(replay);
            self.enabled = true;
            tracing::info!(path = %path.display(), "ESF replay backend started");
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            if !env_enabled(ESLOGGER_DISABLE_ENV, false) {
                match EsloggerBackend::start() {
                    Ok(eslogger) => {
                        self.backend = EsfBackend::Eslogger(eslogger);
                        self.enabled = true;
                        tracing::info!("ESF eslogger backend started");
                        return Ok(());
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "failed starting eslogger backend, falling back to process polling");
                    }
                }
            }

            self.backend = EsfBackend::ProcessPoll(ProcessPollBackend::new());
            self.enabled = true;
            tracing::info!("ESF process-poll fallback started");
            return Ok(());
        }

        #[cfg(not(target_os = "macos"))]
        {
            // Non-macOS builds keep the API operable for tests and cross-target checks.
            self.backend = EsfBackend::Disabled;
            self.enabled = true;
            Ok(())
        }
    }

    /// Stop telemetry collection and release resources.
    pub fn stop(&mut self) -> Result<(), EsfError> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            if let EsfBackend::Eslogger(eslogger) = &mut self.backend {
                eslogger.stop()?;
            }
        }

        self.backend = EsfBackend::Disabled;
        self.enabled = false;
        Ok(())
    }

    /// Whether the ESF subsystem is currently active.
    pub fn is_active(&self) -> bool {
        self.enabled
    }

    /// Poll decoded ESF events.
    pub fn poll_events(&mut self, max_batch: usize) -> Result<Vec<super::RawEvent>, EsfError> {
        if !self.enabled || max_batch == 0 {
            return Ok(Vec::new());
        }

        let outcome = match &mut self.backend {
            EsfBackend::Replay(replay) => replay.poll(max_batch)?,
            #[cfg(target_os = "macos")]
            EsfBackend::Eslogger(eslogger) => eslogger.poll(max_batch)?,
            #[cfg(target_os = "macos")]
            EsfBackend::ProcessPoll(poller) => poller.poll(max_batch)?,
            EsfBackend::Disabled => PollOutcome::default(),
        };

        self.stats.events_received = self
            .stats
            .events_received
            .saturating_add(outcome.events.len() as u64);
        self.stats.events_dropped = self.stats.events_dropped.saturating_add(outcome.dropped);

        Ok(outcome.events)
    }

    /// Collect current statistics.
    pub fn stats(&self) -> EsfStats {
        self.stats.clone()
    }
}

impl Default for EsfEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
struct PollOutcome {
    events: Vec<super::RawEvent>,
    dropped: u64,
}

enum EsfBackend {
    Replay(ReplayBackend),
    #[cfg(target_os = "macos")]
    Eslogger(EsloggerBackend),
    #[cfg(target_os = "macos")]
    ProcessPoll(ProcessPollBackend),
    Disabled,
}

struct ReplayBackend {
    reader: std::io::BufReader<std::fs::File>,
    pending: VecDeque<super::RawEvent>,
}

impl ReplayBackend {
    fn open(path: &Path) -> Result<Self, EsfError> {
        let file = std::fs::File::open(path).map_err(|err| {
            EsfError::NotAvailable(format!("open replay path {}: {err}", path.display()))
        })?;

        Ok(Self {
            reader: std::io::BufReader::new(file),
            pending: VecDeque::new(),
        })
    }

    fn poll(&mut self, max_batch: usize) -> Result<PollOutcome, EsfError> {
        let mut dropped = 0u64;

        while self.pending.len() < max_batch {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }

                    match parse_event_line(trimmed) {
                        Some(event) => self.pending.push_back(event),
                        None => {
                            dropped = dropped.saturating_add(1);
                            tracing::warn!(line = trimmed, "dropped invalid ESF replay line");
                        }
                    }
                }
                Err(err) => {
                    return Err(EsfError::NotAvailable(format!("read replay stream: {err}")));
                }
            }
        }

        let mut events = Vec::with_capacity(max_batch.min(self.pending.len()));
        while events.len() < max_batch {
            let Some(event) = self.pending.pop_front() else {
                break;
            };
            events.push(event);
        }

        Ok(PollOutcome { events, dropped })
    }
}

#[cfg(target_os = "macos")]
struct EsloggerBackend {
    child: Child,
    rx: Receiver<String>,
    reader_thread: Option<JoinHandle<()>>,
    dropped_lines: Arc<AtomicU64>,
    pending: VecDeque<super::RawEvent>,
}

#[cfg(target_os = "macos")]
impl EsloggerBackend {
    fn start() -> Result<Self, EsfError> {
        let binary = std::env::var(ESLOGGER_BIN_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "eslogger".to_string());

        let args = std::env::var(ESLOGGER_ARGS_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|raw| {
                raw.split_whitespace()
                    .map(|segment| segment.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["--json".to_string()]);

        let mut child = Command::new(&binary)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|err| {
                EsfError::NotAvailable(format!("spawn {binary} with args {:?}: {err}", args))
            })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            EsfError::NotAvailable("eslogger stdout pipe unavailable".to_string())
        })?;

        let (tx, rx) = sync_channel::<String>(4096);
        let dropped_lines = Arc::new(AtomicU64::new(0));
        let dropped_lines_clone = dropped_lines.clone();

        let reader_thread = std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        match tx.try_send(trimmed.to_string()) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                dropped_lines_clone.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySendError::Disconnected(_)) => break,
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            child,
            rx,
            reader_thread: Some(reader_thread),
            dropped_lines,
            pending: VecDeque::new(),
        })
    }

    fn poll(&mut self, max_batch: usize) -> Result<PollOutcome, EsfError> {
        let mut dropped = self.dropped_lines.swap(0, Ordering::Relaxed);

        while self.pending.len() < max_batch {
            match self.rx.try_recv() {
                Ok(line) => match parse_event_line(&line) {
                    Some(event) => self.pending.push_back(event),
                    None => dropped = dropped.saturating_add(1),
                },
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }

        let mut events = Vec::with_capacity(max_batch.min(self.pending.len()));
        while events.len() < max_batch {
            let Some(event) = self.pending.pop_front() else {
                break;
            };
            events.push(event);
        }

        Ok(PollOutcome { events, dropped })
    }

    fn stop(&mut self) -> Result<(), EsfError> {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        self.child
            .wait()
            .map_err(|err| EsfError::NotAvailable(format!("wait eslogger process: {err}")))?;

        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }

        Ok(())
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct ProcessSnapshot {
    uid: u32,
    cmdline: String,
}

#[cfg(target_os = "macos")]
struct ProcessPollBackend {
    known_processes: HashMap<u32, ProcessSnapshot>,
    seeded: bool,
    last_scan: Option<Instant>,
    scan_interval: Duration,
    pending: VecDeque<super::RawEvent>,
}

#[cfg(target_os = "macos")]
impl ProcessPollBackend {
    fn new() -> Self {
        let scan_interval = std::env::var(PROCESS_POLL_INTERVAL_MS_ENV)
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_millis(1_000));

        Self {
            known_processes: HashMap::new(),
            seeded: false,
            last_scan: None,
            scan_interval,
            pending: VecDeque::new(),
        }
    }

    fn poll(&mut self, max_batch: usize) -> Result<PollOutcome, EsfError> {
        if !self.pending.is_empty() {
            return Ok(self.drain_pending(max_batch, 0));
        }

        let now = Instant::now();
        if let Some(last_scan) = self.last_scan {
            if now.duration_since(last_scan) < self.scan_interval {
                return Ok(PollOutcome::default());
            }
        }
        self.last_scan = Some(now);

        let snapshot = collect_process_snapshot()?;

        if !self.seeded {
            self.known_processes = snapshot;
            self.seeded = true;
            return Ok(PollOutcome::default());
        }

        let ts_ns = unix_now_ns();

        for (pid, current) in &snapshot {
            if self.known_processes.contains_key(pid) {
                continue;
            }

            let payload = process_exec_payload(&current.cmdline);
            self.pending.push_back(super::RawEvent {
                event_type: super::EventType::ProcessExec,
                pid: *pid,
                uid: current.uid,
                ts_ns,
                payload,
            });
        }

        for (pid, previous) in &self.known_processes {
            if snapshot.contains_key(pid) {
                continue;
            }

            self.pending.push_back(super::RawEvent {
                event_type: super::EventType::ProcessExit,
                pid: *pid,
                uid: previous.uid,
                ts_ns,
                payload: format!("cmdline={}", sanitize_payload_value(&previous.cmdline)),
            });
        }

        self.known_processes = snapshot;
        Ok(self.drain_pending(max_batch, 0))
    }

    fn drain_pending(&mut self, max_batch: usize, dropped: u64) -> PollOutcome {
        let mut events = Vec::with_capacity(max_batch.min(self.pending.len()));
        while events.len() < max_batch {
            let Some(event) = self.pending.pop_front() else {
                break;
            };
            events.push(event);
        }

        PollOutcome { events, dropped }
    }
}

#[cfg(target_os = "macos")]
fn collect_process_snapshot() -> Result<HashMap<u32, ProcessSnapshot>, EsfError> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,uid=,command="])
        .output()
        .map_err(|err| EsfError::NotAvailable(format!("spawn ps: {err}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(EsfError::NotAvailable(format!(
            "ps exited with status {}: {}",
            output.status,
            stderr.trim()
        )));
    }

    let mut snapshot = HashMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut fields = trimmed.split_whitespace();
        let Some(pid_raw) = fields.next() else {
            continue;
        };
        let Some(uid_raw) = fields.next() else {
            continue;
        };

        let Ok(pid) = pid_raw.parse::<u32>() else {
            continue;
        };
        if pid == 0 {
            continue;
        }

        let uid = uid_raw.parse::<u32>().unwrap_or(0);
        let cmdline = fields.collect::<Vec<_>>().join(" ");

        snapshot.insert(pid, ProcessSnapshot { uid, cmdline });
    }

    Ok(snapshot)
}

#[cfg(target_os = "macos")]
fn process_exec_payload(cmdline: &str) -> String {
    let cmdline = sanitize_payload_value(cmdline);
    if cmdline.is_empty() {
        return String::new();
    }

    if let Some(exe) = cmdline.split_whitespace().next() {
        if !exe.is_empty() {
            return format!("path={};cmdline={}", sanitize_payload_value(exe), cmdline);
        }
    }

    format!("cmdline={cmdline}")
}

fn replay_path_from_env() -> Option<std::path::PathBuf> {
    std::env::var(REPLAY_PATH_ENV)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(std::path::PathBuf::from)
}

#[cfg(target_os = "macos")]
fn env_enabled(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on" | "enabled"
            )
        })
        .unwrap_or(default)
}

fn parse_event_line(raw_line: &str) -> Option<super::RawEvent> {
    if let Ok(event) = serde_json::from_str::<super::RawEvent>(raw_line) {
        return Some(event);
    }

    let value = serde_json::from_str::<Value>(raw_line).ok()?;
    decode_event_value(&value)
}

fn decode_event_value(value: &Value) -> Option<super::RawEvent> {
    let event_type = decode_event_type(value)?;
    let pid = decode_pid(value).unwrap_or(0);
    let uid = decode_uid(value).unwrap_or(0);
    let ts_ns = decode_timestamp_ns(value).unwrap_or_else(unix_now_ns);
    let payload = decode_payload(&event_type, value);

    Some(super::RawEvent {
        event_type,
        pid,
        uid,
        ts_ns,
        payload,
    })
}

fn decode_event_type(value: &Value) -> Option<super::EventType> {
    let candidates = [
        lookup_string_path(value, &["event_type"]),
        lookup_string_path(value, &["event", "event_type"]),
        lookup_string_path(value, &["event", "es_event_type"]),
        lookup_string_path(value, &["event", "type"]),
        lookup_string_path(value, &["type"]),
        lookup_string_path(value, &["action"]),
        lookup_string_path(value, &["event_name"]),
        find_string_by_keys(
            value,
            &["event_type", "es_event_type", "event_name", "action"],
        ),
        find_string_by_keys(value, &["type"]),
    ];

    for candidate in candidates.into_iter().flatten() {
        if let Some(event_type) = map_event_type(&candidate) {
            return Some(event_type);
        }
    }

    None
}

fn map_event_type(raw: &str) -> Option<super::EventType> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    if normalized == "processexec" || normalized == "process_exec" || normalized.contains("exec") {
        return Some(super::EventType::ProcessExec);
    }
    if normalized == "processexit" || normalized == "process_exit" || normalized.contains("exit") {
        return Some(super::EventType::ProcessExit);
    }
    if normalized.contains("rename") || normalized.contains("move") {
        return Some(super::EventType::FileRename);
    }
    if normalized.contains("unlink")
        || normalized.contains("delete")
        || normalized.contains("remove")
    {
        return Some(super::EventType::FileUnlink);
    }
    if normalized == "filewrite"
        || normalized == "file_write"
        || normalized.contains("write")
        || normalized.contains("truncate")
        || normalized.contains("create")
    {
        return Some(super::EventType::FileWrite);
    }
    if normalized == "fileopen" || normalized == "file_open" || normalized.contains("open") {
        return Some(super::EventType::FileOpen);
    }
    if normalized == "dnsquery" || normalized == "dns_query" || normalized.contains("dns") {
        return Some(super::EventType::DnsQuery);
    }
    if normalized == "tcpconnect"
        || normalized == "tcp_connect"
        || normalized.contains("connect")
        || normalized.contains("socket")
    {
        return Some(super::EventType::TcpConnect);
    }
    if normalized == "moduleload"
        || normalized == "module_load"
        || normalized.contains("mmap")
        || normalized.contains("module")
        || normalized.contains("dyld")
        || normalized.contains("library")
    {
        return Some(super::EventType::ModuleLoad);
    }
    if normalized.contains("lsm") || normalized.contains("deny") || normalized.contains("block") {
        return Some(super::EventType::LsmBlock);
    }

    None
}

fn decode_pid(value: &Value) -> Option<u32> {
    let raw = first_u64(
        value,
        &[
            &["pid"],
            &["process", "pid"],
            &["process", "audit_token", "pid"],
            &["audit_token", "pid"],
            &["event", "pid"],
            &["target", "pid"],
        ],
    )
    .or_else(|| find_u64_by_keys(value, &["pid"]))?;

    u32::try_from(raw).ok()
}

fn decode_uid(value: &Value) -> Option<u32> {
    let raw = first_u64(
        value,
        &[
            &["uid"],
            &["process", "uid"],
            &["process", "audit_token", "uid"],
            &["audit_token", "uid"],
            &["event", "uid"],
            &["target", "uid"],
        ],
    )
    .or_else(|| find_u64_by_keys(value, &["uid", "euid"]))?;

    u32::try_from(raw).ok()
}

fn decode_timestamp_ns(value: &Value) -> Option<u64> {
    let raw = first_u64(
        value,
        &[
            &["ts_ns"],
            &["timestamp_ns"],
            &["timestamp"],
            &["event", "timestamp_ns"],
            &["event", "timestamp"],
            &["time"],
        ],
    )
    .or_else(|| find_u64_by_keys(value, &["timestamp", "ts", "time", "ts_ns"]));

    raw.map(normalize_timestamp_ns)
}

fn normalize_timestamp_ns(raw: u64) -> u64 {
    if raw == 0 {
        return unix_now_ns();
    }

    // Heuristic normalization:
    // - >=1e16: already in ns/us range (treat as ns)
    // - >=1e13: microseconds -> nanoseconds
    // - >=1e10: milliseconds -> nanoseconds
    // - >=1e9:  seconds -> nanoseconds
    if raw >= 10_000_000_000_000_000 {
        raw
    } else if raw >= 10_000_000_000_000 {
        raw.saturating_mul(1_000)
    } else if raw >= 10_000_000_000 {
        raw.saturating_mul(1_000_000)
    } else if raw >= 1_000_000_000 {
        raw.saturating_mul(1_000_000_000)
    } else {
        unix_now_ns()
    }
}

fn decode_payload(event_type: &super::EventType, value: &Value) -> String {
    let mut parts = Vec::new();

    match event_type {
        super::EventType::ProcessExec => {
            push_payload_kv(&mut parts, "path", extract_primary_path(value));
            push_payload_kv(&mut parts, "cmdline", extract_command_line(value));
        }
        super::EventType::ProcessExit => {
            push_payload_kv(&mut parts, "cmdline", extract_command_line(value));
        }
        super::EventType::FileOpen | super::EventType::FileWrite | super::EventType::ModuleLoad => {
            push_payload_kv(&mut parts, "path", extract_primary_path(value));
            if matches!(event_type, super::EventType::FileWrite) {
                push_payload_kv(
                    &mut parts,
                    "flags",
                    first_u64(value, &[&["flags"], &["event", "flags"]])
                        .map(|flags| flags.to_string()),
                );
            }
        }
        super::EventType::FileRename => {
            push_payload_kv(&mut parts, "src", extract_primary_path(value));
            push_payload_kv(
                &mut parts,
                "dst",
                first_string(
                    value,
                    &[
                        &["dst"],
                        &["target", "path"],
                        &["new", "path"],
                        &["event", "dst"],
                        &["event", "target", "path"],
                    ],
                )
                .or_else(|| find_string_by_keys(value, &["dst", "new_path", "target"])),
            );
        }
        super::EventType::FileUnlink => {
            push_payload_kv(&mut parts, "path", extract_primary_path(value));
        }
        super::EventType::TcpConnect => {
            let dst_ip = first_string(
                value,
                &[
                    &["dst_ip"],
                    &["remote", "ip"],
                    &["remote_address"],
                    &["event", "remote_address"],
                    &["event", "dst_ip"],
                ],
            )
            .or_else(|| find_string_by_keys(value, &["dst_ip", "remote_address", "ip"]));

            let dst_port = first_u64(
                value,
                &[
                    &["dst_port"],
                    &["remote", "port"],
                    &["event", "dst_port"],
                    &["event", "remote", "port"],
                ],
            )
            .or_else(|| find_u64_by_keys(value, &["dst_port", "port"]));

            match (dst_ip, dst_port) {
                (Some(ip), Some(port)) => {
                    push_payload_kv(&mut parts, "dst", Some(format!("{ip}:{port}")));
                }
                (Some(ip), None) => {
                    push_payload_kv(&mut parts, "dst_ip", Some(ip));
                }
                (None, Some(port)) => {
                    push_payload_kv(&mut parts, "dst_port", Some(port.to_string()));
                }
                (None, None) => {}
            }
        }
        super::EventType::DnsQuery => {
            let domain = first_string(
                value,
                &[
                    &["domain"],
                    &["query"],
                    &["qname"],
                    &["event", "domain"],
                    &["event", "query"],
                ],
            )
            .or_else(|| find_string_by_keys(value, &["domain", "qname", "query"]));
            push_payload_kv(&mut parts, "domain", domain);
        }
        super::EventType::LsmBlock => {
            push_payload_kv(
                &mut parts,
                "subject",
                first_string(value, &[&["subject"], &["event", "subject"]])
                    .or_else(|| find_string_by_keys(value, &["reason", "subject"])),
            );
        }
    }

    if parts.is_empty() {
        serde_json::to_string(value).unwrap_or_default()
    } else {
        parts.join(";")
    }
}

fn extract_primary_path(value: &Value) -> Option<String> {
    first_string(
        value,
        &[
            &["path"],
            &["file", "path"],
            &["target", "path"],
            &["source", "path"],
            &["process", "executable", "path"],
            &["executable", "path"],
            &["event", "path"],
            &["event", "file", "path"],
        ],
    )
    .or_else(|| {
        find_string_by_keys(
            value,
            &["path", "filename", "file", "executable", "source", "src"],
        )
    })
}

fn extract_command_line(value: &Value) -> Option<String> {
    let direct = first_string(
        value,
        &[
            &["cmdline"],
            &["command_line"],
            &["process", "cmdline"],
            &["process", "command_line"],
            &["event", "command_line"],
        ],
    )
    .or_else(|| find_string_by_keys(value, &["cmdline", "command_line"]));

    if direct.is_some() {
        return direct;
    }

    let args = first_string_array(
        value,
        &[
            &["args"],
            &["argv"],
            &["process", "args"],
            &["process", "argv"],
        ],
    );
    args.and_then(|items| {
        if items.is_empty() {
            None
        } else {
            Some(items.join(" "))
        }
    })
}

fn push_payload_kv(parts: &mut Vec<String>, key: &str, value: Option<String>) {
    let Some(value) = value else {
        return;
    };

    let cleaned = sanitize_payload_value(&value);
    if cleaned.is_empty() {
        return;
    }

    parts.push(format!("{key}={cleaned}"));
}

fn sanitize_payload_value(raw: &str) -> String {
    raw.chars()
        .map(|ch| match ch {
            ';' | ',' | '\n' | '\r' => ' ',
            _ => ch,
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn first_string(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| lookup_string_path(value, path))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn first_u64(value: &Value, paths: &[&[&str]]) -> Option<u64> {
    paths.iter().find_map(|path| lookup_u64_path(value, path))
}

fn first_string_array(value: &Value, paths: &[&[&str]]) -> Option<Vec<String>> {
    paths
        .iter()
        .find_map(|path| lookup_string_array_path(value, path))
}

fn lookup_string_path(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }

    if let Some(value) = current.as_str() {
        return Some(value.to_string());
    }

    if let Some(value) = current.as_i64() {
        return Some(value.to_string());
    }

    current.as_u64().map(|value| value.to_string())
}

fn lookup_u64_path(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }

    current
        .as_u64()
        .or_else(|| current.as_i64().and_then(|v| u64::try_from(v).ok()))
        .or_else(|| current.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
}

fn lookup_string_array_path(value: &Value, path: &[&str]) -> Option<Vec<String>> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }

    let items = current
        .as_array()?
        .iter()
        .filter_map(|item| {
            item.as_str()
                .map(|raw| raw.to_string())
                .or_else(|| item.as_u64().map(|raw| raw.to_string()))
        })
        .collect::<Vec<_>>();

    if items.is_empty() {
        None
    } else {
        Some(items)
    }
}

fn find_string_by_keys(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if keys
                    .iter()
                    .any(|candidate| key.eq_ignore_ascii_case(candidate))
                {
                    if let Some(value) = child
                        .as_str()
                        .map(|raw| raw.to_string())
                        .or_else(|| child.as_i64().map(|raw| raw.to_string()))
                        .or_else(|| child.as_u64().map(|raw| raw.to_string()))
                    {
                        let trimmed = value.trim();
                        if !trimmed.is_empty() {
                            return Some(trimmed.to_string());
                        }
                    }
                }

                if let Some(found) = find_string_by_keys(child, keys) {
                    return Some(found);
                }
            }

            None
        }
        Value::Array(items) => items
            .iter()
            .find_map(|item| find_string_by_keys(item, keys)),
        _ => None,
    }
}

fn find_u64_by_keys(value: &Value, keys: &[&str]) -> Option<u64> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if keys
                    .iter()
                    .any(|candidate| key.eq_ignore_ascii_case(candidate))
                {
                    if let Some(value) = child
                        .as_u64()
                        .or_else(|| child.as_i64().and_then(|raw| u64::try_from(raw).ok()))
                        .or_else(|| {
                            child
                                .as_str()
                                .and_then(|raw| raw.trim().parse::<u64>().ok())
                        })
                    {
                        return Some(value);
                    }
                }

                if let Some(found) = find_u64_by_keys(child, keys) {
                    return Some(found);
                }
            }

            None
        }
        Value::Array(items) => items.iter().find_map(|item| find_u64_by_keys(item, keys)),
        _ => None,
    }
}

fn unix_now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Statistics for the ESF subsystem.
#[derive(Debug, Clone, Default)]
pub struct EsfStats {
    pub events_received: u64,
    pub events_dropped: u64,
}

/// Errors from ESF operations.
#[derive(Debug)]
pub enum EsfError {
    NotAvailable(String),
}

impl fmt::Display for EsfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAvailable(msg) => write!(f, "ESF not available: {msg}"),
        }
    }
}

impl std::error::Error for EsfError {}

#[cfg(test)]
mod tests {
    use super::{map_event_type, parse_event_line, EsfEngine};

    #[test]
    fn esf_engine_stub_starts_cleanly() {
        let mut engine = EsfEngine::new();
        assert!(!engine.is_active());

        engine.start().expect("engine starts in compatibility mode");
        assert!(engine.is_active());

        let events = engine.poll_events(100).expect("poll succeeds");
        assert!(events.is_empty());

        let stats = engine.stats();
        assert_eq!(stats.events_received, 0);

        engine.stop().expect("engine stops cleanly");
        assert!(!engine.is_active());
    }

    #[test]
    fn event_type_mapping_handles_common_esf_event_names() {
        assert!(matches!(
            map_event_type("AUTH_EXEC"),
            Some(super::super::EventType::ProcessExec)
        ));
        assert!(matches!(
            map_event_type("NOTIFY_OPEN"),
            Some(super::super::EventType::FileOpen)
        ));
        assert!(matches!(
            map_event_type("NOTIFY_RENAME"),
            Some(super::super::EventType::FileRename)
        ));
        assert!(matches!(
            map_event_type("NOTIFY_DNS_REQUEST"),
            Some(super::super::EventType::DnsQuery)
        ));
    }

    #[test]
    fn parser_accepts_raw_event_json_lines() {
        let line = r#"{"event_type":"DnsQuery","pid":5,"uid":501,"ts_ns":42,"payload":"domain=example.com"}"#;
        let event = parse_event_line(line).expect("line parses");

        assert!(matches!(
            event.event_type,
            super::super::EventType::DnsQuery
        ));
        assert_eq!(event.pid, 5);
        assert_eq!(event.uid, 501);
        assert_eq!(event.ts_ns, 42);
        assert_eq!(event.payload, "domain=example.com");
    }

    #[test]
    fn parser_normalizes_eslogger_exec_shape() {
        let line = r#"{
            "event_type":"AUTH_EXEC",
            "process":{"audit_token":{"pid":4242,"uid":501},"command_line":"/bin/zsh -l","executable":{"path":"/bin/zsh"}}
        }"#;

        let event = parse_event_line(line).expect("eslogger line parses");
        assert!(matches!(
            event.event_type,
            super::super::EventType::ProcessExec
        ));
        assert_eq!(event.pid, 4242);
        assert_eq!(event.uid, 501);
        assert!(event.payload.contains("path=/bin/zsh"));
        assert!(event.payload.contains("cmdline=/bin/zsh -l"));
    }
}
