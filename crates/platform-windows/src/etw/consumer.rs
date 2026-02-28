//! Real-time ETW event consumer.
//!
//! On Windows: dedicated OS thread running `ProcessTrace()` with a callback that
//! bridges events into a bounded `mpsc::sync_channel`. The main tick loop drains
//! this channel via `poll_events()`.
//!
//! On non-Windows: lightweight stub that only supports replay-based testing.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::RawEvent;

const ETW_REPLAY_PATH_ENV: &str = "EGUARD_ETW_REPLAY_PATH";

/// Channel capacity: bounded to provide back-pressure.
#[cfg(target_os = "windows")]
const CHANNEL_CAPACITY: usize = 16_384;

// ── Windows: real ProcessTrace consumer ──────────────────────────────

#[cfg(target_os = "windows")]
mod win32 {
    use super::super::codec;
    use crate::RawEvent;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::SyncSender;
    use std::sync::Arc;
    use windows::Win32::System::Diagnostics::Etw::*;

    /// State passed to the ETW callback via thread-local storage.
    struct CallbackState {
        sender: SyncSender<RawEvent>,
        agent_pid: u32,
        drops: Arc<AtomicU64>,
    }

    thread_local! {
        static CALLBACK_STATE: RefCell<Option<CallbackState>> = const { RefCell::new(None) };
    }

    /// The raw ETW event callback invoked by `ProcessTrace` on the consumer thread.
    ///
    /// SAFETY: Called by the OS on the thread that invoked `ProcessTrace`.
    /// We access only thread-local state and send via the bounded channel.
    unsafe extern "system" fn etw_event_callback(record: *mut EVENT_RECORD) {
        let record = unsafe { &*record };
        let header = &record.EventHeader;

        // Self-filter: skip events from the agent's own process.
        CALLBACK_STATE.with(|cell| {
            let borrow = cell.borrow();
            let Some(state) = borrow.as_ref() else {
                return;
            };

            if header.ProcessId == state.agent_pid {
                return;
            }

            // Extract provider GUID as string for codec dispatch.
            let guid = &header.ProviderId;
            let guid_str = format!(
                "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                guid.data1,
                guid.data2,
                guid.data3,
                guid.data4[0],
                guid.data4[1],
                guid.data4[2],
                guid.data4[3],
                guid.data4[4],
                guid.data4[5],
                guid.data4[6],
                guid.data4[7],
            );

            // Convert FILETIME (100-ns since 1601) to Unix nanoseconds.
            let ts_ns = filetime_to_unix_ns(header.TimeStamp);

            let opcode = header.EventDescriptor.Opcode;
            let pid = header.ProcessId;

            // Parse the binary UserData into a structured RawEvent.
            let user_data = if record.UserDataLength > 0 && !record.UserData.is_null() {
                unsafe {
                    std::slice::from_raw_parts(
                        record.UserData as *const u8,
                        record.UserDataLength as usize,
                    )
                }
            } else {
                &[]
            };

            let event = codec::decode_etw_record(&guid_str, opcode, pid, ts_ns, user_data);

            if let Some(event) = event {
                if state.sender.try_send(event).is_err() {
                    state.drops.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    /// Convert Windows FILETIME (100-ns intervals since 1601-01-01) to Unix nanoseconds.
    fn filetime_to_unix_ns(filetime: i64) -> u64 {
        // Offset between 1601 and 1970 in 100-ns intervals.
        const EPOCH_OFFSET: i64 = 116_444_736_000_000_000;
        let unix_100ns = filetime.saturating_sub(EPOCH_OFFSET);
        if unix_100ns < 0 {
            return 0;
        }
        (unix_100ns as u64).saturating_mul(100)
    }

    /// Spawn the consumer thread. Returns `(JoinHandle, Receiver, Arc<AtomicU64>)`.
    pub(super) fn spawn_consumer_thread(
        session_name: String,
        sender: SyncSender<RawEvent>,
        drops: Arc<AtomicU64>,
    ) -> std::thread::JoinHandle<()> {
        let agent_pid = std::process::id();

        std::thread::Builder::new()
            .name("etw-consumer".into())
            .spawn(move || {
                // Install thread-local callback state.
                CALLBACK_STATE.with(|cell| {
                    *cell.borrow_mut() = Some(CallbackState {
                        sender,
                        agent_pid,
                        drops,
                    });
                });

                run_process_trace(&session_name);

                // Cleanup thread-local.
                CALLBACK_STATE.with(|cell| {
                    *cell.borrow_mut() = None;
                });
            })
            .expect("failed to spawn etw-consumer thread")
    }

    /// Open the real-time trace and block on `ProcessTrace`.
    fn run_process_trace(session_name: &str) {
        use widestring::U16CString;
        use windows::Win32::Foundation::ERROR_SUCCESS;

        /// `PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD`.
        const TRACE_MODE: u32 = 0x0000_0100 | 0x1000_0000;

        let Ok(name_wide) = U16CString::from_str(session_name) else {
            tracing::error!(
                session = session_name,
                "invalid session name for OpenTraceW"
            );
            return;
        };

        // SAFETY: EVENT_TRACE_LOGFILEW is a C struct; zeroed memory is a valid initial state.
        // Union field access requires unsafe in older Rust editions but not 2021+.
        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        logfile.LoggerName = windows::core::PWSTR(name_wide.as_ptr() as *mut _);
        logfile.Anonymous1.ProcessTraceMode = TRACE_MODE;
        logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback);

        let trace_handle = unsafe { OpenTraceW(&mut logfile) };

        // INVALID_PROCESSTRACE_HANDLE = u64::MAX
        if trace_handle.Value == u64::MAX {
            tracing::error!(session = session_name, "OpenTraceW failed (invalid handle)");
            return;
        }

        tracing::info!(session = session_name, "ETW consumer thread started");

        // ProcessTrace blocks until the session is stopped.
        let result = unsafe { ProcessTrace(&[trace_handle], None, None) };

        if result != ERROR_SUCCESS {
            tracing::warn!(
                session = session_name,
                error = ?result,
                "ProcessTrace returned error"
            );
        }

        let _ = unsafe { CloseTrace(trace_handle) };
        tracing::info!(session = session_name, "ETW consumer thread exiting");
    }
}

// ── Public API ───────────────────────────────────────────────────────

/// Consumes events from an ETW real-time session.
pub struct EtwConsumer {
    pending_events: VecDeque<RawEvent>,
    running: bool,

    #[cfg(target_os = "windows")]
    receiver: Option<std::sync::mpsc::Receiver<RawEvent>>,
    #[cfg(target_os = "windows")]
    thread_handle: Option<std::thread::JoinHandle<()>>,
    #[cfg(target_os = "windows")]
    drops_count: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl EtwConsumer {
    /// Create a consumer for the given session.
    pub fn new(session_name: &str) -> Self {
        let mut consumer = Self {
            pending_events: VecDeque::new(),
            running: false,

            #[cfg(target_os = "windows")]
            receiver: None,
            #[cfg(target_os = "windows")]
            thread_handle: None,
            #[cfg(target_os = "windows")]
            drops_count: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        let _ = session_name; // used on Windows only for real trace
        consumer.load_replay_from_env();
        consumer
    }

    /// Begin consuming events.
    ///
    /// On Windows: spawns the `ProcessTrace` thread and opens the bounded channel.
    /// On non-Windows: just marks the consumer as running (replay events available).
    pub fn run(&mut self, session_name: &str) -> Result<(), super::EtwError> {
        if session_name.is_empty() {
            return Err(super::EtwError::ConsumerStart(
                "cannot run ETW consumer without a session name".to_string(),
            ));
        }

        #[cfg(target_os = "windows")]
        {
            let (tx, rx) = std::sync::mpsc::sync_channel(CHANNEL_CAPACITY);
            let drops = self.drops_count.clone();
            let handle = win32::spawn_consumer_thread(session_name.to_string(), tx, drops);
            self.receiver = Some(rx);
            self.thread_handle = Some(handle);
        }

        self.running = true;
        Ok(())
    }

    /// Poll for the next batch of events (non-blocking).
    ///
    /// Drains replay events first, then reads from the real channel.
    pub fn poll_events(&mut self, max_batch: usize) -> Vec<RawEvent> {
        if !self.running || max_batch == 0 {
            return Vec::new();
        }

        let mut events = Vec::with_capacity(max_batch.min(256));

        // 1. Drain pending replay events first.
        while events.len() < max_batch {
            if let Some(event) = self.pending_events.pop_front() {
                events.push(event);
            } else {
                break;
            }
        }

        // 2. Drain real channel (Windows only).
        #[cfg(target_os = "windows")]
        {
            if let Some(rx) = &self.receiver {
                while events.len() < max_batch {
                    match rx.try_recv() {
                        Ok(event) => events.push(event),
                        Err(std::sync::mpsc::TryRecvError::Empty) => break,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            tracing::warn!("ETW consumer channel disconnected");
                            self.running = false;
                            break;
                        }
                    }
                }
            }
        }

        events
    }

    /// Number of events dropped due to channel back-pressure (Windows only).
    pub fn drops_count(&self) -> u64 {
        #[cfg(target_os = "windows")]
        {
            self.drops_count.load(std::sync::atomic::Ordering::Relaxed)
        }
        #[cfg(not(target_os = "windows"))]
        {
            0
        }
    }

    fn load_replay_from_env(&mut self) {
        let Some(path) = std::env::var(ETW_REPLAY_PATH_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return;
        };

        match load_replay_events(Path::new(&path)) {
            Ok(events) => {
                if !events.is_empty() {
                    self.pending_events.extend(events);
                    tracing::info!(
                        replay_path = %path,
                        replay_events = self.pending_events.len(),
                        "loaded ETW replay events"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(
                    replay_path = %path,
                    error = %err,
                    "failed loading ETW replay events"
                );
            }
        }
    }

    #[cfg(test)]
    fn inject_events(&mut self, events: Vec<RawEvent>) {
        self.pending_events.extend(events);
    }
}

impl Drop for EtwConsumer {
    fn drop(&mut self) {
        self.running = false;

        // On Windows, join the consumer thread. The session should already be
        // stopped (by EtwEngine::stop), which causes ProcessTrace to return.
        #[cfg(target_os = "windows")]
        {
            // Drop receiver first to unblock any pending send.
            self.receiver = None;
            if let Some(handle) = self.thread_handle.take() {
                let _ = handle.join();
            }
        }
    }
}

fn load_replay_events(path: &Path) -> std::io::Result<Vec<RawEvent>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        match serde_json::from_str::<RawEvent>(trimmed) {
            Ok(event) => out.push(event),
            Err(err) => {
                tracing::warn!(
                    replay_path = %path.display(),
                    line = trimmed,
                    error = %err,
                    "failed parsing ETW replay line"
                );
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{load_replay_events, EtwConsumer};
    use crate::{EventType, RawEvent};

    #[test]
    fn load_replay_events_parses_ndjson_lines() {
        let replay_path =
            std::env::temp_dir().join(format!("eguard-etw-replay-{}.ndjson", std::process::id()));

        let content = [
            "# comment",
            r#"{"event_type":"ProcessExec","pid":10,"uid":0,"ts_ns":1,"payload":"cmdline=powershell"}"#,
            r#"{"event_type":"TcpConnect","pid":10,"uid":0,"ts_ns":2,"payload":"dst=203.0.113.10:443"}"#,
        ]
        .join("\n");
        std::fs::write(&replay_path, content).expect("write replay file");

        let events = load_replay_events(&replay_path).expect("parse replay file");
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0].event_type, EventType::ProcessExec));
        assert!(matches!(events[1].event_type, EventType::TcpConnect));

        let _ = std::fs::remove_file(replay_path);
    }

    #[test]
    fn poll_events_respects_batch_size() {
        let mut consumer = EtwConsumer::new("test-session");
        consumer.inject_events(vec![
            RawEvent {
                event_type: EventType::ProcessExec,
                pid: 1,
                uid: 0,
                ts_ns: 1,
                payload: "a".to_string(),
            },
            RawEvent {
                event_type: EventType::ProcessExec,
                pid: 2,
                uid: 0,
                ts_ns: 2,
                payload: "b".to_string(),
            },
        ]);

        consumer.running = true;

        let batch = consumer.poll_events(1);
        assert_eq!(batch.len(), 1);

        let remaining = consumer.poll_events(10);
        assert_eq!(remaining.len(), 1);
    }

    #[test]
    fn run_requires_non_empty_session_name() {
        let mut consumer = EtwConsumer::new("test");
        assert!(consumer.run("").is_err());
    }

    #[test]
    fn drops_count_is_zero_on_non_windows() {
        let consumer = EtwConsumer::new("test");
        assert_eq!(consumer.drops_count(), 0);
    }
}
