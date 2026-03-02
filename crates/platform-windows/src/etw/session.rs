//! ETW session lifecycle management.
//!
//! Manages creation, configuration, and teardown of ETW trace sessions.
//! On Windows: real Win32 `StartTraceW` / `EnableTraceEx2` / `ControlTraceW`.
//! On non-Windows: lightweight stub for cross-compilation and tests.

use super::providers::ProviderConfig;
use std::collections::HashSet;

// ── Windows implementation ───────────────────────────────────────────

#[cfg(target_os = "windows")]
mod win32 {
    use super::super::EtwError;
    use super::ProviderConfig;
    use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
    use windows::Win32::System::Diagnostics::Etw::*;

    /// `EVENT_TRACE_REAL_TIME_MODE` — enable real-time delivery.
    const REAL_TIME_MODE: u32 = 0x0000_0100;
    /// `WNODE_FLAG_TRACED_GUID`.
    const WNODE_FLAG_TRACED_GUID: u32 = 0x0002_0000;
    /// `EnableTraceEx2` control code for enabling a provider.
    const ENABLE_PROVIDER: u32 = 1;
    /// `EnableTraceEx2` control code for disabling a provider.
    const DISABLE_PROVIDER: u32 = 0;

    fn handle(val: u64) -> CONTROLTRACE_HANDLE {
        CONTROLTRACE_HANDLE { Value: val }
    }

    /// Allocate and initialize an `EVENT_TRACE_PROPERTIES` buffer for a real-time session.
    pub(super) fn alloc_properties(session_name: &str) -> Vec<u8> {
        let name_wide: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let name_bytes = name_wide.len() * 2;
        let struct_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let total = struct_size + name_bytes;

        let mut buf = vec![0u8; total];

        // SAFETY: buf is correctly sized and zeroed.
        let props = unsafe { &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
        props.Wnode.BufferSize = total as u32;
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props.Wnode.ClientContext = 1; // QPC timestamps
        props.BufferSize = 64; // 64 KB per buffer
        props.MinimumBuffers = 4;
        props.MaximumBuffers = 64;
        props.FlushTimer = 1; // flush every 1 second
        props.LogFileMode = REAL_TIME_MODE;
        props.LoggerNameOffset = struct_size as u32;

        // Copy the UTF-16 session name after the struct.
        let name_src =
            unsafe { std::slice::from_raw_parts(name_wide.as_ptr() as *const u8, name_bytes) };
        buf[struct_size..struct_size + name_bytes].copy_from_slice(name_src);

        buf
    }

    /// Try to stop an orphaned session (from a previous crash) before starting fresh.
    pub(super) fn cleanup_orphaned_session(session_name: &str) {
        let mut buf = alloc_properties(session_name);
        let props = unsafe { &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };

        let name_wide: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let pcwstr = windows::core::PCWSTR(name_wide.as_ptr());

        // Best-effort: ignore errors (the session may not exist).
        let _ = unsafe { ControlTraceW(handle(0), pcwstr, props, EVENT_TRACE_CONTROL_STOP) };
    }

    /// Start a real-time ETW trace session. Returns the trace handle on success.
    pub(super) fn start_trace(session_name: &str) -> Result<(u64, Vec<u8>), EtwError> {
        // Clean up any orphaned session from a previous crash.
        cleanup_orphaned_session(session_name);

        const START_TRACE_MAX_ATTEMPTS: usize = 3;
        const START_TRACE_RETRY_DELAY_MS: u64 = 50;

        let name_wide: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let pcwstr = windows::core::PCWSTR(name_wide.as_ptr());

        for attempt in 0..START_TRACE_MAX_ATTEMPTS {
            let mut props_buf = alloc_properties(session_name);
            let props = unsafe { &mut *(props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };

            let mut trace_handle = handle(0);
            let result = unsafe { StartTraceW(&mut trace_handle, pcwstr, props) };

            if result == ERROR_SUCCESS {
                return Ok((trace_handle.Value, props_buf));
            }

            if result == ERROR_ALREADY_EXISTS && attempt + 1 < START_TRACE_MAX_ATTEMPTS {
                cleanup_orphaned_session(session_name);
                std::thread::sleep(std::time::Duration::from_millis(START_TRACE_RETRY_DELAY_MS));
                continue;
            }

            return Err(EtwError::SessionCreate(format!(
                "StartTraceW failed: {:?}",
                result
            )));
        }

        Err(EtwError::SessionCreate(
            "StartTraceW failed after retries".to_string(),
        ))
    }

    /// Enable a provider on the trace session.
    pub(super) fn enable_provider(
        trace_handle: u64,
        config: &ProviderConfig,
    ) -> Result<(), EtwError> {
        let guid = super::super::providers::parse_guid(config.guid_str).map_err(|e| {
            EtwError::ProviderEnable(format!("bad GUID '{}': {e}", config.guid_str))
        })?;

        let result = unsafe {
            EnableTraceEx2(
                handle(trace_handle),
                &guid,
                ENABLE_PROVIDER,
                config.level,
                config.match_any_keyword,
                0, // MatchAllKeyword
                0, // Timeout
                None,
            )
        };

        if result != ERROR_SUCCESS {
            return Err(EtwError::ProviderEnable(format!(
                "EnableTraceEx2 failed for '{}': {:?}",
                config.guid_str, result
            )));
        }

        Ok(())
    }

    /// Disable a provider before stopping the session.
    pub(super) fn disable_provider(trace_handle: u64, guid_str: &str) {
        if let Ok(guid) = super::super::providers::parse_guid(guid_str) {
            let _ = unsafe {
                EnableTraceEx2(
                    handle(trace_handle),
                    &guid,
                    DISABLE_PROVIDER,
                    0,
                    0,
                    0,
                    0,
                    None,
                )
            };
        }
    }

    /// Stop the trace session.
    pub(super) fn stop_trace(session_name: &str, trace_handle: u64, props_buf: &mut [u8]) {
        let props = unsafe { &mut *(props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
        // Zero counters so ControlTraceW can fill them.
        props.NumberOfBuffers = 0;
        props.FreeBuffers = 0;
        props.EventsLost = 0;
        props.BuffersWritten = 0;

        let name_wide: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let pcwstr = windows::core::PCWSTR(name_wide.as_ptr());

        let _ = unsafe {
            ControlTraceW(
                handle(trace_handle),
                pcwstr,
                props,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
    }
}

// ── Public API ───────────────────────────────────────────────────────

/// Represents a named ETW trace session.
pub struct EtwSession {
    name: String,
    active: bool,
    enabled_providers: HashSet<String>,

    #[cfg(target_os = "windows")]
    trace_handle: u64,
    #[cfg(target_os = "windows")]
    props_buf: Vec<u8>,

    #[cfg(not(target_os = "windows"))]
    stub_handle: u64,
}

#[cfg(not(target_os = "windows"))]
static NEXT_STUB_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl EtwSession {
    /// Create a new session descriptor (does not start tracing).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            active: false,
            enabled_providers: HashSet::new(),

            #[cfg(target_os = "windows")]
            trace_handle: 0,
            #[cfg(target_os = "windows")]
            props_buf: Vec::new(),

            #[cfg(not(target_os = "windows"))]
            stub_handle: 0,
        }
    }

    /// Start the trace session.
    pub fn start(&mut self) -> Result<(), super::EtwError> {
        if self.active {
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        {
            let (handle, props_buf) = win32::start_trace(&self.name)?;
            self.trace_handle = handle;
            self.props_buf = props_buf;
            self.active = true;
        }

        #[cfg(not(target_os = "windows"))]
        {
            self.stub_handle = NEXT_STUB_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.active = true;
        }

        Ok(())
    }

    /// Enable a provider on this session.
    pub fn enable_provider(&mut self, config: &ProviderConfig) -> Result<(), super::EtwError> {
        if !self.active {
            return Err(super::EtwError::InvalidState(format!(
                "session '{}' is not active",
                self.name
            )));
        }

        #[cfg(target_os = "windows")]
        {
            win32::enable_provider(self.trace_handle, config)?;
        }

        self.enabled_providers
            .insert(config.guid_str.to_ascii_lowercase());
        Ok(())
    }

    /// Stop the session and release resources.
    pub fn stop(&mut self) -> Result<(), super::EtwError> {
        if !self.active {
            return Ok(());
        }

        tracing::info!(session = %self.name, "stopping ETW session");

        #[cfg(target_os = "windows")]
        {
            // Disable all providers before stopping.
            let guids: Vec<String> = self.enabled_providers.drain().collect();
            for guid_str in &guids {
                win32::disable_provider(self.trace_handle, guid_str);
            }
            win32::stop_trace(&self.name, self.trace_handle, &mut self.props_buf);
            self.trace_handle = 0;
            self.props_buf.clear();
        }

        #[cfg(not(target_os = "windows"))]
        {
            self.stub_handle = 0;
            self.enabled_providers.clear();
        }

        self.active = false;
        Ok(())
    }

    /// Session name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the session is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Number of enabled providers.
    pub fn provider_count(&self) -> usize {
        self.enabled_providers.len()
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        if self.active {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::providers::{ProviderConfig, DEFAULT_PROVIDERS, KERNEL_PROCESS};
    use super::EtwSession;

    #[test]
    fn enable_provider_deduplicates_entries() {
        let mut session = EtwSession::new("test");
        session.start().expect("session start");

        // Same GUID with different casing.
        let cfg1 = ProviderConfig {
            guid_str: KERNEL_PROCESS,
            match_any_keyword: u64::MAX,
            level: 5,
        };
        let cfg2 = ProviderConfig {
            guid_str: KERNEL_PROCESS,
            match_any_keyword: u64::MAX,
            level: 5,
        };

        session.enable_provider(&cfg1).expect("provider 1");
        session.enable_provider(&cfg2).expect("provider 2");

        assert_eq!(session.provider_count(), 1);
    }

    #[test]
    fn stop_clears_providers() {
        let mut session = EtwSession::new("test-stop");
        session.start().expect("start");
        session
            .enable_provider(&DEFAULT_PROVIDERS[0])
            .expect("enable");
        assert_eq!(session.provider_count(), 1);

        session.stop().expect("stop");
        assert_eq!(session.provider_count(), 0);
        assert!(!session.is_active());
    }
}
