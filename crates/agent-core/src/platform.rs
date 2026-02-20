#[cfg(target_os = "linux")]
pub use platform_linux::{
    enrich_event_with_cache, scan_kernel_integrity, EbpfEngine, EbpfStats, EnrichedEvent,
    EnrichmentCache, EventType, KernelIntegrityScanOptions, RawEvent,
};

#[cfg(target_os = "windows")]
pub use platform_windows::{
    enrich_event_with_cache, EnrichedEvent, EnrichmentCache, EventType, RawEvent,
};

#[cfg(target_os = "windows")]
mod windows_engine {
    use std::collections::HashMap;
    use std::fmt;
    use std::io;
    use std::time::Duration;

    use platform_windows::EtwEngine;

    use super::RawEvent;

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct EbpfStats {
        pub events_received: u64,
        pub events_dropped: u64,
        pub parse_errors: u64,
        pub per_probe_events: HashMap<String, u64>,
        pub per_probe_errors: HashMap<String, u64>,
        pub failed_probes: Vec<String>,
        pub kernel_version: String,
        pub btf_available: bool,
        pub lsm_available: bool,
    }

    #[derive(Debug)]
    pub enum EbpfError {
        Backend(String),
    }

    impl fmt::Display for EbpfError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Backend(msg) => write!(f, "ETW backend error: {msg}"),
            }
        }
    }

    impl std::error::Error for EbpfError {}

    pub type Result<T> = std::result::Result<T, EbpfError>;

    pub struct EbpfEngine {
        etw: EtwEngine,
        stats: EbpfStats,
        enabled: bool,
        started: bool,
    }

    impl EbpfEngine {
        pub fn disabled() -> Self {
            Self {
                etw: EtwEngine::new(),
                stats: EbpfStats {
                    kernel_version: "windows".to_string(),
                    ..EbpfStats::default()
                },
                enabled: false,
                started: false,
            }
        }

        pub fn from_etw() -> Result<Self> {
            Ok(Self {
                etw: EtwEngine::new(),
                stats: EbpfStats {
                    kernel_version: "windows".to_string(),
                    ..EbpfStats::default()
                },
                enabled: true,
                started: false,
            })
        }

        pub fn poll_once(&mut self, _timeout: Duration) -> Result<Vec<RawEvent>> {
            if !self.enabled {
                return Ok(Vec::new());
            }

            if !self.started {
                self.etw
                    .start()
                    .map_err(|err| EbpfError::Backend(err.to_string()))?;
                self.started = true;
            }

            let events = self
                .etw
                .poll_events(256)
                .map_err(|err| EbpfError::Backend(err.to_string()))?;

            let etw_stats = self.etw.stats();
            self.stats.events_received = self
                .stats
                .events_received
                .saturating_add(events.len() as u64);
            self.stats.events_dropped = etw_stats.events_lost;
            self.stats.per_probe_events.insert(
                "etw".to_string(),
                self.stats
                    .per_probe_events
                    .get("etw")
                    .copied()
                    .unwrap_or_default()
                    .saturating_add(events.len() as u64),
            );

            Ok(events)
        }

        pub fn stats(&self) -> EbpfStats {
            self.stats.clone()
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct KernelIntegrityScanOptions;

    impl KernelIntegrityScanOptions {
        pub fn from_env() -> Self {
            Self
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct KernelIntegrityReport {
        pub indicators: Vec<String>,
    }

    impl KernelIntegrityReport {
        pub fn command_line(&self) -> String {
            "indicators=none; collector=etw; kernel_integrity=not_applicable".to_string()
        }
    }

    pub fn scan_kernel_integrity(
        _opts: &KernelIntegrityScanOptions,
    ) -> io::Result<KernelIntegrityReport> {
        Ok(KernelIntegrityReport::default())
    }
}

#[cfg(target_os = "windows")]
pub use windows_engine::{
    scan_kernel_integrity, EbpfEngine, EbpfStats, KernelIntegrityScanOptions,
};
