use std::fmt;

#[derive(Debug, Clone)]
pub struct DebuggerCheckConfig {
    pub timing_threshold_cycles: u64,
    pub timing_probe_iterations: u32,
    pub enable_tracer_pid_probe: bool,
    pub enable_timing_probe: bool,
}

impl Default for DebuggerCheckConfig {
    fn default() -> Self {
        Self {
            timing_threshold_cycles: env_u64(
                "EGUARD_SELF_PROTECT_TIMING_THRESHOLD_CYCLES",
                50_000_000,
            ),
            timing_probe_iterations: env_u32("EGUARD_SELF_PROTECT_TIMING_ITERATIONS", 200_000),
            enable_tracer_pid_probe: env_bool("EGUARD_SELF_PROTECT_ENABLE_TRACER_PID", true),
            enable_timing_probe: env_bool("EGUARD_SELF_PROTECT_ENABLE_TIMING", true),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebuggerSignal {
    TracerPidDetected {
        tracer_pid: u32,
    },
    TimingAnomaly {
        observed_cycles: u64,
        threshold_cycles: u64,
    },
    ProbeError {
        probe: &'static str,
        detail: String,
    },
}

impl DebuggerSignal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::TracerPidDetected { .. } => "tracer_pid_detected",
            Self::TimingAnomaly { .. } => "timing_anomaly",
            Self::ProbeError { .. } => "probe_error",
        }
    }
}

impl fmt::Display for DebuggerSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TracerPidDetected { tracer_pid } => {
                write!(f, "TracerPid indicates debugger attached ({})", tracer_pid)
            }
            Self::TimingAnomaly {
                observed_cycles,
                threshold_cycles,
            } => write!(
                f,
                "timing probe exceeded threshold (observed={} threshold={})",
                observed_cycles, threshold_cycles
            ),
            Self::ProbeError { probe, detail } => {
                write!(f, "debugger probe '{}' failed: {}", probe, detail)
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DebuggerObservation {
    pub signals: Vec<DebuggerSignal>,
}

impl DebuggerObservation {
    pub fn detected(&self) -> bool {
        !self.signals.is_empty()
    }

    pub fn signal_codes(&self) -> Vec<&'static str> {
        self.signals.iter().map(DebuggerSignal::code).collect()
    }
}

pub fn detect_debugger(config: &DebuggerCheckConfig) -> DebuggerObservation {
    let mut signals = Vec::new();

    if config.enable_tracer_pid_probe {
        #[cfg(target_os = "linux")]
        {
            match std::fs::read_to_string("/proc/self/status") {
                Ok(status) => {
                    if let Some(tracer_pid) = parse_tracer_pid(&status) {
                        if tracer_pid > 0 {
                            signals.push(DebuggerSignal::TracerPidDetected { tracer_pid });
                        }
                    }
                }
                Err(err) => {
                    signals.push(DebuggerSignal::ProbeError {
                        probe: "tracer_pid",
                        detail: err.to_string(),
                    });
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            // On macOS, check the P_TRACED flag via sysctl instead of /proc.
            if let Some(traced) = detect_tracer_macos() {
                if traced {
                    signals.push(DebuggerSignal::TracerPidDetected { tracer_pid: 1 });
                }
            }
        }
    }

    if config.enable_timing_probe {
        if let Some(observed_cycles) = sample_timing_cycles(config.timing_probe_iterations) {
            if observed_cycles > config.timing_threshold_cycles {
                signals.push(DebuggerSignal::TimingAnomaly {
                    observed_cycles,
                    threshold_cycles: config.timing_threshold_cycles,
                });
            }
        }
    }

    DebuggerObservation { signals }
}

pub fn parse_tracer_pid(status: &str) -> Option<u32> {
    for line in status.lines() {
        let Some(raw) = line.strip_prefix("TracerPid:") else {
            continue;
        };
        let value = raw.trim();
        if value.is_empty() {
            return None;
        }
        return value.parse::<u32>().ok();
    }
    None
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub fn sample_timing_cycles(iterations: u32) -> Option<u64> {
    if iterations == 0 {
        return Some(0);
    }

    let start = read_tsc();
    let mut state = 0u64;
    for i in 0..iterations {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(i as u64);
        std::hint::black_box(state);
    }
    let end = read_tsc();
    Some(end.saturating_sub(start))
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
pub fn sample_timing_cycles(_iterations: u32) -> Option<u64> {
    None
}

#[cfg(target_arch = "x86_64")]
fn read_tsc() -> u64 {
    // SAFETY: reading the processor cycle counter has no memory safety implications.
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[cfg(target_arch = "x86")]
fn read_tsc() -> u64 {
    // SAFETY: reading the processor cycle counter has no memory safety implications.
    unsafe { core::arch::x86::_rdtsc() }
}

/// Detect debugger on macOS via sysctl P_TRACED flag.
#[cfg(target_os = "macos")]
fn detect_tracer_macos() -> Option<bool> {
    use std::mem;
    use std::ptr;

    const P_TRACED: i32 = 0x00000800;

    let pid = unsafe { libc::getpid() };
    let mut mib: [libc::c_int; 4] = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    let mut info: libc::kinfo_proc = unsafe { mem::zeroed() };
    let mut size = mem::size_of::<libc::kinfo_proc>();

    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            &mut info as *mut _ as *mut libc::c_void,
            &mut size,
            ptr::null_mut(),
            0,
        )
    };

    if ret != 0 || size == 0 {
        return None;
    }

    Some((info.kp_proc.p_flag & P_TRACED) != 0)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(raw) => matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "enabled" | "on"
        ),
        Err(_) => default,
    }
}
