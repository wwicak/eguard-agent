mod debugger;
mod engine;
mod hardening;
mod integrity;

pub use debugger::{
    detect_debugger, parse_tracer_pid, sample_timing_cycles, DebuggerCheckConfig,
    DebuggerObservation, DebuggerSignal,
};
pub use engine::{
    normalize_sha256_hex, SelfProtectConfig, SelfProtectEngine, SelfProtectReport,
    SelfProtectViolation,
};
pub use hardening::{
    apply_linux_hardening, apply_macos_hardening, capability_number, default_retained_capabilities,
    LinuxHardeningConfig, LinuxHardeningReport, LinuxHardeningStep, LinuxHardeningStepStatus,
    MacosHardeningConfig, MacosHardeningReport,
};
pub use integrity::{
    measure_executable_sections, measure_self_integrity, IntegrityMeasurement, SectionDigest,
    INTEGRITY_SECTION_SET,
};
