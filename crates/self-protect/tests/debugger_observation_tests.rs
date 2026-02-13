use self_protect::{
    detect_debugger, parse_tracer_pid, sample_timing_cycles, DebuggerCheckConfig, DebuggerSignal,
};

#[test]
// AC-ATP-007
fn parse_tracer_pid_returns_none_when_field_missing_or_invalid() {
    assert_eq!(parse_tracer_pid("Name:\ttest\nState:\tR\n"), None);
    assert_eq!(parse_tracer_pid("TracerPid:\tinvalid\n"), None);
}

#[test]
// AC-ATP-006
fn debugger_detection_disabled_probes_produces_no_signals() {
    let config = DebuggerCheckConfig {
        enable_tracer_pid_probe: false,
        enable_timing_probe: false,
        ..DebuggerCheckConfig::default()
    };
    let observation = detect_debugger(&config);
    assert!(!observation.detected());
    assert!(observation.signals.is_empty());
    assert!(observation.signal_codes().is_empty());
}

#[test]
fn debugger_signal_code_and_display_are_stable() {
    let signal = DebuggerSignal::TimingAnomaly {
        observed_cycles: 200,
        threshold_cycles: 100,
    };
    assert_eq!(signal.code(), "timing_anomaly");
    let rendered = signal.to_string();
    assert!(rendered.contains("observed=200"));
    assert!(rendered.contains("threshold=100"));
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[test]
// AC-ATP-006
fn sample_timing_cycles_handles_zero_iterations() {
    assert_eq!(sample_timing_cycles(0), Some(0));
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[test]
fn sample_timing_cycles_returns_nonzero_for_workload() {
    let observed = sample_timing_cycles(50_000).expect("timing sample");
    assert!(observed > 0);
}
