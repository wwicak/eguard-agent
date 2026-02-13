use self_protect::{detect_debugger, parse_tracer_pid, DebuggerCheckConfig, DebuggerSignal};

#[test]
fn parse_tracer_pid_extracts_numeric_value() {
    let status = "Name:\ttest\nState:\tR (running)\nTracerPid:\t42\n";
    assert_eq!(parse_tracer_pid(status), Some(42));
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[test]
fn timing_probe_flags_anomaly_when_threshold_is_tiny() {
    let config = DebuggerCheckConfig {
        timing_threshold_cycles: 1,
        timing_probe_iterations: 10_000,
        enable_tracer_pid_probe: false,
        enable_timing_probe: true,
    };
    let observation = detect_debugger(&config);
    assert!(observation
        .signals
        .iter()
        .any(|signal| matches!(signal, DebuggerSignal::TimingAnomaly { .. })));
}
