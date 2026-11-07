use detection::{compile_sigma_rule, TelemetryEvent};

#[test]
fn sigma_matcher_throughput_reference_workload() {
    let rule = compile_sigma_rule("title: throughput\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: /bash\n    CommandLine|contains: ' --sensitive-flag '\n  condition: selection\n").unwrap();
    let event = |command: &str| -> TelemetryEvent {
        serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":"ProcessExec","pid":42,"ppid":1,"uid":1000,
            "process":"bash","parent_process":"test","session_id":42,"file_path":"/usr/bin/bash","file_write":false,
            "command_line":command,"container_escape":false,"container_privileged":false})).unwrap()
    };
    let positive = event("bash --sensitive-flag payload");
    let negative = event("bash nightly.sh");
    let predicate = &rule.stages[0].predicate;
    // Warm the regex crate's thread-local scratch storage before measurement.
    assert!(predicate.matches(&positive));
    assert!(!predicate.matches(&negative));
    let start = std::time::Instant::now();
    let mut hits = 0;
    for _ in 0..100_000 {
        hits += std::hint::black_box(predicate.matches(std::hint::black_box(&positive))) as usize;
        hits += std::hint::black_box(predicate.matches(std::hint::black_box(&negative))) as usize;
    }
    assert_eq!(hits, 100_000);
    println!(
        "SIGMA_THROUGHPUT events=200000 hits={hits} events_per_sec={:.0}",
        200000.0 / start.elapsed().as_secs_f64()
    );
}
