use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn section<'a>(source: &'a str, start_pat: &str, end_pat: &str) -> &'a str {
    let start = source
        .find(start_pat)
        .unwrap_or_else(|| panic!("missing start pattern: {start_pat}"));
    let end_rel = source[start..]
        .find(end_pat)
        .unwrap_or_else(|| panic!("missing end pattern after {start_pat}: {end_pat}"));
    &source[start..start + end_rel]
}

fn ordered_indices(haystack: &str, patterns: &[&str]) -> Vec<usize> {
    patterns
        .iter()
        .map(|pat| {
            haystack
                .find(pat)
                .unwrap_or_else(|| panic!("missing pattern: {pat}"))
        })
        .collect()
}

#[test]
// AC-EBP-035
fn tick_pipeline_keeps_raw_enrich_detect_and_routing_stages_in_order() {
    let source =
        std::fs::read_to_string(workspace_root().join("crates/agent-core/src/lifecycle.rs"))
            .expect("read lifecycle source");

    let evaluate = section(
        &source,
        "fn evaluate_tick(&mut self, now_unix: i64) -> Result<TickEvaluation> {",
        "async fn handle_degraded_tick(&mut self, evaluation: &TickEvaluation) -> Result<()> {",
    );
    let eval_order = ordered_indices(
        evaluate,
        &[
            "self.next_raw_event(now_unix)",
            "enrich_event_with_cache(raw, &mut self.enrichment_cache)",
            "to_detection_event(&enriched, now_unix)",
            "self.detection_state.process_event(&detection_event)",
            "plan_action(confidence, &response_cfg)",
            "self.build_event_envelope(enriched.process_exe.as_deref(), now_unix)",
        ],
    );
    assert!(eval_order.windows(2).all(|w| w[0] < w[1]));

    let connected = section(
        &source,
        "async fn handle_connected_tick(",
        "async fn ensure_enrolled(&mut self) {",
    );
    assert!(connected.contains("self.report_local_action_if_needed("));
    assert!(connected.contains("self.send_event_batch(evaluation.event_envelope.clone())"));
}

#[test]
// AC-EBP-042
fn connected_tick_sends_event_batch_immediately_without_flush_gate() {
    let source =
        std::fs::read_to_string(workspace_root().join("crates/agent-core/src/lifecycle.rs"))
            .expect("read lifecycle source");

    let connected = section(
        &source,
        "async fn handle_connected_tick(",
        "async fn ensure_enrolled(&mut self) {",
    );
    let order = ordered_indices(
        connected,
        &[
            "self.send_event_batch(evaluation.event_envelope.clone())",
            "self.send_heartbeat_if_due(&evaluation.compliance.status)",
            "self.send_compliance_if_due(&evaluation.compliance)",
            "self.sync_pending_commands(now_unix)",
        ],
    );
    assert!(order.windows(2).all(|w| w[0] < w[1]));

    let send_batch = section(
        &source,
        "async fn send_event_batch(&mut self, envelope: EventEnvelope) -> Result<()> {",
        "async fn send_heartbeat_if_due(&self, compliance_status: &str) {",
    );
    assert!(send_batch.contains("batch.push(envelope);"));
    assert!(send_batch.contains("self.client.send_events(&batch).await"));
    assert!(!send_batch.contains("flush_interval_ms"));
    assert!(!send_batch.contains("tick_count %"));
}

#[test]
// AC-EBP-080 AC-EBP-081 AC-EBP-082 AC-EBP-083 AC-EBP-084 AC-EBP-086 AC-EBP-087 AC-EBP-088 AC-EBP-090
fn ebpf_resource_budget_harness_declares_required_limits_and_measurement_commands() {
    let script =
        std::fs::read_to_string(workspace_root().join("scripts/run_ebpf_resource_budget_ci.sh"))
            .expect("read eBPF budget harness script");

    for required in [
        "IDLE_CPU_PCT_LIMIT=\"0.05\"",
        "ACTIVE_CPU_PCT_LIMIT=\"0.5\"",
        "PEAK_CPU_PCT_LIMIT=\"3\"",
        "MEMORY_RSS_MB_LIMIT=\"25\"",
        "DISK_IO_KBPS_LIMIT=\"100\"",
        "BINARY_SIZE_MB_LIMIT=\"10\"",
        "STARTUP_SECONDS_LIMIT=\"2\"",
        "DETECTION_LATENCY_NS_LIMIT=\"500\"",
        "LSM_BLOCK_LATENCY_MS_LIMIT=\"1\"",
        "pidstat -p \\$(pidof agent-core) 60",
        "ps -o rss= -p \\$(pidof agent-core)",
        "wc -c < \"${BIN_PATH}\"",
        "cargo test -p detection --lib detection_latency_p99_stays_within_budget_for_reference_workload -- --exact",
        "cargo test -p platform-linux --lib parses_structured_lsm_block_payload -- --exact",
    ] {
        assert!(script.contains(required), "missing harness contract: {required}");
    }
}

#[test]
// AC-EBP-080 AC-EBP-081 AC-EBP-082 AC-EBP-083 AC-EBP-084 AC-EBP-086 AC-EBP-087 AC-EBP-088 AC-EBP-090
fn ebpf_resource_budget_workflow_runs_harness_and_publishes_artifacts() {
    let workflow = std::fs::read_to_string(
        workspace_root().join(".github/workflows/ebpf-resource-budget.yml"),
    )
    .expect("read eBPF budget workflow");

    for required in [
        "name: ebpf-resource-budget",
        "run: ./scripts/run_ebpf_resource_budget_ci.sh",
        "uses: actions/upload-artifact@v4",
        "name: ebpf-resource-budget",
        "path: artifacts/ebpf-resource-budget",
    ] {
        assert!(
            workflow.contains(required),
            "missing workflow contract: {required}"
        );
    }
}
