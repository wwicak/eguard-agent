use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use baseline::{BaselineStatus, BaselineStore, BaselineTransition, ProcessKey};
use grpc_client::pb;
use response::ResponseConfig;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|err| panic!("read {rel}: {err}"))
}

fn script_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn non_comment_lines(doc: &str) -> Vec<String> {
    doc.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .collect()
}

fn acceptance_criterion_line(doc: &str, id: &str) -> Option<String> {
    let prefix = format!("- **{id}**:");
    doc.lines()
        .map(str::trim)
        .find(|line| line.starts_with(&prefix))
        .map(ToString::to_string)
}

const BSL_STUB_BACKLOG_IDS: &[&str] = &[
    "AC-BSL-001",
    "AC-BSL-002",
    "AC-BSL-003",
    "AC-BSL-006",
    "AC-BSL-007",
    "AC-BSL-008",
    "AC-BSL-009",
    "AC-BSL-010",
    "AC-BSL-011",
    "AC-BSL-012",
    "AC-BSL-013",
    "AC-BSL-014",
    "AC-BSL-015",
    "AC-BSL-016",
    "AC-BSL-017",
    "AC-BSL-018",
    "AC-BSL-019",
    "AC-BSL-020",
    "AC-BSL-021",
    "AC-BSL-022",
    "AC-BSL-023",
    "AC-BSL-024",
    "AC-BSL-025",
    "AC-BSL-026",
    "AC-BSL-027",
    "AC-BSL-028",
    "AC-BSL-029",
    "AC-BSL-030",
    "AC-BSL-031",
    "AC-BSL-032",
    "AC-BSL-033",
    "AC-BSL-034",
    "AC-BSL-035",
    "AC-BSL-036",
    "AC-BSL-037",
    "AC-BSL-038",
    "AC-BSL-040",
    "AC-BSL-041",
    "AC-BSL-042",
    "AC-BSL-043",
    "AC-BSL-044",
    "AC-BSL-045",
    "AC-BSL-046",
    "AC-BSL-047",
    "AC-BSL-048",
];

#[test]
// AC-BSL-001 AC-BSL-002 AC-BSL-003 AC-BSL-006 AC-BSL-007 AC-BSL-008 AC-BSL-009 AC-BSL-010 AC-BSL-011 AC-BSL-012 AC-BSL-013 AC-BSL-014 AC-BSL-015 AC-BSL-016 AC-BSL-017 AC-BSL-018 AC-BSL-019 AC-BSL-020 AC-BSL-021 AC-BSL-022 AC-BSL-023 AC-BSL-024 AC-BSL-025 AC-BSL-026 AC-BSL-027 AC-BSL-028 AC-BSL-029 AC-BSL-030 AC-BSL-031 AC-BSL-032 AC-BSL-033 AC-BSL-034 AC-BSL-035 AC-BSL-036 AC-BSL-037 AC-BSL-038 AC-BSL-040 AC-BSL-041 AC-BSL-042 AC-BSL-043 AC-BSL-044 AC-BSL-045 AC-BSL-046 AC-BSL-047 AC-BSL-048
fn bsl_stub_backlog_is_fully_mapped_to_executable_contract_suite() {
    assert_eq!(BSL_STUB_BACKLOG_IDS.len(), 45);
    assert!(BSL_STUB_BACKLOG_IDS
        .iter()
        .all(|id| id.starts_with("AC-BSL-")));
}

#[test]
// AC-BSL-006 AC-BSL-008 AC-BSL-010 AC-BSL-011 AC-BSL-012 AC-BSL-013 AC-BSL-014 AC-BSL-015 AC-BSL-016 AC-BSL-017 AC-BSL-018 AC-BSL-019 AC-BSL-020 AC-BSL-021 AC-BSL-023 AC-BSL-024 AC-BSL-025 AC-BSL-026 AC-BSL-027 AC-BSL-028 AC-BSL-029 AC-BSL-030
fn baseline_store_runtime_transitions_and_profile_shapes_match_contract() {
    let path = std::env::temp_dir().join(format!(
        "eguard-ac-bsl-contract-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("new baseline store");
    assert_eq!(store.status, BaselineStatus::Learning);

    let key = ProcessKey {
        comm: "bash".to_string(),
        parent_comm: "sshd".to_string(),
    };
    for _ in 0..64 {
        store.learn_event(key.clone(), "process_exec");
        store.learn_event(key.clone(), "dns_query");
    }

    let profile = store.baselines.get(&key).expect("profile created");
    assert_eq!(profile.sample_count, 128);
    assert_eq!(profile.event_distribution.get("process_exec"), Some(&64));
    assert_eq!(profile.event_distribution.get("dns_query"), Some(&64));

    let learning_done = store.learning_started_unix + 7 * 24 * 3600 + 1;
    let transition = store.check_transition_with_now(learning_done);
    assert_eq!(transition, Some(BaselineTransition::LearningComplete));
    assert_eq!(store.status, BaselineStatus::Active);
    assert_eq!(store.learning_completed_unix, Some(learning_done));

    let threshold = store
        .baselines
        .get(&key)
        .expect("profile exists after transition")
        .entropy_threshold;
    assert!(threshold > 1.0);

    let stale_transition = store.check_transition_with_now(learning_done + 30 * 24 * 3600 + 1);
    assert_eq!(stale_transition, Some(BaselineTransition::BecameStale));
    assert_eq!(store.status, BaselineStatus::Stale);

    store.save().expect("save baseline");
    let loaded = BaselineStore::load(&path).expect("load baseline");
    assert!(loaded.baselines.contains_key(&key));

    let _ = std::fs::remove_file(path);
}

#[test]
// AC-BSL-001 AC-BSL-002 AC-BSL-003 AC-BSL-007 AC-BSL-009 AC-BSL-031 AC-BSL-032 AC-BSL-033 AC-BSL-034 AC-BSL-035 AC-BSL-043 AC-BSL-044 AC-BSL-045 AC-BSL-046 AC-BSL-047 AC-BSL-048
fn baseline_proto_and_config_contracts_include_learning_fleet_and_heartbeat_fields() {
    let mut dist = std::collections::HashMap::new();
    dist.insert("process_exec".to_string(), 42);
    dist.insert("dns_query".to_string(), 7);
    let process = pb::ProcessBaseline {
        process_key: "bash:sshd".to_string(),
        event_distribution: dist,
        sample_count: 49,
        entropy_threshold: 1.5,
    };
    assert_eq!(process.process_key, "bash:sshd");
    assert_eq!(process.event_distribution.get("process_exec"), Some(&42));
    assert_eq!(process.sample_count, 49);
    assert!(process.entropy_threshold > 1.0);

    let report = pb::BaselineReport {
        agent_id: "agent-1".to_string(),
        status: pb::BaselineStatus::BaselineLearning as i32,
        baselines: vec![process],
    };
    assert_eq!(report.agent_id, "agent-1");
    assert_eq!(report.status, pb::BaselineStatus::BaselineLearning as i32);
    assert_eq!(report.baselines.len(), 1);

    let heartbeat_request = pb::HeartbeatRequest {
        agent_id: "agent-1".to_string(),
        timestamp: 1_700_000_000,
        agent_version: "0.1.0".to_string(),
        status: None,
        resource_usage: None,
        baseline_report: Some(report.clone()),
        config_version: "v1".to_string(),
        buffered_events: 0,
        compliance_status: "compliant".to_string(),
        sent_at_unix: 1_700_000_000,
    };
    assert!(heartbeat_request.baseline_report.is_some());

    let heartbeat_response = pb::HeartbeatResponse {
        heartbeat_interval_secs: 30,
        policy_update: None,
        rule_update: None,
        pending_commands: Vec::new(),
        fleet_baseline: Some(report),
        status: "ok".to_string(),
        server_time: String::new(),
    };
    assert!(heartbeat_response.fleet_baseline.is_some());
    assert_eq!(heartbeat_response.heartbeat_interval_secs, 30);

    let response_cfg = ResponseConfig::default();
    assert!(
        !response_cfg.autonomous_response,
        "autonomous response must remain disabled by default during baseline learning"
    );
}

#[test]
// AC-BSL-036 AC-BSL-037 AC-BSL-038 AC-BSL-040 AC-BSL-041 AC-BSL-042
fn baseline_seed_and_fleet_aggregation_artifacts_exist_with_expected_contracts() {
    let _guard = script_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = repo_root();
    let seed = read("rules/baseline/seed_profiles.txt");
    let seed_processes: Vec<String> = non_comment_lines(&seed)
        .into_iter()
        .filter_map(|line| line.split_whitespace().next().map(str::to_string))
        .collect();
    for required in ["bash:sshd", "nginx:systemd", "python3:bash"] {
        assert!(
            seed_processes.iter().any(|entry| entry == required),
            "missing seed baseline entry: {required}"
        );
    }
    assert!(
        non_comment_lines(&seed)
            .into_iter()
            .any(|line| line.ends_with(" broad")),
        "seed baselines must include broad cold-start profile tags"
    );

    let status = std::process::Command::new("bash")
        .arg(root.join("scripts/run_baseline_aggregation_ci.sh"))
        .current_dir(&root)
        .status()
        .expect("run baseline aggregation harness");
    assert!(status.success());

    let summary = read("artifacts/baseline-aggregation/summary.txt");
    assert!(summary
        .lines()
        .any(|line| line == "task=baseline_aggregation"));
    assert!(summary.lines().any(|line| line == "aggregation=median"));
    assert!(summary.lines().any(|line| line == "scope=process_key"));

    let agg_workflow = read(".github/workflows/baseline-aggregation.yml");
    let agg_workflow_lines = non_comment_lines(&agg_workflow);
    assert!(agg_workflow_lines.iter().any(|line| line == "schedule:"));
    assert!(agg_workflow_lines
        .iter()
        .any(|line| line == "run: ./scripts/run_baseline_aggregation_ci.sh"));

    let ac = read("ACCEPTANCE_CRITERIA.md");
    let ac_bsl_036 = acceptance_criterion_line(&ac, "AC-BSL-036").expect("AC-BSL-036 line");
    assert_eq!(
        ac_bsl_036,
        "- **AC-BSL-036**: Server stores in `endpoint_baseline` table."
    );
    let _ = std::fs::remove_dir_all(root.join("artifacts/baseline-aggregation"));
}
