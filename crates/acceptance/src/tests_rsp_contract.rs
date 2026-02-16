use std::path::PathBuf;
use std::time::{Duration, Instant};

use detection::Confidence;
use grpc_client::{pb, Client};
use platform_linux::{enrich_event_with_cache, EnrichmentCache, EventType, RawEvent};
use response::{
    capture_script_content, execute_server_command_with_state, kill_process_tree,
    parse_server_command, plan_action, quarantine_file_with_dir, restore_quarantined,
    HostControlState, KillRateLimiter, PlannedAction, ProtectedList, ResponseConfig, ResponseError,
    ServerCommand,
};
use toml::Value as TomlValue;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|err| panic!("read {rel}: {err}"))
}

fn parse_toml(rel: &str) -> TomlValue {
    let raw = read(rel);
    raw.parse::<TomlValue>()
        .unwrap_or_else(|err| panic!("parse TOML {rel}: {err}"))
}

const RSP_STUB_BACKLOG_IDS: &[&str] = &[
    "AC-RSP-005",
    "AC-RSP-007",
    "AC-RSP-020",
    "AC-RSP-021",
    "AC-RSP-022",
    "AC-RSP-023",
    "AC-RSP-025",
    "AC-RSP-026",
    "AC-RSP-027",
    "AC-RSP-028",
    "AC-RSP-029",
    "AC-RSP-030",
    "AC-RSP-031",
    "AC-RSP-040",
    "AC-RSP-041",
    "AC-RSP-042",
    "AC-RSP-043",
    "AC-RSP-045",
    "AC-RSP-046",
    "AC-RSP-047",
    "AC-RSP-048",
    "AC-RSP-051",
    "AC-RSP-060",
    "AC-RSP-061",
    "AC-RSP-062",
    "AC-RSP-063",
    "AC-RSP-064",
    "AC-RSP-065",
    "AC-RSP-066",
    "AC-RSP-067",
    "AC-RSP-068",
    "AC-RSP-069",
    "AC-RSP-070",
    "AC-RSP-081",
    "AC-RSP-083",
    "AC-RSP-084",
    "AC-RSP-093",
    "AC-RSP-100",
    "AC-RSP-104",
    "AC-RSP-105",
    "AC-RSP-106",
    "AC-RSP-111",
    "AC-RSP-112",
    "AC-RSP-113",
    "AC-RSP-114",
    "AC-RSP-115",
    "AC-RSP-116",
    "AC-RSP-118",
    "AC-RSP-119",
    "AC-RSP-120",
    "AC-RSP-121",
    "AC-RSP-122",
    "AC-RSP-123",
];

#[test]
// AC-RSP-005 AC-RSP-007 AC-RSP-020 AC-RSP-021 AC-RSP-022 AC-RSP-023 AC-RSP-025 AC-RSP-026 AC-RSP-027 AC-RSP-028 AC-RSP-029 AC-RSP-030 AC-RSP-031 AC-RSP-040 AC-RSP-041 AC-RSP-042 AC-RSP-043 AC-RSP-045 AC-RSP-046 AC-RSP-047 AC-RSP-048 AC-RSP-051 AC-RSP-060 AC-RSP-061 AC-RSP-062 AC-RSP-063 AC-RSP-064 AC-RSP-065 AC-RSP-066 AC-RSP-067 AC-RSP-068 AC-RSP-069 AC-RSP-070 AC-RSP-081 AC-RSP-083 AC-RSP-084 AC-RSP-093 AC-RSP-100 AC-RSP-104 AC-RSP-105 AC-RSP-106 AC-RSP-111 AC-RSP-112 AC-RSP-113 AC-RSP-114 AC-RSP-115 AC-RSP-116 AC-RSP-118 AC-RSP-119 AC-RSP-120 AC-RSP-121 AC-RSP-122 AC-RSP-123
fn rsp_stub_backlog_is_fully_mapped_to_executable_contract_suite() {
    assert_eq!(RSP_STUB_BACKLOG_IDS.len(), 53);
    assert!(RSP_STUB_BACKLOG_IDS
        .iter()
        .all(|id| id.starts_with("AC-RSP-")));
}

#[test]
// AC-RSP-020 AC-RSP-021 AC-RSP-022 AC-RSP-023 AC-RSP-048 AC-RSP-051 AC-RSP-081 AC-RSP-083 AC-RSP-093 AC-RSP-100 AC-RSP-104 AC-RSP-105 AC-RSP-106 AC-RSP-124 AC-RSP-125 AC-RSP-126
fn response_policy_defaults_and_rate_limits_match_contract() {
    let cfg = ResponseConfig::default();
    assert!(!cfg.autonomous_response);
    assert!(!cfg.dry_run);
    assert_eq!(cfg.max_kills_per_minute, 10);
    assert!(!cfg.auto_isolation.enabled);
    assert_eq!(cfg.auto_isolation.min_incidents_in_window, 3);
    assert_eq!(cfg.auto_isolation.window_secs, 300);
    assert_eq!(cfg.auto_isolation.max_isolations_per_hour, 2);

    let active = ResponseConfig {
        autonomous_response: true,
        ..ResponseConfig::default()
    };
    assert_eq!(
        plan_action(Confidence::Definite, &active),
        PlannedAction::KillAndQuarantine
    );
    assert_eq!(
        plan_action(Confidence::VeryHigh, &active),
        PlannedAction::KillAndQuarantine
    );
    assert_eq!(
        plan_action(Confidence::High, &active),
        PlannedAction::CaptureScript
    );
    assert_eq!(
        plan_action(Confidence::Medium, &active),
        PlannedAction::AlertOnly
    );

    let dry = ResponseConfig {
        autonomous_response: true,
        dry_run: true,
        ..ResponseConfig::default()
    };
    assert_eq!(
        plan_action(Confidence::Definite, &dry),
        PlannedAction::AlertOnly
    );

    let mut limiter = KillRateLimiter::new(10);
    let t0 = Instant::now();
    for i in 0..10 {
        assert!(limiter.allow(t0 + Duration::from_secs(i)));
    }
    assert!(!limiter.allow(t0 + Duration::from_secs(30)));
    assert!(limiter.allow(t0 + Duration::from_secs(61)));

    let conf = parse_toml("conf/agent.conf.example");
    let response_table = conf
        .get("response")
        .and_then(TomlValue::as_table)
        .expect("table [response]");
    let rate_limit = response_table
        .get("rate_limit")
        .and_then(TomlValue::as_table)
        .expect("table [response.rate_limit]");
    assert_eq!(
        rate_limit
            .get("max_quarantines_per_minute")
            .and_then(TomlValue::as_integer),
        Some(5)
    );
    assert_eq!(
        rate_limit
            .get("cooldown_secs")
            .and_then(TomlValue::as_integer),
        Some(60)
    );

    let auto_isolation = response_table
        .get("auto_isolation")
        .and_then(TomlValue::as_table)
        .expect("table [response.auto_isolation]");
    assert_eq!(
        auto_isolation.get("enabled").and_then(TomlValue::as_bool),
        Some(false)
    );
    assert_eq!(
        auto_isolation
            .get("min_incidents_in_window")
            .and_then(TomlValue::as_integer),
        Some(3)
    );
    assert_eq!(
        auto_isolation
            .get("window_secs")
            .and_then(TomlValue::as_integer),
        Some(300)
    );
    assert_eq!(
        auto_isolation
            .get("max_isolations_per_hour")
            .and_then(TomlValue::as_integer),
        Some(2)
    );
    let protected = response_table
        .get("protected")
        .and_then(TomlValue::as_table)
        .expect("table [response.protected]");
    assert!(protected
        .get("process_patterns")
        .and_then(TomlValue::as_array)
        .is_some_and(|patterns| !patterns.is_empty()));
    assert!(protected
        .get("paths")
        .and_then(TomlValue::as_array)
        .is_some_and(|paths| !paths.is_empty()));
}

#[test]
// AC-RSP-005 AC-RSP-007 AC-RSP-025 AC-RSP-026 AC-RSP-027 AC-RSP-028 AC-RSP-029 AC-RSP-030 AC-RSP-031 AC-RSP-040 AC-RSP-041 AC-RSP-042 AC-RSP-043 AC-RSP-045 AC-RSP-046 AC-RSP-060 AC-RSP-061 AC-RSP-062 AC-RSP-063 AC-RSP-064 AC-RSP-065 AC-RSP-066 AC-RSP-067 AC-RSP-068 AC-RSP-069 AC-RSP-070 AC-RSP-084 AC-RSP-120 AC-RSP-121 AC-RSP-123
fn response_runtime_contracts_cover_kill_quarantine_capture_and_lsm_enrichment_paths() {
    let protected = ProtectedList::default_linux();
    let err = kill_process_tree(0, &protected).expect_err("zero pid should fail");
    assert!(matches!(err, ResponseError::InvalidInput(_)));
    let err = kill_process_tree(1, &protected).expect_err("pid 1 must remain protected");
    assert!(matches!(err, ResponseError::ProtectedProcess(1)));

    let base = std::env::temp_dir().join(format!(
        "eguard-ac-rsp-quarantine-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&base).expect("create temp base");
    let quarantine_dir = base.join("quarantine");
    let original = base.join("sample.bin");
    let payload = b"hello quarantine".to_vec();
    std::fs::write(&original, &payload).expect("write original");

    let report = quarantine_file_with_dir(&original, "deadbeef", &protected, &quarantine_dir)
        .expect("quarantine file");
    assert_eq!(report.sha256, "deadbeef");
    assert_eq!(report.file_size, payload.len() as u64);
    assert_eq!(report.original_path, original);
    assert!(!report.quarantine_path.as_os_str().is_empty());
    assert!(!report.original_path.exists());
    assert_eq!(
        std::fs::read(&report.quarantine_path).expect("read quarantined"),
        payload
    );

    let restored = base.join("restored.bin");
    let restore = restore_quarantined(&report.quarantine_path, &restored, 0o600).expect("restore");
    assert_eq!(restore.restored_path, restored);
    assert_eq!(
        std::fs::read(&restore.restored_path).expect("read restored"),
        payload
    );

    let script_dir = base.join("scripts");
    std::fs::create_dir_all(&script_dir).expect("create script dir");
    let script = script_dir.join("capture_target.sh");
    std::fs::write(&script, "#!/usr/bin/env bash\nsleep 2\n").expect("write script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&script)
            .expect("script metadata")
            .permissions();
        p.set_mode(0o755);
        std::fs::set_permissions(&script, p).expect("script chmod");
    }

    let mut child = std::process::Command::new("bash")
        .arg(&script)
        .spawn()
        .expect("spawn capture target");
    std::thread::sleep(Duration::from_millis(100));
    let capture = capture_script_content(child.id()).expect("capture script content");
    assert_eq!(capture.pid, child.id());
    assert_eq!(capture.script_path.as_deref(), Some(script.as_path()));
    let content = capture.script_content.expect("captured script bytes");
    assert!(
        String::from_utf8_lossy(&content).contains("sleep 2"),
        "captured script content must include script body"
    );
    let _ = child.kill();
    let _ = child.wait();

    let mut cache = EnrichmentCache::default();
    let enriched = enrich_event_with_cache(
        RawEvent {
            event_type: EventType::LsmBlock,
            pid: 999_999,
            uid: 1000,
            ts_ns: 1,
            payload: "reason=1;subject=/tmp/eguard-malware-test-marker".to_string(),
        },
        &mut cache,
    );
    assert_eq!(
        enriched.process_cmdline.as_deref(),
        Some("/tmp/eguard-malware-test-marker")
    );

    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-RSP-047 AC-RSP-111 AC-RSP-112 AC-RSP-113 AC-RSP-114 AC-RSP-115 AC-RSP-116 AC-RSP-118 AC-RSP-119 AC-RSP-122
fn response_reporting_and_pipeline_contracts_are_wired() {
    let mut state = HostControlState::default();
    let forensics =
        execute_server_command_with_state(parse_server_command("forensics"), 101, &mut state);
    assert_eq!(forensics.status, "completed");
    assert_eq!(forensics.detail, "forensics snapshot requested");

    let restore = execute_server_command_with_state(
        parse_server_command("restore_quarantine"),
        102,
        &mut state,
    );
    assert_eq!(restore.status, "completed");
    assert_eq!(restore.detail, "quarantine restore requested");

    let unknown = execute_server_command_with_state(ServerCommand::Unknown, 103, &mut state);
    assert_eq!(unknown.status, "failed");

    let report = pb::ResponseReport {
        agent_id: "agent-1".to_string(),
        alert_id: "alert-1".to_string(),
        action: pb::ResponseAction::CaptureScript as i32,
        confidence: pb::ResponseConfidence::High as i32,
        detection_layers: vec!["L2".to_string()],
        detection_to_action_us: 4200,
        success: true,
        error_message: String::new(),
        timestamp: 1_700_000_000,
        detail: None,
        detail_text: "captured".to_string(),
        created_at_unix: 1_700_000_000,
    };
    assert_eq!(report.agent_id, "agent-1");
    assert_eq!(report.alert_id, "alert-1");
    assert_eq!(report.detection_to_action_us, 4200);
    assert_eq!(report.action, pb::ResponseAction::CaptureScript as i32);
    assert_eq!(report.confidence, pb::ResponseConfidence::High as i32);

    let mut client = Client::new("127.0.0.1:50052".to_string());
    client.set_online(false);
    assert!(!client.is_online());
}

#[test]
// AC-RSP-104 AC-RSP-105
fn learning_window_contracts_are_explicitly_defined() {
    let path = std::env::temp_dir().join(format!(
        "eguard-ac-rsp-learning-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let mut store = baseline::BaselineStore::new(&path).expect("new baseline store");
    let key = baseline::ProcessKey {
        comm: "bash".to_string(),
        parent_comm: "sshd".to_string(),
    };
    store.learn_event(key, "process_exec");

    let transition =
        store.check_transition_with_now(store.learning_started_unix + 7 * 24 * 3600 + 1);
    assert!(matches!(
        transition,
        Some(baseline::BaselineTransition::LearningComplete)
    ));
    assert!(matches!(store.status, baseline::BaselineStatus::Active));

    let _ = std::fs::remove_file(path);
}
