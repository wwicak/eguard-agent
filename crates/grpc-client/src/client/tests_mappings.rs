use super::*;
use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
// AC-GRP-021 AC-GRP-022 AC-GRP-023
fn event_type_mapping_supports_aliases_and_safe_default() {
    assert_eq!(map_event_type("process_exec"), pb::EventType::ProcessExec);
    assert_eq!(map_event_type("exec"), pb::EventType::ProcessExec);
    assert_eq!(map_event_type("file"), pb::EventType::FileOpen);
    assert_eq!(map_event_type("tcp"), pb::EventType::TcpConnect);
    assert_eq!(map_event_type("dns"), pb::EventType::DnsQuery);
    assert_eq!(map_event_type("module"), pb::EventType::ModuleLoad);
    assert_eq!(map_event_type("login"), pb::EventType::UserLogin);
    assert_eq!(map_event_type("alert"), pb::EventType::Alert);

    assert_eq!(
        map_event_type("unrecognized-event"),
        pb::EventType::ProcessExec
    );
}

#[test]
// AC-GRP-043 AC-GRP-044
fn command_type_mapping_covers_all_enums_and_defaults_to_run_scan() {
    assert_eq!(
        map_command_type(pb::CommandType::IsolateHost as i32),
        "isolate_host"
    );
    assert_eq!(
        map_command_type(pb::CommandType::UnisolateHost as i32),
        "unisolate_host"
    );
    assert_eq!(
        map_command_type(pb::CommandType::RunScan as i32),
        "run_scan"
    );
    assert_eq!(
        map_command_type(pb::CommandType::UpdateRules as i32),
        "update_rules"
    );
    assert_eq!(
        map_command_type(pb::CommandType::ForensicsCollect as i32),
        "forensics_collect"
    );
    assert_eq!(
        map_command_type(pb::CommandType::ConfigChange as i32),
        "config_change"
    );
    assert_eq!(
        map_command_type(pb::CommandType::RestoreQuarantine as i32),
        "restore_quarantine"
    );
    assert_eq!(
        map_command_type(pb::CommandType::Uninstall as i32),
        "uninstall"
    );
    assert_eq!(
        map_command_type(pb::CommandType::EmergencyRulePush as i32),
        "emergency_rule_push"
    );

    assert_eq!(map_command_type(9999), "run_scan");
}

#[test]
// AC-GRP-051 AC-GRP-052
fn response_action_mapping_accepts_aliases_and_defaults_to_kill_process() {
    assert_eq!(map_response_action("kill"), pb::ResponseAction::KillProcess);
    assert_eq!(
        map_response_action("kill_process"),
        pb::ResponseAction::KillProcess
    );
    assert_eq!(
        map_response_action("kill_tree"),
        pb::ResponseAction::KillTree
    );
    assert_eq!(
        map_response_action("quarantine"),
        pb::ResponseAction::QuarantineFile
    );
    assert_eq!(
        map_response_action("quarantine_file"),
        pb::ResponseAction::QuarantineFile
    );
    assert_eq!(
        map_response_action("block_execution"),
        pb::ResponseAction::BlockExecution
    );
    assert_eq!(
        map_response_action("block_connection"),
        pb::ResponseAction::BlockConnection
    );
    assert_eq!(
        map_response_action("capture_script"),
        pb::ResponseAction::CaptureScript
    );
    assert_eq!(
        map_response_action("network_isolate"),
        pb::ResponseAction::NetworkIsolate
    );

    assert_eq!(
        map_response_action("something-unknown"),
        pb::ResponseAction::KillProcess
    );
}

#[test]
// AC-GRP-051
fn response_confidence_mapping_accepts_expected_variants() {
    assert_eq!(
        map_response_confidence("definite"),
        pb::ResponseConfidence::Definite
    );
    assert_eq!(
        map_response_confidence("very_high"),
        pb::ResponseConfidence::VeryHigh
    );
    assert_eq!(
        map_response_confidence("very-high"),
        pb::ResponseConfidence::VeryHigh
    );
    assert_eq!(
        map_response_confidence("high"),
        pb::ResponseConfidence::High
    );
    assert_eq!(
        map_response_confidence("medium"),
        pb::ResponseConfidence::Medium
    );

    assert_eq!(
        map_response_confidence("not-a-confidence"),
        pb::ResponseConfidence::Medium
    );
}

#[test]
// AC-WIRE-006 AC-WIRE-007 AC-WIRE-008 AC-WIRE-009 AC-WIRE-010
fn response_confidence_mapping_handles_low_none_case_whitespace() {
    assert_eq!(
        map_response_confidence("low"),
        pb::ResponseConfidence::Low
    );
    assert_eq!(
        map_response_confidence("none"),
        pb::ResponseConfidence::None
    );
    assert_eq!(
        map_response_confidence("very_high"),
        pb::ResponseConfidence::VeryHigh
    );
    assert_eq!(
        map_response_confidence("VERY_HIGH"),
        pb::ResponseConfidence::VeryHigh
    );
    assert_eq!(
        map_response_confidence("  high  "),
        pb::ResponseConfidence::High
    );
    assert_eq!(
        map_response_confidence("unknown-value"),
        pb::ResponseConfidence::Medium
    );
}

#[test]
// AC-GRP-042 AC-GRP-043
fn server_command_conversion_uses_command_type_mapping() {
    let pb_command = pb::ServerCommand {
        command_id: "cmd-22".to_string(),
        command_type: pb::CommandType::RestoreQuarantine as i32,
        ..pb::ServerCommand::default()
    };

    let out = from_pb_server_command(pb_command);
    assert_eq!(out.command_id, "cmd-22");
    assert_eq!(out.command_type, "restore_quarantine");
    assert_eq!(out.payload_json, "");
}

#[test]
// AC-PKG-027
fn default_agent_version_prefers_environment_override() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::set_var("EGUARD_AGENT_VERSION", "9.9.9");
    assert_eq!(default_agent_version(), "9.9.9");
    std::env::remove_var("EGUARD_AGENT_VERSION");
    assert_eq!(default_agent_version(), env!("CARGO_PKG_VERSION"));
}
