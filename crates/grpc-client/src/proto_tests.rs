const AGENT_PROTO: &str = include_str!("../../../proto/eguard/v1/agent.proto");
const TELEMETRY_PROTO: &str = include_str!("../../../proto/eguard/v1/telemetry.proto");
const COMPLIANCE_PROTO: &str = include_str!("../../../proto/eguard/v1/compliance.proto");
const COMMAND_PROTO: &str = include_str!("../../../proto/eguard/v1/command.proto");
const RESPONSE_PROTO: &str = include_str!("../../../proto/eguard/v1/response.proto");

fn assert_proto_header(raw: &str) {
    assert!(raw.contains("syntax = \"proto3\";"));
    assert!(raw.contains("package eguard.v1;"));
}

fn assert_contains_all(raw: &str, expected: &[&str]) {
    for needle in expected {
        assert!(
            raw.contains(needle),
            "missing protobuf contract fragment: {needle}"
        );
    }
}

#[test]
// AC-GRP-070
fn all_agent_protos_use_proto3_and_expected_package() {
    for raw in [
        AGENT_PROTO,
        TELEMETRY_PROTO,
        COMPLIANCE_PROTO,
        COMMAND_PROTO,
        RESPONSE_PROTO,
    ] {
        assert_proto_header(raw);
    }
}

#[test]
// AC-GRP-001 AC-GRP-010
fn agent_control_proto_declares_enroll_and_heartbeat_rpcs() {
    assert!(AGENT_PROTO.contains("service AgentControlService"));
    assert!(AGENT_PROTO.contains("rpc Enroll(EnrollRequest) returns (EnrollResponse);"));
    assert!(AGENT_PROTO.contains("rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);"));
}

#[test]
// AC-GRP-071 AC-GRP-076
fn agent_proto_imports_domain_protos_and_declares_eight_rpc_agent_service() {
    assert!(AGENT_PROTO.contains("import \"eguard/v1/telemetry.proto\";"));
    assert!(AGENT_PROTO.contains("import \"eguard/v1/compliance.proto\";"));
    assert!(AGENT_PROTO.contains("import \"eguard/v1/command.proto\";"));
    assert!(AGENT_PROTO.contains("import \"eguard/v1/response.proto\";"));

    assert!(AGENT_PROTO.contains("service AgentService"));
    let service_block = AGENT_PROTO
        .split("service AgentService")
        .nth(1)
        .and_then(|tail| tail.split('}').next())
        .expect("agent service block");
    assert_eq!(service_block.matches("rpc ").count(), 8);
    assert!(AGENT_PROTO.contains("rpc GetPolicy("));
    assert!(AGENT_PROTO.contains("rpc DownloadRuleBundle("));
}

#[test]
// AC-GRP-020 AC-GRP-030 AC-GRP-040 AC-GRP-050 AC-GRP-060 AC-GRP-061 AC-EBP-040 AC-EBP-043 AC-DET-142
fn service_protos_declare_streaming_and_reporting_rpcs() {
    assert!(TELEMETRY_PROTO.contains("service TelemetryService"));
    assert!(TELEMETRY_PROTO
        .contains("rpc StreamEvents(stream TelemetryBatch) returns (stream EventAck);"));

    assert!(COMPLIANCE_PROTO.contains("service ComplianceService"));
    assert!(COMPLIANCE_PROTO.contains("rpc ReportCompliance("));

    assert!(COMMAND_PROTO.contains("service CommandService"));
    assert!(COMMAND_PROTO
        .contains("rpc CommandChannel(CommandPollRequest) returns (stream ServerCommand);"));

    assert!(RESPONSE_PROTO.contains("service ResponseService"));
    assert!(RESPONSE_PROTO.contains("rpc ReportResponse("));

    assert!(AGENT_PROTO.contains("rpc GetPolicy(PolicyRequest) returns (PolicyResponse);"));
    assert!(AGENT_PROTO
        .contains("rpc DownloadRuleBundle(RuleBundleRequest) returns (stream RuleBundleChunk);"));
}

#[test]
// AC-GRP-002 AC-GRP-003 AC-GRP-004 AC-GRP-005
fn enrollment_contract_includes_capabilities_and_cert_material() {
    assert_contains_all(
        AGENT_PROTO,
        &[
            "message AgentCapabilities",
            "bool ebpf_supported",
            "bool lsm_supported",
            "bool yara_supported",
            "repeated string ebpf_programs",
            "message EnrollRequest",
            "string enrollment_token",
            "string hostname",
            "string mac_address",
            "string os_type",
            "string os_version",
            "string kernel_version",
            "string agent_version",
            "string machine_id",
            "bytes csr",
            "AgentCapabilities capabilities",
            "message EnrollResponse",
            "string agent_id",
            "bytes signed_certificate",
            "bytes ca_certificate",
            "string initial_policy",
            "string initial_rules",
            "bool require_mtls_after_enroll",
        ],
    );
}

#[test]
// AC-GRP-011 AC-GRP-012 AC-GRP-013 AC-GRP-014 AC-GRP-016 AC-GRP-017 AC-GRP-018 AC-GRP-019 AC-GRP-085 AC-DET-140 AC-DET-141
fn heartbeat_contract_includes_status_usage_policy_rule_and_baselines() {
    assert_contains_all(
        AGENT_PROTO,
        &[
            "message HeartbeatRequest",
            "string agent_id",
            "int64 timestamp",
            "string agent_version",
            "AgentStatus status",
            "ResourceUsage resource_usage",
            "BaselineReport baseline_report",
            "string config_version",
            "int64 buffered_events",
            "message AgentStatus",
            "AgentMode mode",
            "bool autonomous_response_enabled",
            "int64 active_sigma_rules",
            "int64 active_yara_rules",
            "int64 active_ioc_entries",
            "string last_detection",
            "string last_response_action",
            "enum AgentMode",
            "DEGRADED = 2",
            "message ResourceUsage",
            "double cpu_percent",
            "int64 memory_rss_bytes",
            "int64 disk_usage_bytes",
            "double events_per_second",
            "message HeartbeatResponse",
            "int32 heartbeat_interval_secs",
            "PolicyUpdate policy_update",
            "RuleUpdate rule_update",
            "repeated ServerCommand pending_commands",
            "BaselineReport fleet_baseline",
            "message PolicyUpdate",
            "string config_version",
            "string policy_json",
            "message RuleUpdate",
            "string current_version",
            "string available_version",
            "bool emergency",
            "string bundle_download_url",
            "message BaselineReport",
            "BaselineStatus status",
            "repeated ProcessBaseline baselines",
            "message ProcessBaseline",
            "string process_key",
            "map<string, int64> event_distribution",
            "int64 sample_count",
            "double entropy_threshold",
        ],
    );
}

#[test]
// AC-GRP-021 AC-GRP-022 AC-GRP-023 AC-GRP-024 AC-GRP-025 AC-GRP-026 AC-EBP-041
fn telemetry_contract_includes_batch_event_ack_enums_and_detail() {
    assert_contains_all(
        TELEMETRY_PROTO,
        &[
            "message TelemetryBatch",
            "string agent_id",
            "repeated TelemetryEvent events",
            "bool compressed",
            "bytes events_compressed",
            "message TelemetryEvent",
            "string event_id",
            "EventType event_type",
            "Severity severity",
            "int64 timestamp",
            "int64 pid",
            "int64 ppid",
            "int64 uid",
            "string comm",
            "string parent_comm",
            "oneof detail",
            "ProcessExecEvent process_exec",
            "enum EventType",
            "PROCESS_EXEC = 0",
            "FILE_OPEN = 1",
            "TCP_CONNECT = 2",
            "DNS_QUERY = 3",
            "MODULE_LOAD = 4",
            "USER_LOGIN = 5",
            "ALERT = 6",
            "enum Severity",
            "INFO = 0",
            "LOW = 1",
            "MEDIUM = 2",
            "HIGH = 3",
            "CRITICAL = 4",
            "message ProcessExecEvent",
            "string exe_path",
            "string cmdline",
            "string sha256",
            "string cgroup_id",
            "repeated string ancestors",
            "message EventAck",
            "int64 last_event_offset",
            "int64 events_accepted",
        ],
    );
}

#[test]
// AC-GRP-031 AC-GRP-032 AC-GRP-033 AC-GRP-034 AC-GRP-035
fn compliance_contract_includes_report_checks_enums_and_ack_override() {
    assert_contains_all(
        COMPLIANCE_PROTO,
        &[
            "message ComplianceReport",
            "string agent_id",
            "string policy_id",
            "string policy_version",
            "int64 checked_at",
            "repeated ComplianceCheckResult checks",
            "ComplianceStatus overall_status",
            "enum ComplianceStatus",
            "COMPLIANT = 0",
            "NON_COMPLIANT = 1",
            "ERROR = 2",
            "message ComplianceCheckResult",
            "string check_type",
            "CheckStatus status",
            "string actual_value",
            "string expected_value",
            "string detail",
            "bool auto_remediated",
            "string remediation_detail",
            "enum CheckStatus",
            "PASS = 0",
            "FAIL = 1",
            "CHECK_ERROR = 2",
            "message ComplianceAck",
            "bool accepted",
            "int32 next_check_override_secs",
        ],
    );
}

#[test]
// AC-GRP-043 AC-GRP-044 AC-GRP-045 AC-GRP-046 AC-GRP-047 AC-GRP-048 AC-GRP-049
fn command_contract_includes_command_types_and_parameter_messages() {
    assert_contains_all(
        COMMAND_PROTO,
        &[
            "enum CommandType",
            "ISOLATE_HOST = 0",
            "UNISOLATE_HOST = 1",
            "RUN_SCAN = 2",
            "UPDATE_RULES = 3",
            "FORENSICS_COLLECT = 4",
            "CONFIG_CHANGE = 5",
            "RESTORE_QUARANTINE = 6",
            "UNINSTALL = 7",
            "EMERGENCY_RULE_PUSH = 8",
            "message IsolateParams",
            "bool allow_server_connection",
            "message ScanParams",
            "repeated string paths",
            "bool yara_scan",
            "bool ioc_scan",
            "message UpdateParams",
            "string target_version",
            "string download_url",
            "string checksum",
            "message ForensicsParams",
            "bool memory_dump",
            "bool process_list",
            "bool network_connections",
            "bool open_files",
            "bool loaded_modules",
            "repeated int64 target_pids",
            "message ConfigChangeParams",
            "string config_json",
            "string config_version",
            "message RestoreQuarantineParams",
            "string sha256",
            "string original_path",
        ],
    );
}

#[test]
// AC-GRP-051 AC-GRP-052 AC-GRP-053 AC-GRP-054 AC-GRP-055 AC-GRP-056 AC-GRP-057 AC-GRP-058
fn response_contract_includes_enums_action_details_and_ack() {
    assert_contains_all(
        RESPONSE_PROTO,
        &[
            "message ResponseReport",
            "string agent_id",
            "string alert_id",
            "ResponseAction action",
            "ResponseConfidence confidence",
            "repeated string detection_layers",
            "int64 detection_to_action_us",
            "bool success",
            "string error_message",
            "int64 timestamp",
            "oneof detail",
            "enum ResponseAction",
            "KILL_PROCESS = 0",
            "KILL_TREE = 1",
            "QUARANTINE_FILE = 2",
            "BLOCK_EXECUTION = 3",
            "BLOCK_CONNECTION = 4",
            "CAPTURE_SCRIPT = 5",
            "NETWORK_ISOLATE = 6",
            "enum ResponseConfidence",
            "RESPONSE_CONFIDENCE_DEFINITE = 0",
            "RESPONSE_CONFIDENCE_VERY_HIGH = 1",
            "RESPONSE_CONFIDENCE_HIGH = 2",
            "RESPONSE_CONFIDENCE_MEDIUM = 3",
            "message KillReport",
            "int64 target_pid",
            "string target_exe",
            "repeated int64 killed_pids",
            "message QuarantineReport",
            "string original_path",
            "string quarantine_path",
            "string sha256",
            "int64 file_size",
            "string detection_rule",
            "message BlockReport",
            "string blocked_target",
            "string block_method",
            "message CaptureReport",
            "string interpreter",
            "string script_path",
            "string script_content",
            "map<string, string> environment",
            "message ResponseAck",
            "bool accepted",
            "string incident_id",
        ],
    );
}

#[test]
// AC-GRP-062 AC-GRP-063 AC-GRP-064 AC-GRP-065
fn rule_bundle_contract_includes_compression_signature_and_reload_constraints() {
    assert_contains_all(
        AGENT_PROTO,
        &[
            "message RuleBundleRequest",
            "string target_version",
            "bool emergency",
            "bool immediate",
            "message RuleBundleChunk",
            "bytes data",
            "bytes ed25519_signature",
            "bool zstd_compressed",
            "int32 chunk_size_bytes",
            "bool verified",
            "int32 reload_deadline_secs",
            "bool emergency",
            "string bundle_download_url",
        ],
    );
}

#[test]
// AC-GRP-092 AC-GRP-093 AC-GRP-094 AC-GRP-095 AC-GRP-096
fn certificate_policy_contract_covers_pinning_rotation_client_cert_and_transport_limits() {
    assert_contains_all(
        AGENT_PROTO,
        &[
            "message CertificatePolicy",
            "string pinned_ca_sha256",
            "int32 rotate_before_expiry_days",
            "bool seamless_rotation",
            "bool require_client_cert_for_all_rpcs_except_enroll",
            "int32 grpc_max_recv_msg_size_bytes",
            "int32 grpc_port",
            "CertificatePolicy certificate_policy",
        ],
    );
}

#[test]
// AC-GRP-098 AC-GRP-099
fn go_binding_contract_is_explicit_in_proto() {
    assert!(AGENT_PROTO.contains(
        "option go_package = \"gitlab.com/devaistech77/fe_eguard/go/api/agent/v1;agentv1\";"
    ));
    assert!(AGENT_PROTO.contains("pb.RegisterAgentServiceServer("));
}
