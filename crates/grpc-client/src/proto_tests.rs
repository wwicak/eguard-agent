const AGENT_PROTO: &str = include_str!("../../../proto/eguard/v1/agent.proto");
const TELEMETRY_PROTO: &str = include_str!("../../../proto/eguard/v1/telemetry.proto");
const COMPLIANCE_PROTO: &str = include_str!("../../../proto/eguard/v1/compliance.proto");
const COMMAND_PROTO: &str = include_str!("../../../proto/eguard/v1/command.proto");
const RESPONSE_PROTO: &str = include_str!("../../../proto/eguard/v1/response.proto");

fn assert_proto_header(raw: &str) {
    assert!(raw.contains("syntax = \"proto3\";"));
    assert!(raw.contains("package eguard.v1;"));
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
// AC-GRP-020 AC-GRP-030 AC-GRP-040 AC-GRP-050
fn service_protos_declare_streaming_and_reporting_rpcs() {
    assert!(TELEMETRY_PROTO.contains("service TelemetryService"));
    assert!(TELEMETRY_PROTO.contains("rpc StreamEvents("));

    assert!(COMPLIANCE_PROTO.contains("service ComplianceService"));
    assert!(COMPLIANCE_PROTO.contains("rpc ReportCompliance("));

    assert!(COMMAND_PROTO.contains("service CommandService"));
    assert!(COMMAND_PROTO.contains("rpc CommandChannel("));

    assert!(RESPONSE_PROTO.contains("service ResponseService"));
    assert!(RESPONSE_PROTO.contains("rpc ReportResponse("));
}
