#![no_main]

use grpc_client::pb;
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let _ = pb::TelemetryEvent::decode(data);
    let _ = pb::TelemetryBatch::decode(data);
    let _ = pb::HeartbeatRequest::decode(data);
    let _ = pb::HeartbeatResponse::decode(data);
    let _ = pb::ComplianceReport::decode(data);
    let _ = pb::ResponseReport::decode(data);
    let _ = pb::ServerCommand::decode(data);
});
