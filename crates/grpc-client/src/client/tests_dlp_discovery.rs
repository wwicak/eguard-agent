use crate::client::from_pb_server_command;
use crate::pb;

#[test]
fn server_command_conversion_preserves_dlp_discovery_fields() {
    let pb_command = pb::ServerCommand {
        command_id: "cmd-discovery".to_string(),
        command_type: pb::CommandType::DlpDiscovery as i32,
        params: Some(pb::server_command::Params::DlpDiscovery(
            pb::DlpDiscoveryParams {
                roots: vec!["C:/fixture".to_string()],
                approved_roots: vec!["C:/fixture".to_string()],
                allowed_extensions: vec!["txt".to_string()],
                excluded_roots: vec!["C:/fixture/excluded".to_string()],
            },
        )),
        ..pb::ServerCommand::default()
    };

    let out = from_pb_server_command(pb_command);
    assert_eq!(out.command_type, "dlp_discovery");
    assert!(out.payload_json.contains("C:/fixture"));
    assert!(out.payload_json.contains("C:/fixture/excluded"));
    assert!(out.payload_json.contains("txt"));
}
