use super::*;

#[test]
// AC-GRP-090
fn transport_mode_parsing_matches_expected_values() {
    assert!(matches!(TransportMode::parse("grpc"), TransportMode::Grpc));
    assert!(matches!(TransportMode::parse("tonic"), TransportMode::Grpc));
    assert!(matches!(TransportMode::parse("http"), TransportMode::Http));
    assert!(matches!(
        TransportMode::parse("anything-else"),
        TransportMode::Http
    ));
}
