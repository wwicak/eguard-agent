use super::*;

#[test]
// AC-GRP-090
fn transport_mode_parsing_matches_expected_values() {
    assert!(matches!(
        TransportMode::from_str("grpc"),
        TransportMode::Grpc
    ));
    assert!(matches!(
        TransportMode::from_str("tonic"),
        TransportMode::Grpc
    ));
    assert!(matches!(
        TransportMode::from_str("http"),
        TransportMode::Http
    ));
    assert!(matches!(
        TransportMode::from_str("anything-else"),
        TransportMode::Http
    ));
}
