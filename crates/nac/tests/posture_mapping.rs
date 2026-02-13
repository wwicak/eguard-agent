use nac::{posture_from_compliance, Posture};

#[test]
// AC-NAC-005 AC-NAC-006 AC-NAC-007 AC-NAC-008
fn posture_mapping_matches_policy() {
    assert_eq!(posture_from_compliance("pass"), Posture::Compliant);
    assert_eq!(posture_from_compliance("compliant"), Posture::Compliant);
    assert_eq!(posture_from_compliance("fail"), Posture::NonCompliant);
    assert_eq!(
        posture_from_compliance("non_compliant"),
        Posture::NonCompliant
    );
    assert_eq!(posture_from_compliance("unknown"), Posture::Unknown);
}

#[test]
// AC-NAC-005 AC-NAC-008
fn posture_mapping_is_case_sensitive_for_status_input() {
    assert_eq!(posture_from_compliance("PASS"), Posture::Unknown);
    assert_eq!(posture_from_compliance("FAIL"), Posture::Unknown);
}
