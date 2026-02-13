use self_protect::{measure_executable_sections, INTEGRITY_SECTION_SET};
use std::path::Path;

#[test]
// AC-ATP-001
fn measure_executable_sections_rejects_empty_section_list() {
    let err = measure_executable_sections(Path::new("/proc/self/exe"), &[])
        .expect_err("empty section list should fail");
    assert!(err.contains("sections list cannot be empty"));
}

#[test]
// AC-ATP-001
fn measure_executable_sections_rejects_missing_required_section() {
    let err = measure_executable_sections(Path::new("/proc/self/exe"), &[".definitely_missing"])
        .expect_err("missing section should fail");
    assert!(err.contains("required section '.definitely_missing' not found"));
}

#[test]
// AC-ATP-001
fn measure_executable_sections_preserves_requested_section_order() {
    let measurement =
        measure_executable_sections(Path::new("/proc/self/exe"), &[".rodata", ".text"])
            .expect("measure custom section ordering");

    let names = measurement
        .section_digests
        .iter()
        .map(|d| d.section.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec![".rodata", ".text"]);
    assert!(measurement
        .section_digests
        .iter()
        .all(|d| d.sha256_hex.len() == 64));
    assert!(measurement.section_digests.iter().all(|d| d.size_bytes > 0));
}

#[test]
// AC-ATP-001
fn default_integrity_section_set_matches_contract() {
    assert_eq!(INTEGRITY_SECTION_SET, [".text", ".rodata"]);
}
