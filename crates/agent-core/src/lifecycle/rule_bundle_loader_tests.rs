use super::*;
use detection::DetectionEngine;

#[test]
fn yara_files_load_without_per_file_sleep() {
    let dir = std::env::temp_dir().join(format!("eguard-rafix-yara-load-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for i in 0..3 {
        std::fs::write(dir.join(format!("{i}.yar")), format!("rule eguard_fixture_{i} {{\n strings:\n  $x = \"fixture\"\n condition:\n  $x at 0 and filesize <= 128\n}}\n")).unwrap();
    }
    let mut engine = DetectionEngine::default_with_rules();
    let start = std::time::Instant::now();
    assert_eq!(load_yara_rules_recursive(&mut engine, &dir), 3);
    let elapsed = start.elapsed();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "three trivial files took {elapsed:?}"
    );
}
