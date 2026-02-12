use std::path::Path;

use detection::DetectionEngine;
use tracing::{info, warn};

pub(super) fn build_detection_engine() -> DetectionEngine {
    let mut detection = DetectionEngine::default_with_rules();
    seed_detection_inputs(&mut detection);
    seed_sigma_rules(&mut detection);
    seed_yara_rules(&mut detection);
    detection
}

fn seed_detection_inputs(detection: &mut DetectionEngine) {
    detection.layer1.load_hashes(["deadbeef".to_string()]);
    detection
        .layer1
        .load_domains(["known-c2.example.com".to_string()]);
    detection.layer1.load_ips(["198.51.100.10".to_string()]);
    detection.layer1.load_string_signatures([
        "curl|bash".to_string(),
        "python -c".to_string(),
        "powershell -enc".to_string(),
    ]);
}

fn seed_sigma_rules(detection: &mut DetectionEngine) {
    const BUILTIN_SIGMA_RULE: &str = r#"
title: eguard_builtin_webshell
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash, sh]
      parent_any_of: [nginx, apache2, caddy]
      within_secs: 30
    - event_class: network_connect
      dst_port_not_in: [80, 443]
      within_secs: 10
"#;

    let mut loaded = 0usize;
    match detection.load_sigma_rule_yaml(BUILTIN_SIGMA_RULE) {
        Ok(_) => loaded += 1,
        Err(err) => warn!(error = %err, "failed loading built-in SIGMA rule"),
    }

    let rules_dir = Path::new("rules/sigma");
    if rules_dir.exists() {
        match detection.load_sigma_rules_from_dir(rules_dir) {
            Ok(count) => loaded += count,
            Err(err) => {
                warn!(error = %err, path = %rules_dir.display(), "failed loading SIGMA rules from directory")
            }
        }
    }

    info!(loaded_sigma_rules = loaded, "SIGMA rules initialized");
}

fn seed_yara_rules(detection: &mut DetectionEngine) {
    const BUILTIN_YARA_RULE: &str = r#"
rule eguard_builtin_test_marker {
  strings:
    $marker = "eguard-malware-test-marker"
  condition:
    $marker
}
"#;

    let mut loaded = 0usize;
    match detection.load_yara_rules_str(BUILTIN_YARA_RULE) {
        Ok(count) => loaded += count,
        Err(err) => warn!(error = %err, "failed loading built-in YARA rule"),
    }

    let rules_dir = Path::new("rules/yara");
    if rules_dir.exists() {
        match detection.load_yara_rules_from_dir(rules_dir) {
            Ok(count) => {
                loaded += count;
            }
            Err(err) => {
                warn!(error = %err, path = %rules_dir.display(), "failed loading YARA rules from directory")
            }
        }
    }

    info!(loaded_yara_rules = loaded, "YARA rules initialized");
}
