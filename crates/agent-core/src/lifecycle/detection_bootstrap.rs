use std::path::Path;

use detection::{DetectionEngine, KillChainTemplate, RansomwarePolicy, TemplatePredicate};
use tracing::{info, warn};

pub(super) fn build_detection_engine() -> DetectionEngine {
    let mut detection = DetectionEngine::default_with_rules();
    seed_ioc_hashes(&mut detection);
    seed_ioc_domains(&mut detection);
    seed_ioc_ips(&mut detection);
    seed_string_signatures(&mut detection);
    seed_sigma_rules(&mut detection);
    seed_yara_rules(&mut detection);
    seed_kill_chain_templates(&mut detection);
    load_ioc_files(&mut detection);
    detection
}

pub(super) fn build_detection_engine_with_ransomware_policy(
    policy: RansomwarePolicy,
) -> DetectionEngine {
    let mut detection = DetectionEngine::default_with_rules();
    detection.layer4 = detection::Layer4Engine::with_capacity_and_policy(
        300,
        8_192,
        32_768,
        policy,
    );
    seed_ioc_hashes(&mut detection);
    seed_ioc_domains(&mut detection);
    seed_ioc_ips(&mut detection);
    seed_string_signatures(&mut detection);
    seed_sigma_rules(&mut detection);
    seed_yara_rules(&mut detection);
    seed_kill_chain_templates(&mut detection);
    load_ioc_files(&mut detection);
    detection
}

// ── Layer 1: IOC Hashes ─────────────────────────────────────────
fn seed_ioc_hashes(detection: &mut DetectionEngine) {
    detection.layer1.load_hashes([
        // EICAR test file SHA-256
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
        // Placeholder for real malware hashes (loaded from rules/ioc/ at runtime)
        "deadbeef".to_string(),
    ]);
}

// ── Layer 1: IOC Domains ────────────────────────────────────────
fn seed_ioc_domains(detection: &mut DetectionEngine) {
    detection.layer1.load_domains([
        "known-c2.example.com".to_string(),
        "evil-c2-domain.example.com".to_string(),
        // Common test/simulation C2 domains
        "malware-callback.example.net".to_string(),
    ]);
}

// ── Layer 1: IOC IPs ────────────────────────────────────────────
fn seed_ioc_ips(detection: &mut DetectionEngine) {
    detection.layer1.load_ips([
        // RFC 5737 documentation ranges (used for testing)
        "198.51.100.10".to_string(),
        "203.0.113.10".to_string(),
        // Feodo Tracker / known C2 placeholder
        "192.0.2.1".to_string(),
    ]);
}

// ── Layer 1: Aho-Corasick String Signatures ─────────────────────
fn seed_string_signatures(detection: &mut DetectionEngine) {
    detection.layer1.load_string_signatures([
        // Download-and-execute patterns
        "curl|bash".to_string(),
        "curl | bash".to_string(),
        "wget|bash".to_string(),
        "wget | bash".to_string(),
        "curl|sh".to_string(),
        "wget|sh".to_string(),
        // Scripting interpreter execution
        "python -c".to_string(),
        "python3 -c".to_string(),
        "perl -e".to_string(),
        "ruby -e".to_string(),
        "powershell -enc".to_string(),
        "powershell -e ".to_string(),
        // Reverse shell patterns
        ">& /dev/tcp/".to_string(),
        "bash -i".to_string(),
        "nc -e /bin".to_string(),
        "ncat -e /bin".to_string(),
        "mkfifo /tmp/".to_string(),
        // Obfuscation patterns
        "base64 -d".to_string(),
        "base64 --decode".to_string(),
        // Privilege escalation / credential access
        "/etc/shadow".to_string(),
        "/etc/sudoers".to_string(),
        "passwd --stdin".to_string(),
        // Kernel module loading
        "insmod ".to_string(),
        "modprobe ".to_string(),
        // Persistence
        "crontab ".to_string(),
        "systemctl enable".to_string(),
        // Lateral movement
        "ssh root@".to_string(),
        // Data exfiltration indicators
        "curl -x post".to_string(),
        "curl --upload".to_string(),
        // Crypto mining
        "xmrig".to_string(),
        "stratum+tcp://".to_string(),
        "stratum+ssl://".to_string(),
        "minerd".to_string(),
        "cpuminer".to_string(),
        "cryptonight".to_string(),
        // Download to /tmp
        "-o /tmp/".to_string(),
        "-O /tmp/".to_string(),
        // Pipe to interpreter (with URL gap)
        "| bash".to_string(),
        "| sh".to_string(),
        "|bash".to_string(),
        "|sh".to_string(),
        // Anti-forensics
        "rm -rf /var/log".to_string(),
        "history -c".to_string(),
        "shred ".to_string(),
    ]);
}

// ── Layer 2: SIGMA Temporal Rules ───────────────────────────────
fn seed_sigma_rules(detection: &mut DetectionEngine) {
    let rules: &[(&str, &str)] = &[
        ("builtin_webshell", SIGMA_WEBSHELL),
        ("builtin_reverse_shell", SIGMA_REVERSE_SHELL),
        ("builtin_download_exec", SIGMA_DOWNLOAD_EXEC),
        ("builtin_privesc", SIGMA_PRIVESC),
        ("builtin_kernel_module", SIGMA_KERNEL_MODULE),
        ("builtin_persistence", SIGMA_PERSISTENCE),
        ("builtin_lateral_movement", SIGMA_LATERAL_MOVEMENT),
        ("builtin_sensitive_file", SIGMA_SENSITIVE_FILE),
        ("builtin_data_exfil", SIGMA_DATA_EXFIL),
    ];

    let mut loaded = 0usize;
    for (label, yaml) in rules {
        match detection.load_sigma_rule_yaml(yaml) {
            Ok(_) => loaded += 1,
            Err(err) => warn!(rule = %label, error = %err, "failed loading built-in SIGMA rule"),
        }
    }

    // Load rules from rules/sigma/ directory
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

// ── Webshell: web server spawns shell that makes outbound connection ──
const SIGMA_WEBSHELL: &str = r#"
title: eguard_builtin_webshell
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash, sh, dash, zsh, python, python3, perl, php]
      parent_any_of: [nginx, apache2, httpd, caddy, lighttpd, php-fpm]
      within_secs: 30
    - event_class: network_connect
      dst_port_not_in: [80, 443]
      within_secs: 10
"#;

// ── Reverse shell: bash with /dev/tcp redirect or nc/ncat ──
const SIGMA_REVERSE_SHELL: &str = r#"
title: eguard_builtin_reverse_shell
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash, sh, dash, zsh]
      within_secs: 60
    - event_class: network_connect
      dst_port_not_in: [80, 443, 22, 53, 8080, 8443]
      within_secs: 5
"#;

// ── Download & execute: curl/wget followed by shell ──
const SIGMA_DOWNLOAD_EXEC: &str = r#"
title: eguard_builtin_download_exec
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [curl, wget]
      within_secs: 60
    - event_class: process_exec
      process_any_of: [bash, sh, python, python3, perl, chmod]
      within_secs: 10
"#;

// ── Privilege escalation: non-root process chain to root ──
const SIGMA_PRIVESC: &str = r#"
title: eguard_builtin_privesc
detection:
  sequence:
    - event_class: process_exec
      uid_ne: 0
      within_secs: 60
    - event_class: process_exec
      uid_eq: 0
      within_secs: 20
"#;

// ── Suspicious kernel module load ──
const SIGMA_KERNEL_MODULE: &str = r#"
title: eguard_builtin_kernel_module
detection:
  sequence:
    - event_class: module_load
      within_secs: 300
"#;

// ── Persistence via cron or systemd ──
const SIGMA_PERSISTENCE: &str = r#"
title: eguard_builtin_persistence
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [crontab, systemctl, at]
      within_secs: 120
    - event_class: file_open
      within_secs: 10
"#;

// ── Lateral movement: SSH or SMB ──
const SIGMA_LATERAL_MOVEMENT: &str = r#"
title: eguard_builtin_lateral_movement
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [ssh, scp, rsync, smbclient, psexec, impacket]
      within_secs: 120
    - event_class: network_connect
      within_secs: 10
"#;

// ── Sensitive file access ──
const SIGMA_SENSITIVE_FILE: &str = r#"
title: eguard_builtin_sensitive_file_access
detection:
  sequence:
    - event_class: file_open
      uid_ne: 0
      within_secs: 300
"#;

// ── Data exfiltration: file read followed by outbound POST ──
const SIGMA_DATA_EXFIL: &str = r#"
title: eguard_builtin_data_exfil
detection:
  sequence:
    - event_class: file_open
      within_secs: 60
    - event_class: network_connect
      dst_port_not_in: [22, 53]
      within_secs: 15
"#;

// ── Layer 3: YARA Rules ─────────────────────────────────────────
fn seed_yara_rules(detection: &mut DetectionEngine) {
    const YARA_RULES: &str = r#"
rule eguard_builtin_test_marker {
  strings:
    $marker = "eguard-malware-test-marker"
  condition:
    $marker
}

rule eguard_eicar_test {
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}" ascii
  condition:
    $eicar
}
"#;

    let mut loaded = 0usize;
    match detection.load_yara_rules_str(YARA_RULES) {
        Ok(count) => loaded += count,
        Err(err) => warn!(error = %err, "failed loading built-in YARA rules"),
    }

    let rules_dir = Path::new("rules/yara");
    if rules_dir.exists() {
        match detection.load_yara_rules_from_dir(rules_dir) {
            Ok(count) => loaded += count,
            Err(err) => {
                warn!(error = %err, path = %rules_dir.display(), "failed loading YARA rules from directory")
            }
        }
    }

    info!(loaded_yara_rules = loaded, "YARA rules initialized");
}

// ── Layer 4: Kill Chain Templates ───────────────────────────────
fn seed_kill_chain_templates(detection: &mut DetectionEngine) {
    use detection::util::set_of;

    // Data theft chain: sensitive file read → outbound connection
    detection.layer4.add_template(KillChainTemplate {
        name: "killchain_data_theft".to_string(),
        stages: vec![
            TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: true,
                require_ransomware_write_burst: false,
            },
            TemplatePredicate {
                process_any_of: Some(set_of(["curl", "wget", "python", "python3", "nc", "ncat"])),
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: true,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
            },
        ],
        max_depth: 6,
        max_inter_stage_secs: 60,
    });

    // Lateral movement chain: SSH/SCP connection
    detection.layer4.add_template(KillChainTemplate {
        name: "killchain_lateral_ssh".to_string(),
        stages: vec![
            TemplatePredicate {
                process_any_of: Some(set_of(["ssh", "scp", "rsync"])),
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
            },
            TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: true,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
            },
        ],
        max_depth: 4,
        max_inter_stage_secs: 30,
    });

    // Reverse shell chain: shell → outbound non-standard port
    detection.layer4.add_template(KillChainTemplate {
        name: "killchain_reverse_shell".to_string(),
        stages: vec![
            TemplatePredicate {
                process_any_of: Some(set_of(["bash", "sh", "dash", "zsh"])),
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
            },
            TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: true,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
            },
        ],
        max_depth: 4,
        max_inter_stage_secs: 10,
    });
}

// ── Load IOC files from rules/ioc/ directory ────────────────────
fn load_ioc_files(detection: &mut DetectionEngine) {
    let ioc_dir = Path::new("rules/ioc");
    if !ioc_dir.exists() {
        return;
    }

    // hashes.txt — one SHA-256 per line
    let hashes_path = ioc_dir.join("hashes.txt");
    if hashes_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&hashes_path) {
            let hashes: Vec<String> = content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            let count = hashes.len();
            detection.layer1.load_hashes(hashes);
            if count > 0 {
                info!(count, path = %hashes_path.display(), "loaded IOC hashes from file");
            }
        }
    }

    // domains.txt — one domain per line
    let domains_path = ioc_dir.join("domains.txt");
    if domains_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&domains_path) {
            let domains: Vec<String> = content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            let count = domains.len();
            detection.layer1.load_domains(domains);
            if count > 0 {
                info!(count, path = %domains_path.display(), "loaded IOC domains from file");
            }
        }
    }

    // ips.txt — one IP per line
    let ips_path = ioc_dir.join("ips.txt");
    if ips_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&ips_path) {
            let ips: Vec<String> = content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            let count = ips.len();
            detection.layer1.load_ips(ips);
            if count > 0 {
                info!(count, path = %ips_path.display(), "loaded IOC IPs from file");
            }
        }
    }
}
