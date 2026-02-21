use crate::types::EventClass;
use crate::util::{set_of, set_u16};

use super::predicate::TemporalPredicate;
use super::rule::{TemporalRule, TemporalStage};

pub(super) fn default_rules() -> Vec<TemporalRule> {
    let web_servers = set_of(["nginx", "apache2", "httpd", "caddy"]);
    let shells = set_of(["sh", "bash", "dash", "zsh", "ksh"]);

    // --- phi_webshell ---
    let webshell = TemporalRule {
        name: "phi_webshell".to_string(),
        stages: vec![
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: Some(shells.clone()),
                    process_starts_with: None,
                    parent_any_of: Some(web_servers),
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 30,
            },
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::NetworkConnect,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: Some(set_u16([80, 443])),
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 10,
            },
        ],
    };

    // --- phi_priv_esc ---
    let priv_esc = TemporalRule {
        name: "phi_priv_esc".to_string(),
        stages: vec![
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: Some(0),
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 60,
            },
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: Some(0),
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 20,
            },
        ],
    };

    // --- phi_reverse_shell ---
    let reverse_shell = TemporalRule {
        name: "phi_reverse_shell".to_string(),
        stages: vec![
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: Some(set_of([
                        ">& /dev/tcp/",
                        "bash -i",
                        "nc -e /bin",
                        "ncat -e",
                        "socat exec",
                        "0<&196",
                    ])),
                    require_file_write: false,
                },
                within_secs: 30,
            },
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::NetworkConnect,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: Some(set_u16([80, 443])),
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 10,
            },
        ],
    };

    // --- phi_download_exec ---
    let download_exec = TemporalRule {
        name: "phi_download_exec".to_string(),
        stages: vec![
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: Some(set_of(["curl", "wget", "fetch"])),
                    process_starts_with: Some(vec![
                        "python".to_string(),
                        "perl".to_string(),
                        "ruby".to_string(),
                    ]),
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 30,
            },
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: Some(shells),
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 30,
            },
        ],
    };

    // --- phi_credential_exfil ---
    let credential_exfil = TemporalRule {
        name: "phi_credential_exfil".to_string(),
        stages: vec![
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::FileOpen,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: Some(set_of([
                        "/etc/shadow",
                        "/etc/passwd",
                        ".ssh/id_",
                        ".ssh/authorized_keys",
                        ".aws/credentials",
                        ".kube/config",
                    ])),
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 60,
            },
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::NetworkConnect,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: Some(set_u16([80, 443])),
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 60,
            },
        ],
    };

    // --- phi_persistence_install ---
    let persistence_install = TemporalRule {
        name: "phi_persistence_install".to_string(),
        stages: vec![
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::FileOpen,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: Some(set_of([
                        "/etc/cron",
                        "/etc/systemd/system/",
                        "/etc/init.d/",
                        ".bashrc",
                        ".profile",
                        "/etc/profile.d/",
                    ])),
                    command_line_contains: None,
                    require_file_write: true,
                },
                within_secs: 30,
            },
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 30,
            },
        ],
    };

    // --- phi_ssh_lateral ---
    let ssh_lateral = TemporalRule {
        name: "phi_ssh_lateral".to_string(),
        stages: vec![
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::FileOpen,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: Some(set_of([".ssh/id_", ".ssh/known_hosts"])),
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 60,
            },
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::NetworkConnect,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: Some(set_u16([22])),
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 60,
            },
        ],
    };

    // --- phi_data_staging ---
    let data_staging = TemporalRule {
        name: "phi_data_staging".to_string(),
        stages: vec![
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: Some(set_of(["tar ", "zip ", "gzip ", "7z "])),
                    require_file_write: false,
                },
                within_secs: 120,
            },
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::NetworkConnect,
                    process_any_of: None,
                    process_starts_with: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: Some(set_u16([80, 443])),
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                    require_file_write: false,
                },
                within_secs: 120,
            },
        ],
    };

    vec![
        webshell,
        priv_esc,
        reverse_shell,
        download_exec,
        credential_exfil,
        persistence_install,
        ssh_lateral,
        data_staging,
    ]
}
