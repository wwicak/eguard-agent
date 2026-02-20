use crate::types::EventClass;
use crate::util::{set_of, set_u16};

use super::predicate::TemporalPredicate;
use super::rule::{TemporalRule, TemporalStage};

pub(super) fn default_rules() -> Vec<TemporalRule> {
    let web_servers = set_of(["nginx", "apache2", "httpd", "caddy"]);
    let shells = set_of(["sh", "bash", "dash", "zsh", "ksh"]);
    let webshell = TemporalRule {
        name: "phi_webshell".to_string(),
        stages: vec![
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: Some(shells),
                    parent_any_of: Some(web_servers),
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                },
                within_secs: 30,
            },
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::NetworkConnect,
                    process_any_of: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: Some(set_u16([80, 443])),
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                },
                within_secs: 10,
            },
        ],
    };

    let priv_esc = TemporalRule {
        name: "phi_priv_esc".to_string(),
        stages: vec![
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: Some(0),
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                },
                within_secs: 60,
            },
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: None,
                    parent_any_of: None,
                    uid_eq: Some(0),
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                },
                within_secs: 20,
            },
        ],
    };

    vec![webshell, priv_esc]
}
