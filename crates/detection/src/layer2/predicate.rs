use std::collections::HashSet;
use std::sync::Arc;

use crate::sigma_expr::SigmaExpr;

use crate::types::{EventClass, TelemetryEvent};

#[derive(Debug, Clone, Copy, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalLink {
    #[default]
    SameProcess,
    SameProcessOrChild,
    SameProcessOrDescendant,
    Sibling,
    SameProcessOrSibling,
    SiblingOrChild,
    SameProcessOrDescendantOrSibling,
}

#[derive(Debug, Clone)]
pub struct TemporalPredicate {
    pub sigma: Option<Arc<SigmaExpr>>, // RAFIX shared: sigma expr (APACKS)
    pub event_class: EventClass,
    pub process_any_of: Option<HashSet<String>>,
    pub process_starts_with: Option<Vec<String>>,
    pub parent_any_of: Option<HashSet<String>>,
    pub uid_eq: Option<u32>,
    pub uid_ne: Option<u32>,
    pub dst_port_not_in: Option<HashSet<u16>>,
    pub dst_port_any_of: Option<HashSet<u16>>,
    pub file_path_any_of: Option<HashSet<String>>,
    pub file_path_contains: Option<HashSet<String>>,
    pub command_line_contains: Option<HashSet<String>>,
    pub require_file_write: bool,
    pub require_credential_source: bool,
    pub parent_starts_with: Option<Vec<String>>,
    pub process_not_any_of: Option<HashSet<String>>,
    pub parent_not_any_of: Option<HashSet<String>>,
    pub command_line_all_of: Vec<HashSet<String>>,
    pub command_line_not_contains: Option<HashSet<String>>,
    pub command_line_exact_any_of: Option<HashSet<String>>,
    pub file_path_not_contains: Option<HashSet<String>>,
    pub dst_not_loopback: bool,
    pub link: TemporalLink,
}

impl Default for TemporalPredicate {
    fn default() -> Self {
        Self {
            sigma: None,
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
            require_credential_source: false,
            parent_starts_with: None,
            process_not_any_of: None,
            parent_not_any_of: None,
            command_line_all_of: Vec::new(),
            command_line_not_contains: None,
            command_line_exact_any_of: None,
            file_path_not_contains: None,
            dst_not_loopback: false,
            link: TemporalLink::default(),
        }
    }
}

impl TemporalPredicate {
    pub fn matches(&self, event: &TelemetryEvent) -> bool {
        if self.event_class != event.event_class {
            return false;
        }

        // When both process_any_of and process_starts_with are set, the
        // process must match at least one from either field (OR logic).
        // When only one is set, it acts as a standalone filter.
        let has_any_of = self.process_any_of.is_some();
        let has_starts_with = self.process_starts_with.is_some();

        if has_any_of || has_starts_with {
            let process_lower = event.process.to_ascii_lowercase();

            let any_of_match = self
                .process_any_of
                .as_ref()
                .map(|set| {
                    set.iter()
                        .any(|expected| expected.eq_ignore_ascii_case(&process_lower))
                })
                .unwrap_or(false);

            let starts_with_match = self
                .process_starts_with
                .as_ref()
                .map(|prefixes| {
                    prefixes
                        .iter()
                        .any(|prefix| process_lower.starts_with(&prefix.to_ascii_lowercase()))
                })
                .unwrap_or(false);

            if has_any_of && has_starts_with {
                // OR: must match at least one from either field.
                if !any_of_match && !starts_with_match {
                    return false;
                }
            } else if (has_any_of && !any_of_match) || (has_starts_with && !starts_with_match) {
                return false;
            }
        }

        let parent = event.parent_process.to_ascii_lowercase();
        if self.parent_any_of.is_some() || self.parent_starts_with.is_some() {
            let exact = self.parent_any_of.as_ref().is_some_and(|set| {
                set.iter()
                    .any(|expected| expected.eq_ignore_ascii_case(&parent))
            });
            let prefix = self.parent_starts_with.as_ref().is_some_and(|prefixes| {
                prefixes
                    .iter()
                    .any(|prefix| parent.starts_with(&prefix.to_ascii_lowercase()))
            });
            if !exact && !prefix {
                return false;
            }
        }
        if self
            .process_not_any_of
            .as_ref()
            .is_some_and(|set| set.iter().any(|p| p.eq_ignore_ascii_case(&event.process)))
            || self
                .parent_not_any_of
                .as_ref()
                .is_some_and(|set| set.iter().any(|p| p.eq_ignore_ascii_case(&parent)))
        {
            return false;
        }
        if self.dst_not_loopback && !event.dst_ip.as_deref().is_some_and(is_non_loopback) {
            return false;
        }
        let cmd = event
            .command_line
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        if !self
            .command_line_all_of
            .iter()
            .all(|group| group.iter().any(|s| cmd.contains(&s.to_ascii_lowercase())))
            || self
                .command_line_not_contains
                .as_ref()
                .is_some_and(|set| set.iter().any(|s| cmd.contains(&s.to_ascii_lowercase())))
            || self
                .command_line_exact_any_of
                .as_ref()
                .is_some_and(|set| !set.iter().any(|s| s.eq_ignore_ascii_case(cmd.trim())))
        {
            return false;
        }
        let path = normalize_path(event.file_path.as_deref().unwrap_or(""));
        if self
            .file_path_not_contains
            .as_ref()
            .is_some_and(|set| set.iter().any(|s| path.contains(&normalize_path(s))))
        {
            return false;
        }

        if let Some(value) = self.uid_eq {
            if event.uid != value {
                return false;
            }
        }

        if let Some(value) = self.uid_ne {
            if event.uid == value {
                return false;
            }
        }

        if let Some(excluded_ports) = &self.dst_port_not_in {
            match event.dst_port {
                Some(port) => {
                    if excluded_ports.contains(&port) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        if let Some(required_ports) = &self.dst_port_any_of {
            match event.dst_port {
                Some(port) => {
                    if !required_ports.contains(&port) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        if let Some(needles) = &self.command_line_contains {
            let Some(command_line) = event.command_line.as_deref() else {
                return false;
            };
            let command_line = command_line.to_ascii_lowercase();
            if !needles
                .iter()
                .any(|needle| command_line.contains(&needle.to_ascii_lowercase()))
            {
                return false;
            }
        }

        if self.require_credential_source
            && !event
                .file_path
                .as_deref()
                .is_some_and(crate::layer4::is_credential_source)
        {
            return false;
        }

        if self.file_path_any_of.is_some() || self.file_path_contains.is_some() {
            let Some(path) = event.file_path.as_deref() else {
                return false;
            };

            let normalized_path = normalize_path(path);
            let exact_ok = self
                .file_path_any_of
                .as_ref()
                .map(|set| {
                    set.iter()
                        .any(|needle| normalize_path(needle) == normalized_path)
                })
                .unwrap_or(false);
            let contains_ok = self
                .file_path_contains
                .as_ref()
                .map(|set| {
                    set.iter()
                        .any(|needle| normalized_path.contains(&normalize_path(needle)))
                })
                .unwrap_or(false);

            if !exact_ok && !contains_ok {
                return false;
            }
        }

        if self.require_file_write && !event.file_write {
            return false;
        }

        if self.sigma.as_ref().is_some_and(|expr| !expr.matches(event)) {
            // RAFIX shared: sigma expr (APACKS)
            return false;
        }

        true
    }
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

pub(crate) fn is_non_loopback(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok_and(|ip| {
        !ip.is_loopback() && !ip.is_unspecified()
            && !matches!(ip, std::net::IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback() || v4.is_unspecified()))
    })
}
