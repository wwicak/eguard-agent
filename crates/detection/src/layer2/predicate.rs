use std::collections::HashSet;

use crate::types::{EventClass, TelemetryEvent};

#[derive(Debug, Clone)]
pub struct TemporalPredicate {
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
            } else if has_any_of && !any_of_match {
                return false;
            } else if has_starts_with && !starts_with_match {
                return false;
            }
        }

        if let Some(set) = &self.parent_any_of {
            let parent_process = event.parent_process.to_ascii_lowercase();
            if !set
                .iter()
                .any(|expected| expected.eq_ignore_ascii_case(&parent_process))
            {
                return false;
            }
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

        if self.file_path_any_of.is_some() || self.file_path_contains.is_some() {
            let Some(path) = event.file_path.as_deref() else {
                return false;
            };

            let normalized_path = path.to_ascii_lowercase();
            let exact_ok = self
                .file_path_any_of
                .as_ref()
                .map(|set| {
                    set.contains(&normalized_path)
                        || set.iter().any(|needle| needle.eq_ignore_ascii_case(path))
                })
                .unwrap_or(false);
            let contains_ok = self
                .file_path_contains
                .as_ref()
                .map(|set| {
                    set.iter()
                        .any(|needle| normalized_path.contains(&needle.to_ascii_lowercase()))
                })
                .unwrap_or(false);

            if !exact_ok && !contains_ok {
                return false;
            }
        }

        if self.require_file_write && !event.file_write {
            return false;
        }

        true
    }
}
