use std::collections::HashSet;

use crate::types::{EventClass, TelemetryEvent};

#[derive(Debug, Clone)]
pub struct TemporalPredicate {
    pub event_class: EventClass,
    pub process_any_of: Option<HashSet<String>>,
    pub parent_any_of: Option<HashSet<String>>,
    pub uid_eq: Option<u32>,
    pub uid_ne: Option<u32>,
    pub dst_port_not_in: Option<HashSet<u16>>,
    pub file_path_any_of: Option<HashSet<String>>,
    pub file_path_contains: Option<HashSet<String>>,
}

impl TemporalPredicate {
    pub fn matches(&self, event: &TelemetryEvent) -> bool {
        if self.event_class != event.event_class {
            return false;
        }

        if let Some(set) = &self.process_any_of {
            if !set.contains(&event.process) {
                return false;
            }
        }

        if let Some(set) = &self.parent_any_of {
            if !set.contains(&event.parent_process) {
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

        if self.file_path_any_of.is_some() || self.file_path_contains.is_some() {
            let Some(path) = event.file_path.as_deref() else {
                return false;
            };

            let exact_ok = self
                .file_path_any_of
                .as_ref()
                .map(|set| set.contains(path))
                .unwrap_or(false);
            let contains_ok = self
                .file_path_contains
                .as_ref()
                .map(|set| set.iter().any(|needle| path.contains(needle)))
                .unwrap_or(false);

            if !exact_ok && !contains_ok {
                return false;
            }
        }

        true
    }
}
