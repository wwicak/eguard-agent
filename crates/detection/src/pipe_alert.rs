use std::collections::HashMap;

use crate::{EventClass, TelemetryEvent};

// RAFIX shared: only an already-alerted wrapper can suppress its sibling-pipe duplicate.
#[derive(Default)]
pub(crate) struct PipeAlerts {
    wrappers: HashMap<u32, (u64, i64)>,
    pub suppressed_total: u64,
    pub evicted_total: u64,
}

impl PipeAlerts {
    pub fn observe(&mut self, event: &TelemetryEvent) {
        if matches!(
            event.event_class,
            EventClass::ProcessExec | EventClass::ProcessExit
        ) {
            self.wrappers.remove(&event.pid);
        }
        let before = self.wrappers.len();
        self.wrappers
            .retain(|_, (_, ts)| event.ts_unix.saturating_sub(*ts) <= 30);
        self.evicted_total = self
            .evicted_total
            .saturating_add((before - self.wrappers.len()) as u64);
    }

    pub fn record(&mut self, event: &TelemetryEvent, epoch: u64) {
        if self.wrappers.len() >= 1024 {
            if let Some(pid) = self
                .wrappers
                .iter()
                .min_by_key(|(pid, (_, ts))| (*ts, **pid))
                .map(|(pid, _)| *pid)
            {
                self.wrappers.remove(&pid);
                self.evicted_total = self.evicted_total.saturating_add(1);
            }
        }
        self.wrappers.insert(event.pid, (epoch, event.ts_unix));
    }

    pub fn suppress(&mut self, event: &TelemetryEvent, parent_epoch: Option<u64>) -> bool {
        let matched = self.wrappers.get(&event.ppid).is_some_and(|(epoch, ts)| {
            Some(*epoch) == parent_epoch && (0..=30).contains(&event.ts_unix.saturating_sub(*ts))
        });
        if matched {
            self.suppressed_total = self.suppressed_total.saturating_add(1);
        }
        matched
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrapper_retention_is_bounded_and_expired_entries_cannot_suppress() {
        let mut alerts = PipeAlerts::default();
        let mut e: TelemetryEvent = serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":"ProcessExec","pid":1,"ppid":1,"uid":1000,"process":"sh","parent_process":"sh","session_id":1,"file_write":false,"container_escape":false,"container_privileged":false})).unwrap();
        for pid in 2..1100 {
            e.pid = pid;
            alerts.observe(&e);
            alerts.record(&e, 1);
        }
        assert_eq!(alerts.wrappers.len(), 1024);
        assert_eq!(alerts.evicted_total, 74);
        e.pid = 1;
        e.ts_unix = 32;
        alerts.observe(&e);
        assert_eq!(alerts.wrappers.len(), 0);
        assert_eq!(alerts.evicted_total, 1098);
        assert!(!alerts.suppress(&e, Some(1)));
    }
}
