//! Per-destination connection periodicity. This is context, not proof of C2.
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

const MAX_DESTINATIONS: usize = 256;
const WINDOW_SIZE: usize = 64;
const MIN_INTERVALS: usize = 12;

#[derive(Debug, Clone)]
struct DestinationState {
    intervals: VecDeque<f64>,
    last_ts: i64,
    last_tick: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct BeaconingResult {
    pub detected: bool,
    /// Compatibility name: now 1-CV in [0,1], not mutual information.
    pub mi_score: f64,
}

#[derive(Debug, Clone, Default)]
pub struct BeaconingTracker {
    destinations: HashMap<String, DestinationState>,
    tick: u64,
}

impl BeaconingTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe a connection. Sizes are deliberately unused: Windows does not
    /// supply them, and dependence on size does not measure periodicity.
    /// The engine excludes configured control-plane peers before calling this.
    pub fn observe(&mut self, dst_key: &str, ts: i64, _event_size: u64) -> BeaconingResult {
        let quiet = BeaconingResult {
            detected: false,
            mi_score: 0.0,
        };
        let Some((host, port)) = dst_key.rsplit_once(':') else {
            return quiet;
        };
        if host.is_empty() || host.len() > 253 || port.parse::<u16>().ok().is_none_or(|p| p == 0) {
            return quiet;
        }
        if host.parse::<IpAddr>().ok().is_some_and(local_address) {
            return quiet;
        }
        self.tick = self.tick.wrapping_add(1);
        if !self.destinations.contains_key(dst_key) {
            if self.destinations.len() >= MAX_DESTINATIONS {
                if let Some(oldest) = self
                    .destinations
                    .iter()
                    .min_by_key(|(_, s)| s.last_tick)
                    .map(|(key, _)| key.clone())
                {
                    self.destinations.remove(&oldest);
                }
            }
            self.destinations.insert(
                dst_key.into(),
                DestinationState {
                    intervals: VecDeque::with_capacity(WINDOW_SIZE),
                    last_ts: ts,
                    last_tick: self.tick,
                },
            );
            return quiet;
        }
        let state = self
            .destinations
            .get_mut(dst_key)
            .expect("destination exists");
        state.last_tick = self.tick;
        if ts < state.last_ts {
            state.intervals.clear();
            state.last_ts = ts;
            return quiet;
        }
        state
            .intervals
            .push_back(ts.saturating_sub(state.last_ts) as f64);
        state.last_ts = ts;
        if state.intervals.len() > WINDOW_SIZE {
            state.intervals.pop_front();
        }
        if state.intervals.len() < MIN_INTERVALS {
            return quiet;
        }
        let n = state.intervals.len() as f64;
        let mean = state.intervals.iter().sum::<f64>() / n;
        if !(10.0..=21600.0).contains(&mean) {
            return quiet;
        }
        let variance = state
            .intervals
            .iter()
            .map(|iat| (iat - mean).powi(2))
            .sum::<f64>()
            / n;
        let cv = variance.sqrt() / mean;
        BeaconingResult {
            detected: cv <= 0.25,
            mi_score: (1.0 - cv).clamp(0.0, 1.0),
        }
    }

    pub fn destination_count(&self) -> usize {
        self.destinations.len()
    }
}

fn local_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            ip.to_ipv4_mapped()
                .is_some_and(|ip| local_address(IpAddr::V4(ip)))
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn irregular_connections_are_not_periodic_context() {
        let mut tracker = BeaconingTracker::new();
        let mut now = 0;
        for i in 0..100 {
            now += [3, 9, 60, 300, 11][i % 5];
            assert!(!tracker.observe("142.250.4.100:443", now, 0).detected);
        }
    }
    #[test]
    fn periodic_context_ignores_missing_or_changing_sizes() {
        let mut tracker = BeaconingTracker::new();
        let mut result = BeaconingResult {
            detected: false,
            mi_score: 0.0,
        };
        for i in 0..30 {
            result = tracker.observe("45.33.12.9:443", i * 60, i as u64 * 137);
        }
        assert!(result.detected);
        assert_eq!(result.mi_score, 1.0);
    }
    #[test]
    fn lru_eviction_bounds_memory() {
        let mut tracker = BeaconingTracker::new();
        for i in 0..MAX_DESTINATIONS + 50 {
            tracker.observe(&format!("45.33.{}.{}:443", i / 256, i % 256), i as i64, 0);
        }
        assert_eq!(tracker.destination_count(), MAX_DESTINATIONS);
    }
}
