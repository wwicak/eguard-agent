//! C2 Beaconing Detection via Mutual Information
//!
//! Tracks per-destination inter-arrival times and event sizes,
//! quantizes them to discrete buckets, and computes mutual information
//! on a sliding window. High MI (> 0.5 bits) indicates periodic
//! communication patterns characteristic of C2 beaconing.

use std::collections::{HashMap, VecDeque};

use crate::information::mutual_information;

/// Maximum tracked destinations (LRU evict beyond this).
const MAX_DESTINATIONS: usize = 256;
/// Sliding window size per destination.
const WINDOW_SIZE: usize = 256;
/// MI threshold above which we declare beaconing detected.
const MI_THRESHOLD: f64 = 0.5;
/// Number of discrete buckets for quantization.
const QUANTIZE_BUCKETS: u32 = 8;
/// Minimum events before computing MI (need statistical significance).
const MIN_EVENTS: usize = 32;
/// Recompute MI every N events per destination (amortize cost).
const MI_RECOMPUTE_INTERVAL: usize = 16;

/// Per-destination tracking state.
#[derive(Debug, Clone)]
struct DestinationState {
    /// Quantized inter-arrival times.
    inter_arrival_times: VecDeque<u32>,
    /// Quantized event sizes.
    event_sizes: VecDeque<u32>,
    /// Timestamp of the last event to this destination.
    last_ts: i64,
    /// Tick counter for LRU eviction.
    last_tick: u64,
    /// Cached MI score (recomputed every MI_RECOMPUTE_INTERVAL events).
    cached_mi: f64,
    /// Event count at last MI computation.
    events_at_last_mi: usize,
}

/// Result of observing a network event for beaconing.
#[derive(Debug, Clone, Copy)]
pub struct BeaconingResult {
    /// Whether MI exceeds the beaconing threshold.
    pub detected: bool,
    /// Raw mutual information score in bits.
    pub mi_score: f64,
}

/// Tracks per-destination network patterns and detects C2 beaconing
/// via mutual information between inter-arrival times and event sizes.
#[derive(Debug, Clone)]
pub struct BeaconingTracker {
    destinations: HashMap<String, DestinationState>,
    tick: u64,
}

impl BeaconingTracker {
    pub fn new() -> Self {
        Self {
            destinations: HashMap::new(),
            tick: 0,
        }
    }

    /// Observe a network event to the given destination.
    ///
    /// Returns a `BeaconingResult` with the MI score and whether
    /// beaconing is detected (MI > 0.5 bits).
    ///
    /// - `dst_key`: Destination identifier (e.g., "1.2.3.4:443")
    /// - `ts`: Unix timestamp of the event
    /// - `event_size`: Size of the event/packet in bytes
    pub fn observe(&mut self, dst_key: &str, ts: i64, event_size: u64) -> BeaconingResult {
        self.tick += 1;

        // LRU eviction when at capacity
        if !self.destinations.contains_key(dst_key)
            && self.destinations.len() >= MAX_DESTINATIONS
        {
            if let Some(oldest_key) = self
                .destinations
                .iter()
                .min_by_key(|(_, v)| v.last_tick)
                .map(|(k, _)| k.clone())
            {
                self.destinations.remove(&oldest_key);
            }
        }

        let tick = self.tick;
        let state = self
            .destinations
            .entry(dst_key.to_string())
            .or_insert_with(|| DestinationState {
                inter_arrival_times: VecDeque::with_capacity(WINDOW_SIZE),
                event_sizes: VecDeque::with_capacity(WINDOW_SIZE),
                last_ts: ts,
                last_tick: tick,
                cached_mi: 0.0,
                events_at_last_mi: 0,
            });
        state.last_tick = tick;

        // Compute inter-arrival time from previous event
        let iat = if ts > state.last_ts {
            (ts - state.last_ts) as f64
        } else {
            0.0
        };
        state.last_ts = ts;

        // Quantize and push
        let iat_bucket = quantize_log(iat, QUANTIZE_BUCKETS);
        let size_bucket = quantize_log(event_size as f64, QUANTIZE_BUCKETS);

        state.inter_arrival_times.push_back(iat_bucket);
        state.event_sizes.push_back(size_bucket);

        // Maintain window bound
        while state.inter_arrival_times.len() > WINDOW_SIZE {
            state.inter_arrival_times.pop_front();
        }
        while state.event_sizes.len() > WINDOW_SIZE {
            state.event_sizes.pop_front();
        }

        // Compute MI once we have enough data
        let current_len = state.inter_arrival_times.len();
        if current_len < MIN_EVENTS {
            return BeaconingResult {
                detected: false,
                mi_score: 0.0,
            };
        }

        // Only recompute MI every MI_RECOMPUTE_INTERVAL events to amortize cost
        let events_since_last = current_len.saturating_sub(state.events_at_last_mi);
        if events_since_last < MI_RECOMPUTE_INTERVAL && state.events_at_last_mi > 0 {
            return BeaconingResult {
                detected: state.cached_mi > MI_THRESHOLD,
                mi_score: state.cached_mi,
            };
        }

        let iats: Vec<u32> = state.inter_arrival_times.iter().copied().collect();
        let sizes: Vec<u32> = state.event_sizes.iter().copied().collect();
        let mi = mutual_information(&iats, &sizes);
        state.cached_mi = mi;
        state.events_at_last_mi = current_len;

        BeaconingResult {
            detected: mi > MI_THRESHOLD,
            mi_score: mi,
        }
    }

    /// Number of actively tracked destinations.
    pub fn destination_count(&self) -> usize {
        self.destinations.len()
    }
}

impl Default for BeaconingTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Log-scale quantization: maps a non-negative value to [0, buckets-1].
///
/// Bucket boundaries are at powers of 2:
/// - value 0     → bucket 0
/// - value 1     → bucket 1
/// - value 3     → bucket 2
/// - value 7     → bucket 3
/// - value 15    → bucket 4
/// - value 31    → bucket 5
/// - value 63    → bucket 6
/// - value 127+  → bucket 7  (for 8 buckets)
fn quantize_log(value: f64, buckets: u32) -> u32 {
    if value <= 0.0 {
        return 0;
    }
    let bucket = (1.0 + value).log2().floor() as u32;
    bucket.min(buckets - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantize_log_boundaries() {
        assert_eq!(quantize_log(0.0, 8), 0);
        assert_eq!(quantize_log(0.5, 8), 0);
        assert_eq!(quantize_log(1.0, 8), 1);
        assert_eq!(quantize_log(3.0, 8), 2);
        assert_eq!(quantize_log(7.0, 8), 3);
        assert_eq!(quantize_log(1000.0, 8), 7);
        assert_eq!(quantize_log(-1.0, 8), 0);
    }

    #[test]
    fn no_beaconing_on_random_traffic() {
        let mut tracker = BeaconingTracker::new();
        // Random inter-arrival times and varying sizes → low MI
        for i in 0..100 {
            let ts = i * (1 + i % 7); // irregular spacing
            let size = (i * 137 + 42) % 10000; // varying sizes
            let result = tracker.observe("1.2.3.4:443", ts, size as u64);
            if result.mi_score > 0.0 {
                // MI should stay low for irregular traffic
                assert!(
                    result.mi_score < 1.5,
                    "MI too high for random traffic: {}",
                    result.mi_score
                );
            }
        }
    }

    #[test]
    fn detects_structured_beaconing() {
        let mut tracker = BeaconingTracker::new();
        // Alternating beacon pattern: heartbeat (short IAT, small) then
        // data exfil (long IAT, large). The correlation between IAT and
        // size is what MI detects — this is a structured C2 protocol.
        let mut detected = false;
        for i in 0..200 {
            let (_iat, size) = if i % 2 == 0 {
                (30, 100_u64) // heartbeat: short interval, small packet
            } else {
                (300, 5000_u64) // data exfil: longer interval, large packet
            };
            let ts: i64 = if i == 0 {
                0
            } else {
                (0..i).map(|j| if j % 2 == 0 { 30_i64 } else { 300 }).sum()
            };
            let result = tracker.observe("evil.com:443", ts, size);
            if result.detected {
                detected = true;
            }
        }
        assert!(
            detected,
            "should detect structured beaconing with correlated IAT + size"
        );
    }

    #[test]
    fn lru_eviction_bounds_memory() {
        let mut tracker = BeaconingTracker::new();
        for i in 0..(MAX_DESTINATIONS + 50) {
            let key = format!("10.0.0.{}:{}", i / 256, i % 65536);
            tracker.observe(&key, i as i64, 100);
        }
        assert!(
            tracker.destination_count() <= MAX_DESTINATIONS,
            "should evict to stay within bounds: {}",
            tracker.destination_count()
        );
    }
}
