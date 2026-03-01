use std::collections::{HashMap, VecDeque};

use crate::information::CusumDetector;
use crate::math::{
    default_uniform_baseline, kl_divergence_bits, robust_z, shannon_entropy_bits, tau_delta_bits,
};
use crate::types::{EventClass, TelemetryEvent, EVENT_CLASSES, EVENT_CLASS_COUNT};

/// Maximum number of per-process CUSUM drift detectors (LRU evict beyond this).
const MAX_CUSUM_PROCESSES: usize = 4096;

#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    pub window_size: usize,
    pub alpha: f64,
    pub delta_high: f64,
    pub delta_med: f64,
    pub tau_floor_high: f64,
    pub tau_floor_med: f64,
    pub min_entropy_len: usize,
    pub entropy_threshold: f64,
    pub entropy_z_threshold: f64,
    pub entropy_history_limit: usize,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            window_size: 128,
            alpha: 1.0,
            delta_high: 1e-6,
            delta_med: 1e-3,
            tau_floor_high: 0.25,
            tau_floor_med: 0.10,
            min_entropy_len: 40,
            entropy_threshold: 4.2,
            entropy_z_threshold: 3.0,
            entropy_history_limit: 512,
        }
    }
}

#[derive(Debug, Clone)]
struct WindowState {
    counts: [u64; EVENT_CLASS_COUNT],
    n: usize,
}

impl Default for WindowState {
    fn default() -> Self {
        Self {
            counts: [0u64; EVENT_CLASS_COUNT],
            n: 0,
        }
    }
}

/// Per-process CUSUM drift tracker with LRU metadata.
#[derive(Debug, Clone)]
struct ProcessCusum {
    detector: CusumDetector,
    last_tick: u64,
}

#[derive(Debug, Clone)]
pub struct AnomalyDecision {
    pub high: bool,
    pub medium: bool,
    pub kl_bits: f64,
    pub tau_high: f64,
    pub tau_med: f64,
    pub entropy_bits: Option<f64>,
    pub entropy_z: Option<f64>,
    /// CUSUM drift alarm: the KL-divergence for this process has been
    /// trending upward across multiple windows, indicating sustained
    /// baseline drift (not just a single anomalous window).
    pub drift_alarm: bool,
}

pub struct AnomalyEngine {
    config: AnomalyConfig,
    baselines: HashMap<String, HashMap<EventClass, f64>>,
    windows: HashMap<String, WindowState>,
    entropy_history: HashMap<String, VecDeque<f64>>,
    /// Per-process CUSUM detectors tracking KL-divergence drift.
    /// Key is process_key (process:parent), bounded by MAX_CUSUM_PROCESSES.
    cusum_drift: HashMap<String, ProcessCusum>,
    /// Monotonic tick counter for LRU eviction.
    tick: u64,
}

impl AnomalyEngine {
    pub fn new(config: AnomalyConfig) -> Self {
        Self {
            config,
            baselines: HashMap::new(),
            windows: HashMap::new(),
            entropy_history: HashMap::new(),
            cusum_drift: HashMap::new(),
            tick: 0,
        }
    }

    pub fn set_baseline(&mut self, process_key: String, dist: HashMap<EventClass, f64>) {
        self.baselines.insert(process_key, dist);
    }

    pub fn observe(&mut self, event: &TelemetryEvent) -> Option<AnomalyDecision> {
        self.tick += 1;
        let (entropy_bits, entropy_z, entropy_high) = self.observe_entropy(event);

        let key = event.process_key();
        let (counts, sample_count) = {
            let window = self.windows.entry(key.clone()).or_default();
            window.counts[event.event_class.index()] =
                window.counts[event.event_class.index()].saturating_add(1);
            window.n = window.n.saturating_add(1);

            if window.n < self.config.window_size {
                if entropy_high {
                    return Some(AnomalyDecision {
                        high: true,
                        medium: false,
                        kl_bits: 0.0,
                        tau_high: 0.0,
                        tau_med: 0.0,
                        entropy_bits,
                        entropy_z,
                        drift_alarm: false,
                    });
                }
                return None;
            }

            let counts = std::mem::take(&mut window.counts);
            let sample_count = std::mem::take(&mut window.n);
            (counts, sample_count)
        };

        let baseline = self
            .baselines
            .get(&key)
            .cloned()
            .unwrap_or_else(default_uniform_baseline);

        let (p, q) = self.distributions_from_window_counts(&counts, sample_count, &baseline);
        let kl = kl_divergence_bits(&p, &q);

        let tau_high = self.config.tau_floor_high.max(tau_delta_bits(
            sample_count,
            EVENT_CLASSES.len(),
            self.config.delta_high,
        ));
        let tau_med = self.config.tau_floor_med.max(tau_delta_bits(
            sample_count,
            EVENT_CLASSES.len(),
            self.config.delta_med,
        ));

        // Feed KL-divergence into per-process CUSUM drift detector
        let drift_alarm = self.observe_cusum_drift(&key, kl);

        let high = kl > tau_high || entropy_high;
        let medium = !high && kl > tau_med;

        if high || medium || drift_alarm {
            return Some(AnomalyDecision {
                high,
                medium,
                kl_bits: kl,
                tau_high,
                tau_med,
                entropy_bits,
                entropy_z,
                drift_alarm,
            });
        }

        None
    }

    /// Feed a KL-divergence value into the per-process CUSUM detector.
    /// Returns true if the CUSUM signals sustained drift.
    fn observe_cusum_drift(&mut self, process_key: &str, kl_bits: f64) -> bool {
        let tick = self.tick;

        // LRU eviction: if at capacity, remove the least-recently-used entry
        if !self.cusum_drift.contains_key(process_key)
            && self.cusum_drift.len() >= MAX_CUSUM_PROCESSES
        {
            if let Some(oldest_key) = self
                .cusum_drift
                .iter()
                .min_by_key(|(_, v)| v.last_tick)
                .map(|(k, _)| k.clone())
            {
                self.cusum_drift.remove(&oldest_key);
            }
        }

        let entry = self
            .cusum_drift
            .entry(process_key.to_string())
            .or_insert_with(|| ProcessCusum {
                // mu_0 = 0.05 bits (expected KL for normal variation)
                // allowance = 0.1 bits (minimum shift to detect)
                // threshold = 2.0 bits (alarm when cumulative shift exceeds this)
                detector: CusumDetector::new(0.05, 0.1, 2.0),
                last_tick: tick,
            });
        entry.last_tick = tick;
        entry.detector.observe(kl_bits)
    }

    fn distributions_from_window_counts(
        &self,
        counts: &[u64; EVENT_CLASS_COUNT],
        sample_count: usize,
        baseline: &HashMap<EventClass, f64>,
    ) -> (Vec<f64>, Vec<f64>) {
        let n = sample_count.max(1) as f64;
        let bsum: f64 = EVENT_CLASSES
            .iter()
            .map(|class| baseline.get(class).copied().unwrap_or(0.0))
            .sum();
        let denom = bsum + self.config.alpha * EVENT_CLASS_COUNT as f64;

        let mut p = Vec::with_capacity(EVENT_CLASS_COUNT);
        let mut q = Vec::with_capacity(EVENT_CLASS_COUNT);

        for class in EVENT_CLASSES {
            let idx = class.index();
            p.push(counts[idx] as f64 / n);

            let base = baseline.get(&class).copied().unwrap_or(0.0);
            q.push((base + self.config.alpha) / denom);
        }

        (p, q)
    }

    fn observe_entropy(&mut self, event: &TelemetryEvent) -> (Option<f64>, Option<f64>, bool) {
        let Some(cmd) = &event.command_line else {
            return (None, None, false);
        };
        if cmd.len() < self.config.min_entropy_len {
            return (None, None, false);
        }

        let entropy = shannon_entropy_bits(cmd);
        let history = self
            .entropy_history
            .entry(event.process.clone())
            .or_default();

        let z = robust_z(entropy, history);
        history.push_back(entropy);
        while history.len() > self.config.entropy_history_limit {
            history.pop_front();
        }

        let high = entropy > self.config.entropy_threshold && z > self.config.entropy_z_threshold;
        (Some(entropy), Some(z), high)
    }

    #[cfg(test)]
    pub(crate) fn debug_entropy_history_len(&self, process: &str) -> usize {
        self.entropy_history
            .get(process)
            .map(|h| h.len())
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn debug_window_sample_count(&self, process_key: &str) -> usize {
        self.windows.get(process_key).map(|w| w.n).unwrap_or(0)
    }

}

impl Default for AnomalyEngine {
    fn default() -> Self {
        Self::new(AnomalyConfig::default())
    }
}
