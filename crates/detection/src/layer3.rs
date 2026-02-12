use std::collections::{HashMap, VecDeque};

use crate::math::{
    default_uniform_baseline, distributions, kl_divergence_bits, robust_z, shannon_entropy_bits,
    tau_delta_bits,
};
use crate::types::{EventClass, TelemetryEvent, EVENT_CLASSES};

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

#[derive(Debug, Clone, Default)]
struct WindowState {
    counts: HashMap<EventClass, u64>,
    n: usize,
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
}

pub struct AnomalyEngine {
    config: AnomalyConfig,
    baselines: HashMap<String, HashMap<EventClass, f64>>,
    windows: HashMap<String, WindowState>,
    entropy_history: HashMap<String, VecDeque<f64>>,
}

impl AnomalyEngine {
    pub fn new(config: AnomalyConfig) -> Self {
        Self {
            config,
            baselines: HashMap::new(),
            windows: HashMap::new(),
            entropy_history: HashMap::new(),
        }
    }

    pub fn set_baseline(&mut self, process_key: String, dist: HashMap<EventClass, f64>) {
        self.baselines.insert(process_key, dist);
    }

    pub fn observe(&mut self, event: &TelemetryEvent) -> Option<AnomalyDecision> {
        let (entropy_bits, entropy_z, entropy_high) = self.observe_entropy(event);

        let key = event.process_key();
        let (counts, sample_count) = {
            let window = self.windows.entry(key.clone()).or_default();
            *window.counts.entry(event.event_class).or_insert(0) += 1;
            window.n += 1;

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
                    });
                }
                return None;
            }

            (std::mem::take(&mut window.counts), std::mem::take(&mut window.n))
        };

        let baseline = self
            .baselines
            .get(&key)
            .cloned()
            .unwrap_or_else(default_uniform_baseline);

        let (p, q) = distributions(&counts, sample_count, &baseline, self.config.alpha);
        let kl = kl_divergence_bits(&p, &q);

        let tau_high = self
            .config
            .tau_floor_high
            .max(tau_delta_bits(sample_count, EVENT_CLASSES.len(), self.config.delta_high));
        let tau_med = self
            .config
            .tau_floor_med
            .max(tau_delta_bits(sample_count, EVENT_CLASSES.len(), self.config.delta_med));

        let high = kl > tau_high || entropy_high;
        let medium = !high && kl > tau_med;

        if high || medium {
            return Some(AnomalyDecision {
                high,
                medium,
                kl_bits: kl,
                tau_high,
                tau_med,
                entropy_bits,
                entropy_z,
            });
        }

        None
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
}

impl Default for AnomalyEngine {
    fn default() -> Self {
        Self::new(AnomalyConfig::default())
    }
}
