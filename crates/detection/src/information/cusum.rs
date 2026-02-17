/// Page's CUSUM (Cumulative Sum) change-point detector.
///
/// Optimal detection delay by Lorden's theorem:
///   E[detection delay] ≤ (h / D_KL(P₁ || P₀)) · (1 + o(1))
///
/// where h is the threshold and D_KL is the KL-divergence between
/// the pre-change (P₀) and post-change (P₁) distributions.
///
/// The CUSUM statistic:
///   S_n = max(0, S_{n-1} + log(p₁(x_n) / p₀(x_n)))
///
/// Alarm when S_n > h.
#[derive(Debug, Clone)]
pub struct CusumDetector {
    /// Current CUSUM statistic.
    pub statistic: f64,
    /// Alarm threshold.
    pub threshold: f64,
    /// Reference (pre-change) mean.
    pub mu_0: f64,
    /// Allowance parameter (minimum shift to detect).
    pub allowance: f64,
    /// Number of observations.
    pub n: u64,
    /// Number of alarms.
    pub alarms: u64,
}

impl CusumDetector {
    /// Create a new CUSUM detector.
    ///
    /// - `mu_0`: expected mean under normal conditions
    /// - `allowance`: minimum shift to detect (k = δ/2 for optimal detection of shift δ)
    /// - `threshold`: alarm threshold h (controls FP rate: ARL₀ ≈ exp(2h²/σ²))
    pub fn new(mu_0: f64, allowance: f64, threshold: f64) -> Self {
        Self {
            statistic: 0.0,
            threshold,
            mu_0,
            allowance,
            n: 0,
            alarms: 0,
        }
    }

    /// Observe a new value. Returns true if change detected.
    pub fn observe(&mut self, x: f64) -> bool {
        self.n += 1;
        // One-sided upper CUSUM: detects increase
        self.statistic = (self.statistic + (x - self.mu_0) - self.allowance).max(0.0);
        if self.statistic > self.threshold {
            self.alarms += 1;
            self.statistic = 0.0; // reset after alarm
            true
        } else {
            false
        }
    }

    /// Average Run Length to false alarm (analytical approximation).
    /// ARL₀ ≈ exp(2·h·(h/σ² + allowance/σ²))
    /// For unit variance, this simplifies.
    pub fn estimated_arl0(&self) -> f64 {
        // Siegmund's approximation for unit variance
        let h = self.threshold;
        let k = self.allowance;
        if k <= 0.0 {
            return f64::INFINITY;
        }
        (h / k).exp() * (1.0 + k * h)
    }
}

/// Two-sided CUSUM: detects both increases and decreases.
#[derive(Debug, Clone)]
pub struct TwoSidedCusum {
    pub upper: CusumDetector,
    pub lower: CusumDetector,
}

impl TwoSidedCusum {
    pub fn new(mu_0: f64, allowance: f64, threshold: f64) -> Self {
        Self {
            upper: CusumDetector::new(mu_0, allowance, threshold),
            lower: CusumDetector::new(-mu_0, allowance, threshold),
        }
    }

    pub fn observe(&mut self, x: f64) -> bool {
        let upper_alarm = self.upper.observe(x);
        let lower_alarm = self.lower.observe(-x);
        upper_alarm || lower_alarm
    }
}
