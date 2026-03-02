use std::cmp::Ordering;

/// Conformal prediction wrapper for ML scores.
///
/// **Theorem (Vovk et al., 2005)**: For exchangeable data (X₁,Y₁),...,(Xₙ,Yₙ),
/// the conformal prediction set C_α(X_{n+1}) satisfies:
///
///   P(Y_{n+1} ∈ C_α(X_{n+1})) ≥ 1 - α
///
/// regardless of the underlying distribution. This is a **finite-sample**
/// guarantee — no asymptotic assumptions.
///
/// We use it to calibrate the ML score threshold so that the declared
/// false-positive rate is mathematically guaranteed, not just empirical.
#[derive(Debug, Clone)]
pub struct ConformalCalibrator {
    /// Sorted nonconformity scores from calibration set.
    scores: Vec<f64>,
    /// Desired miscoverage rate (e.g., 0.01 for 99% coverage).
    alpha: f64,
    /// Calibrated threshold (computed from quantile).
    pub threshold: f64,
}

impl ConformalCalibrator {
    /// Create calibrator from a set of nonconformity scores (higher = more anomalous).
    ///
    /// The threshold is set to the ⌈(1-α)(n+1)⌉/n quantile of the scores,
    /// which guarantees P(score > threshold) ≤ α for exchangeable future data.
    pub fn new(mut calibration_scores: Vec<f64>, alpha: f64) -> Self {
        calibration_scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        let n = calibration_scores.len();
        let threshold = if n == 0 {
            f64::INFINITY
        } else {
            let quantile_idx = (((1.0 - alpha) * (n as f64 + 1.0)).ceil() as usize)
                .min(n)
                .saturating_sub(1);
            calibration_scores[quantile_idx]
        };
        Self {
            scores: calibration_scores,
            alpha,
            threshold,
        }
    }

    /// Test whether a new score is anomalous with guaranteed FP rate ≤ α.
    pub fn is_anomalous(&self, score: f64) -> bool {
        score > self.threshold
    }

    /// Compute the p-value for a new score.
    /// p = |{i : s_i ≥ score}| / (n + 1)
    ///
    /// Uses binary search on the sorted calibration scores for O(log n)
    /// instead of O(n) linear scan.
    pub fn p_value(&self, score: f64) -> f64 {
        let n = self.scores.len();
        if n == 0 {
            return 1.0;
        }
        // scores is sorted ascending (see new()). Find first index where s >= score.
        let idx = self.scores.partition_point(|&s| s < score);
        let count_geq = n - idx;
        (count_geq as f64 + 1.0) / (n as f64 + 1.0)
    }

    /// Guaranteed coverage probability: 1 - α.
    pub fn coverage_guarantee(&self) -> f64 {
        1.0 - self.alpha
    }

    /// Number of calibration samples.
    pub fn calibration_size(&self) -> usize {
        self.scores.len()
    }
}
