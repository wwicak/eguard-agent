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
