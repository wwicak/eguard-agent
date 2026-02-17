use super::support::prob_stats;

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
