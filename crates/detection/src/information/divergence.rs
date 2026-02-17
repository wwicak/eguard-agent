use super::support::{prob_stats, EPS};

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
