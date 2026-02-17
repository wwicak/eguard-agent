use super::compression::compression_ratio;
use super::support::prob_stats;

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
