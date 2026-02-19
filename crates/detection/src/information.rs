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

mod compression;
mod concentration;
mod conformal;
mod cusum;
mod divergence;
mod dns;
mod entropy;
mod mutual;
mod spectral;
mod support;
mod transport;

pub use entropy::{
    char_entropy, cmdline_information, renyi_entropy, renyi_spectrum, shannon_entropy,
    CmdlineInfoMetrics, CmdlineInfoNormalized,
};

pub use divergence::{kl_divergence, renyi_divergence};

pub use transport::wasserstein_1;

pub use compression::{compression_ratio, normalized_compression_distance};

pub use cusum::{CusumDetector, TwoSidedCusum};

pub use spectral::{algebraic_connectivity, spectral_radius};

pub use conformal::ConformalCalibrator;

pub use mutual::mutual_information;

pub use dns::dns_entropy;

pub use concentration::{
    bernstein_threshold, hoeffding_threshold, mcdiarmid_threshold, sanov_threshold,
};

#[cfg(test)]
mod tests;
