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
    output_bits.div_ceil(8)
}
