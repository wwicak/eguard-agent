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
