use std::collections::{HashMap, VecDeque};

use crate::types::{EventClass, EVENT_CLASSES};

pub(crate) fn default_uniform_baseline() -> HashMap<EventClass, f64> {
    let mut out = HashMap::new();
    let p = 1.0 / EVENT_CLASSES.len() as f64;
    for class in EVENT_CLASSES {
        out.insert(class, p);
    }
    out
}

#[cfg(test)]
pub(crate) fn distributions(
    counts: &HashMap<EventClass, u64>,
    total: usize,
    baseline: &HashMap<EventClass, f64>,
    alpha: f64,
) -> (Vec<f64>, Vec<f64>) {
    let mut p = Vec::with_capacity(EVENT_CLASSES.len());
    let mut q = Vec::with_capacity(EVENT_CLASSES.len());

    let n = total.max(1) as f64;
    let bsum: f64 = EVENT_CLASSES
        .iter()
        .map(|class| baseline.get(class).copied().unwrap_or(0.0))
        .sum();
    let denom = bsum + alpha * EVENT_CLASSES.len() as f64;

    for class in EVENT_CLASSES {
        let count = counts.get(&class).copied().unwrap_or(0) as f64;
        p.push(count / n);

        let base = baseline.get(&class).copied().unwrap_or(0.0);
        q.push((base + alpha) / denom);
    }

    (p, q)
}

pub(crate) fn kl_divergence_bits(p: &[f64], q: &[f64]) -> f64 {
    p.iter()
        .zip(q)
        .filter(|(pi, qi)| **pi > 0.0 && **qi > 0.0)
        .map(|(pi, qi)| pi * (pi / qi).log2())
        .sum()
}

pub(crate) fn tau_delta_bits(n: usize, k: usize, delta: f64) -> f64 {
    if n == 0 || delta <= 0.0 {
        return 0.0;
    }
    let n_f = n as f64;
    let k_f = k as f64;
    (k_f * (n_f + 1.0).log2() + (1.0 / delta).log2()) / n_f
}

pub(crate) fn shannon_entropy_bits(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<u8, usize> = HashMap::new();
    for b in s.as_bytes() {
        *freq.entry(*b).or_insert(0) += 1;
    }

    let n = s.len() as f64;
    freq.values()
        .map(|c| {
            let p = *c as f64 / n;
            if p == 0.0 {
                0.0
            } else {
                -p * p.log2()
            }
        })
        .sum()
}

pub(crate) fn robust_z(value: f64, history: &VecDeque<f64>) -> f64 {
    if history.len() < 10 {
        return 0.0;
    }

    let mut values: Vec<f64> = history.iter().copied().collect();
    values.sort_by(|a, b| a.total_cmp(b));
    let median = percentile_sorted(&values, 50.0);

    let mut abs_dev: Vec<f64> = values.iter().map(|x| (x - median).abs()).collect();
    abs_dev.sort_by(|a, b| a.total_cmp(b));
    let mad = percentile_sorted(&abs_dev, 50.0).max(1e-9);

    (value - median) / (1.4826 * mad)
}

fn percentile_sorted(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * (values.len() - 1) as f64).round() as usize;
    values[rank.min(values.len() - 1)]
}
