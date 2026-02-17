pub(super) const EPS: f64 = 1e-15;

pub(super) fn prob_stats(values: &[f64]) -> (f64, f64, usize) {
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
