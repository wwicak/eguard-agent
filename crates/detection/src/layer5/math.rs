use super::constants::FEATURE_COUNT;

pub(super) fn dot(a: &[f64], b: &[f64; FEATURE_COUNT]) -> f64 {
    a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum()
}

pub(super) fn sigmoid(z: f64) -> f64 {
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        let ez = z.exp();
        ez / (1.0 + ez)
    }
}
