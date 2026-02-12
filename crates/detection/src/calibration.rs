#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThresholdCalibration {
    pub tau_delta_high: f64,
    pub tau_delta_med: f64,
    pub tau_high: f64,
    pub tau_med: f64,
}

pub fn tau_delta(n: usize, k: usize, delta: f64) -> Option<f64> {
    if n == 0 || k == 0 || !(0.0..1.0).contains(&delta) {
        return None;
    }

    let n_f = n as f64;
    let k_f = k as f64;
    Some((k_f * (n_f + 1.0).log2() + (1.0 / delta).log2()) / n_f)
}

pub fn sanov_upper_bound(n: usize, k: usize, tau_bits: f64) -> Option<f64> {
    if n == 0 || k == 0 || tau_bits.is_sign_negative() {
        return None;
    }

    let n_f = n as f64;
    let k_f = k as f64;
    let log2_bound = k_f * (n_f + 1.0).log2() - n_f * tau_bits;
    let bound = 2_f64.powf(log2_bound);
    Some(bound.min(1.0))
}

pub fn calibrate_thresholds(
    n: usize,
    k: usize,
    delta_high: f64,
    delta_med: f64,
    tau_floor_high: f64,
    tau_floor_med: f64,
) -> Option<ThresholdCalibration> {
    let tau_delta_high = tau_delta(n, k, delta_high)?;
    let tau_delta_med = tau_delta(n, k, delta_med)?;

    let tau_high = tau_floor_high.max(tau_delta_high);
    let tau_med = tau_floor_med.max(tau_delta_med);

    Some(ThresholdCalibration {
        tau_delta_high,
        tau_delta_med,
        tau_high,
        tau_med,
    })
}
