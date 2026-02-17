use std::collections::HashMap;

/// Estimate mutual information between two discrete time series.
///
/// I(X;Y) = Σ_{x,y} p(x,y) · log₂(p(x,y) / (p(x)·p(y)))
///
/// For C2 beaconing detection: X = inter-arrival times (quantized),
/// Y = packet sizes (quantized). High MI means periodic pattern.
pub fn mutual_information(x: &[u32], y: &[u32]) -> f64 {
    assert_eq!(x.len(), y.len());
    let n = x.len();
    if n == 0 {
        return 0.0;
    }

    let mut joint: HashMap<(u32, u32), usize> = HashMap::new();
    let mut marginal_x: HashMap<u32, usize> = HashMap::new();
    let mut marginal_y: HashMap<u32, usize> = HashMap::new();

    for (&xi, &yi) in x.iter().zip(y.iter()) {
        *joint.entry((xi, yi)).or_insert(0) += 1;
        *marginal_x.entry(xi).or_insert(0) += 1;
        *marginal_y.entry(yi).or_insert(0) += 1;
    }

    let nf = n as f64;
    let mut mi = 0.0;
    for (&(xi, yi), &count) in &joint {
        let pxy = count as f64 / nf;
        let px = marginal_x[&xi] as f64 / nf;
        let py = marginal_y[&yi] as f64 / nf;
        if pxy > 0.0 && px > 0.0 && py > 0.0 {
            mi += pxy * (pxy / (px * py)).log2();
        }
    }
    mi
}
