/// Spectral radius of an adjacency matrix (power iteration method).
///
/// The spectral radius ρ(A) = max|λᵢ| is a structural invariant:
/// - Normal process trees: ρ ≈ √(branching factor)
/// - Attack process trees: higher ρ (more interconnections)
/// - Fork bombs: ρ → ∞ rapidly
///
/// Cheeger's inequality relates ρ to graph expansion, giving
/// a principled anomaly threshold.
pub fn spectral_radius(adjacency: &[Vec<f64>]) -> f64 {
    let n = adjacency.len();
    if n == 0 {
        return 0.0;
    }
    // Power iteration: converges to dominant eigenvalue
    let mut v = vec![1.0 / (n as f64).sqrt(); n];
    let mut eigenvalue = 0.0;
    for _ in 0..50 {
        // Matrix-vector multiply
        let mut w = vec![0.0; n];
        for i in 0..n {
            for j in 0..n {
                w[i] += adjacency[i][j] * v[j];
            }
        }
        // Compute norm
        let norm: f64 = w.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm < 1e-15 {
            return 0.0;
        }
        eigenvalue = norm;
        // Normalize
        for x in &mut w {
            *x /= norm;
        }
        // Check convergence
        let diff: f64 = v
            .iter()
            .zip(w.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f64>()
            .sqrt();
        v = w;
        if diff < 1e-10 {
            break;
        }
    }
    eigenvalue
}

/// Algebraic connectivity (Fiedler value): second-smallest eigenvalue of Laplacian.
///
/// λ₂ > 0 iff graph is connected. Low λ₂ means the graph is "almost disconnected"
/// — a structural signature of lateral movement (attacker bridging network segments).
pub fn algebraic_connectivity(adjacency: &[Vec<f64>]) -> f64 {
    let n = adjacency.len();
    if n <= 1 {
        return 0.0;
    }
    // Build Laplacian: L = D - A
    let mut laplacian = vec![vec![0.0; n]; n];
    for i in 0..n {
        let degree: f64 = adjacency[i].iter().sum();
        laplacian[i][i] = degree;
        for j in 0..n {
            laplacian[i][j] -= adjacency[i][j];
        }
    }
    // Find second-smallest eigenvalue via inverse power iteration
    // with deflation of the constant eigenvector (1/√n, ..., 1/√n).
    fiedler_value(&laplacian)
}

fn fiedler_value(laplacian: &[Vec<f64>]) -> f64 {
    let n = laplacian.len();
    // Shift to make positive definite: L' = L + (1/n)·11ᵀ
    // This maps the zero eigenvalue to 1 while preserving all others.
    let shift = 1.0 / n as f64;
    let mut shifted = laplacian.to_vec();
    for i in 0..n {
        for j in 0..n {
            shifted[i][j] += shift;
        }
    }
    // Inverse power iteration on shifted matrix finds smallest eigenvalue of L'
    // which corresponds to second-smallest of L (since we shifted the zero).
    let mut v = vec![0.0; n];
    // Start with vector orthogonal to constant vector
    for i in 0..n {
        v[i] = if i % 2 == 0 { 1.0 } else { -1.0 };
    }
    let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    for x in &mut v {
        *x /= norm;
    }

    let mut lambda = 0.0;
    for _ in 0..100 {
        // Solve shifted · w = v (using Jacobi iteration for simplicity)
        let w = jacobi_solve(&shifted, &v, 50);
        // Project out constant eigenvector
        let mean: f64 = w.iter().sum::<f64>() / n as f64;
        let mut w_proj: Vec<f64> = w.iter().map(|x| x - mean).collect();
        let norm: f64 = w_proj.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm < 1e-15 {
            return 0.0;
        }
        for x in &mut w_proj {
            *x /= norm;
        }
        // Rayleigh quotient
        let mut num = 0.0;
        for i in 0..n {
            for j in 0..n {
                num += w_proj[i] * laplacian[i][j] * w_proj[j];
            }
        }
        lambda = num;
        let diff: f64 = v
            .iter()
            .zip(w_proj.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f64>()
            .sqrt();
        v = w_proj;
        if diff < 1e-10 {
            break;
        }
    }
    lambda.max(0.0)
}

fn jacobi_solve(a: &[Vec<f64>], b: &[f64], iterations: usize) -> Vec<f64> {
    let n = a.len();
    let mut x = b.to_vec();
    let mut x_new = vec![0.0; n];
    for _ in 0..iterations {
        for i in 0..n {
            let mut sum = b[i];
            for j in 0..n {
                if j != i {
                    sum -= a[i][j] * x[j];
                }
            }
            x_new[i] = if a[i][i].abs() > 1e-15 {
                sum / a[i][i]
            } else {
                0.0
            };
        }
        std::mem::swap(&mut x, &mut x_new);
    }
    x
}
