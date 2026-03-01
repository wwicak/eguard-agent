//! Zero Trust Device Score — composite device health for NAC integration.
//!
//! Computes a 0-100 trust score from weighted risk factors and maps it to a
//! [`TrustAction`] that NAC / 802.1X infrastructure can consume to gate
//! network access.

use serde::{Deserialize, Serialize};

// ── Score thresholds ─────────────────────────────────────────────────
const ALLOW_THRESHOLD: u8 = 70;
const QUARANTINE_THRESHOLD: u8 = 40;

// ── Public types ─────────────────────────────────────────────────────

/// Composite trust score for a single endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceHealthScore {
    /// Aggregate score in the range 0..=100 (higher = more trusted).
    pub score: u8,
    /// Per-dimension breakdown that produced `score`.
    pub factors: Vec<ScoreFactor>,
    /// Recommended network access action derived from `score`.
    pub recommendation: TrustAction,
    /// Unix timestamp (seconds) when the score was computed.
    pub computed_at: i64,
}

/// One dimension contributing to the composite score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreFactor {
    /// Machine-readable factor identifier, e.g. `"cve_exposure"`.
    pub name: String,
    /// Per-factor score in the range 0..=100.
    pub score: u8,
    /// Relative weight in the range 0.0..=1.0.
    pub weight: f64,
    /// Human-readable explanation of the current score.
    pub detail: String,
}

/// NAC action derived from the composite score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustAction {
    /// Score >= 70: full network access.
    Allow,
    /// Score 40..69: limited access (guest VLAN).
    Restrict,
    /// Score < 40: isolated (remediation VLAN).
    Quarantine,
}

// ── Core logic ───────────────────────────────────────────────────────

/// Compute a [`DeviceHealthScore`] from the supplied factors.
///
/// The aggregate score is the weighted average of all factor scores, clamped
/// to the 0..=100 range.
pub fn compute_score(factors: &[ScoreFactor], now_unix: i64) -> DeviceHealthScore {
    let weighted_sum: f64 = factors
        .iter()
        .map(|f| f64::from(f.score) * f.weight)
        .sum();
    let total_weight: f64 = factors.iter().map(|f| f.weight).sum();

    let raw = if total_weight > 0.0 {
        (weighted_sum / total_weight).round() as i32
    } else {
        0
    };
    let score = raw.clamp(0, 100) as u8;

    DeviceHealthScore {
        score,
        factors: factors.to_vec(),
        recommendation: recommend_action(score),
        computed_at: now_unix,
    }
}

/// Map a raw score to the corresponding [`TrustAction`].
pub fn recommend_action(score: u8) -> TrustAction {
    if score >= ALLOW_THRESHOLD {
        TrustAction::Allow
    } else if score >= QUARANTINE_THRESHOLD {
        TrustAction::Restrict
    } else {
        TrustAction::Quarantine
    }
}

/// Returns a set of factors initialised with "unknown" / worst-case scores.
///
/// Callers should overwrite individual factor scores as real telemetry becomes
/// available.
pub fn default_factors() -> Vec<ScoreFactor> {
    vec![
        ScoreFactor {
            name: "compliance_status".into(),
            score: 0,
            weight: 0.25,
            detail: "Unknown compliance status".into(),
        },
        ScoreFactor {
            name: "cve_exposure".into(),
            score: 0,
            weight: 0.25,
            detail: "Unknown CVE exposure".into(),
        },
        ScoreFactor {
            name: "fim_integrity".into(),
            score: 0,
            weight: 0.20,
            detail: "Unknown FIM integrity".into(),
        },
        ScoreFactor {
            name: "detection_history".into(),
            score: 0,
            weight: 0.15,
            detail: "Unknown detection history".into(),
        },
        ScoreFactor {
            name: "baseline_maturity".into(),
            score: 0,
            weight: 0.10,
            detail: "Unknown baseline maturity".into(),
        },
        ScoreFactor {
            name: "encryption_status".into(),
            score: 0,
            weight: 0.05,
            detail: "Unknown encryption status".into(),
        },
    ]
}

// ── Helper constructors for individual factors ───────────────────────

/// Score the compliance dimension.
///
/// * `100` — fully compliant
/// * `50`  — partially compliant
/// * `0`   — non-compliant
pub fn compliance_factor(compliant: bool, partial: bool) -> ScoreFactor {
    let (score, detail) = if compliant {
        (100, "Fully compliant")
    } else if partial {
        (50, "Partially compliant")
    } else {
        (0, "Non-compliant")
    };
    ScoreFactor {
        name: "compliance_status".into(),
        score,
        weight: 0.25,
        detail: detail.into(),
    }
}

/// Score the CVE exposure dimension.
///
/// `100 - (critical_cve_count * 20)`, clamped to 0.
pub fn cve_factor(critical_cve_count: u32) -> ScoreFactor {
    let raw = 100i32 - (critical_cve_count as i32 * 20);
    let score = raw.max(0) as u8;
    ScoreFactor {
        name: "cve_exposure".into(),
        score,
        weight: 0.25,
        detail: format!("{critical_cve_count} critical CVE(s) detected"),
    }
}

/// Score the FIM integrity dimension.
///
/// * `100` — no FIM changes
/// * `50`  — acknowledged changes only
/// * `0`   — unacknowledged changes present
pub fn fim_factor(no_changes: bool, acknowledged: bool) -> ScoreFactor {
    let (score, detail) = if no_changes {
        (100, "No FIM changes detected")
    } else if acknowledged {
        (50, "Acknowledged FIM changes")
    } else {
        (0, "Unacknowledged FIM changes")
    };
    ScoreFactor {
        name: "fim_integrity".into(),
        score,
        weight: 0.20,
        detail: detail.into(),
    }
}

/// Score the detection history dimension.
///
/// `100 - (high_plus_incidents * 20)`, clamped to 0.
pub fn detection_history_factor(high_plus_incidents_24h: u32) -> ScoreFactor {
    let raw = 100i32 - (high_plus_incidents_24h as i32 * 20);
    let score = raw.max(0) as u8;
    ScoreFactor {
        name: "detection_history".into(),
        score,
        weight: 0.15,
        detail: format!("{high_plus_incidents_24h} High+ detection(s) in last 24h"),
    }
}

/// Score the baseline maturity dimension.
///
/// * `100` — Active baseline
/// * `50`  — Learning baseline
/// * `0`   — Stale or absent baseline
pub fn baseline_factor(active: bool, learning: bool) -> ScoreFactor {
    let (score, detail) = if active {
        (100, "Active baseline")
    } else if learning {
        (50, "Learning baseline")
    } else {
        (0, "Stale or absent baseline")
    };
    ScoreFactor {
        name: "baseline_maturity".into(),
        score,
        weight: 0.10,
        detail: detail.into(),
    }
}

/// Score the encryption status dimension.
///
/// * `100` — disk encrypted
/// * `0`   — disk not encrypted
pub fn encryption_factor(encrypted: bool) -> ScoreFactor {
    let (score, detail) = if encrypted {
        (100, "Disk encrypted")
    } else {
        (0, "Disk not encrypted")
    };
    ScoreFactor {
        name: "encryption_status".into(),
        score,
        weight: 0.05,
        detail: detail.into(),
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn full_health_factors() -> Vec<ScoreFactor> {
        vec![
            compliance_factor(true, false),
            cve_factor(0),
            fim_factor(true, false),
            detection_history_factor(0),
            baseline_factor(true, false),
            encryption_factor(true),
        ]
    }

    #[test]
    fn full_compliance_clean_device_scores_allow() {
        let factors = full_health_factors();
        let result = compute_score(&factors, 1_700_000_000);
        assert!(result.score >= 90, "expected >= 90, got {}", result.score);
        assert_eq!(result.recommendation, TrustAction::Allow);
    }

    #[test]
    fn critical_cves_non_compliant_quarantine() {
        let factors = vec![
            compliance_factor(false, false),   // 0
            cve_factor(5),                     // 0 (100-100)
            fim_factor(false, false),          // 0
            detection_history_factor(5),       // 0
            baseline_factor(false, false),     // 0
            encryption_factor(false),          // 0
        ];
        let result = compute_score(&factors, 1_700_000_000);
        assert!(result.score < QUARANTINE_THRESHOLD, "expected < 40, got {}", result.score);
        assert_eq!(result.recommendation, TrustAction::Quarantine);
    }

    #[test]
    fn partial_compliance_learning_baseline_restrict() {
        let factors = vec![
            compliance_factor(false, true),    // 50
            cve_factor(1),                     // 80
            fim_factor(false, true),           // 50
            detection_history_factor(1),       // 80
            baseline_factor(false, true),      // 50
            encryption_factor(true),           // 100
        ];
        let result = compute_score(&factors, 1_700_000_000);
        assert!(
            result.score >= QUARANTINE_THRESHOLD && result.score < ALLOW_THRESHOLD,
            "expected 40..69, got {}",
            result.score,
        );
        assert_eq!(result.recommendation, TrustAction::Restrict);
    }

    #[test]
    fn score_clamped_to_0_100() {
        // Even with pathological weights, output stays in range.
        let factors = vec![
            ScoreFactor {
                name: "test".into(),
                score: 100,
                weight: 10.0,
                detail: "max".into(),
            },
        ];
        let result = compute_score(&factors, 0);
        assert!(result.score <= 100);

        let factors_zero = vec![
            ScoreFactor {
                name: "test".into(),
                score: 0,
                weight: 10.0,
                detail: "min".into(),
            },
        ];
        let result_zero = compute_score(&factors_zero, 0);
        assert_eq!(result_zero.score, 0);
    }

    #[test]
    fn weighted_average_calculation_correct() {
        // compliance(100 * 0.25) + cve(0 * 0.25) + fim(50 * 0.20) +
        // detection(100 * 0.15) + baseline(50 * 0.10) + encryption(100 * 0.05)
        // = 25 + 0 + 10 + 15 + 5 + 5 = 60 / 1.0 = 60
        let factors = vec![
            compliance_factor(true, false),    // 100
            cve_factor(5),                     // 0
            fim_factor(false, true),           // 50
            detection_history_factor(0),       // 100
            baseline_factor(false, true),      // 50
            encryption_factor(true),           // 100
        ];
        let result = compute_score(&factors, 0);
        assert_eq!(result.score, 60);
    }

    #[test]
    fn default_factors_all_zero() {
        let factors = default_factors();
        let result = compute_score(&factors, 0);
        assert_eq!(result.score, 0);
        assert_eq!(result.recommendation, TrustAction::Quarantine);
    }

    #[test]
    fn recommend_action_boundaries() {
        assert_eq!(recommend_action(100), TrustAction::Allow);
        assert_eq!(recommend_action(70), TrustAction::Allow);
        assert_eq!(recommend_action(69), TrustAction::Restrict);
        assert_eq!(recommend_action(40), TrustAction::Restrict);
        assert_eq!(recommend_action(39), TrustAction::Quarantine);
        assert_eq!(recommend_action(0), TrustAction::Quarantine);
    }

    #[test]
    fn empty_factors_yield_zero() {
        let result = compute_score(&[], 0);
        assert_eq!(result.score, 0);
        assert_eq!(result.recommendation, TrustAction::Quarantine);
    }
}
