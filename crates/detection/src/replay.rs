use std::collections::HashMap;

use crate::{Confidence, DetectionEngine, Layer1Result, TelemetryEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayAlert {
    pub index: usize,
    pub ts_unix: i64,
    pub entity: String,
    pub confidence: Confidence,
    pub rule_hits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReplaySummary {
    pub total_events: usize,
    pub alerts: Vec<ReplayAlert>,
    pub definite: usize,
    pub very_high: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessDriftQuantiles {
    pub p50_kl_bits: f64,
    pub p95_kl_bits: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DriftIndicators {
    pub baseline_age_secs: u64,
    pub kl_quantiles_by_process_family: HashMap<String, ProcessDriftQuantiles>,
}

pub fn replay_events(engine: &mut DetectionEngine, events: &[TelemetryEvent]) -> ReplaySummary {
    let mut summary = ReplaySummary {
        total_events: events.len(),
        ..ReplaySummary::default()
    };

    for (index, event) in events.iter().enumerate() {
        let outcome = engine.process_event(event);
        let confidence = outcome.confidence;
        bump_confidence_count(&mut summary, confidence);

        if matches!(confidence, Confidence::None) {
            continue;
        }

        let mut rule_hits = Vec::new();
        if outcome.layer1.result == Layer1Result::ExactMatch {
            rule_hits.push("layer1_exact".to_string());
        }
        if !outcome.temporal_hits.is_empty() {
            rule_hits.extend(
                outcome
                    .temporal_hits
                    .into_iter()
                    .map(|v| format!("l2:{}", v)),
            );
        }
        if !outcome.kill_chain_hits.is_empty() {
            rule_hits.extend(
                outcome
                    .kill_chain_hits
                    .into_iter()
                    .map(|v| format!("l4:{}", v)),
            );
        }
        if !outcome.yara_hits.is_empty() {
            rule_hits.extend(
                outcome
                    .yara_hits
                    .into_iter()
                    .map(|v| format!("yara:{}", v.rule_name)),
            );
        }
        rule_hits.sort();
        rule_hits.dedup();

        summary.alerts.push(ReplayAlert {
            index,
            ts_unix: event.ts_unix,
            entity: event.entity_key(),
            confidence,
            rule_hits,
        });
    }

    summary
}

pub fn report_drift_indicators(
    engine: &mut DetectionEngine,
    events: &[TelemetryEvent],
    baseline_last_refresh_unix: i64,
    now_unix: i64,
) -> DriftIndicators {
    let mut kl_by_family: HashMap<String, Vec<f64>> = HashMap::new();

    for event in events {
        let outcome = engine.process_event(event);
        if let Some(anomaly) = outcome.anomaly {
            kl_by_family
                .entry(event.process_key())
                .or_default()
                .push(anomaly.kl_bits);
        }
    }

    let mut quantiles = HashMap::new();
    for (family, mut values) in kl_by_family {
        values.sort_by(|a, b| a.total_cmp(b));
        let p50 = percentile_sorted(&values, 0.50);
        let p95 = percentile_sorted(&values, 0.95);
        quantiles.insert(
            family,
            ProcessDriftQuantiles {
                p50_kl_bits: p50,
                p95_kl_bits: p95,
            },
        );
    }

    DriftIndicators {
        baseline_age_secs: now_unix
            .saturating_sub(baseline_last_refresh_unix)
            .max(0) as u64,
        kl_quantiles_by_process_family: quantiles,
    }
}

fn percentile_sorted(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let idx = ((values.len() - 1) as f64 * p).round() as usize;
    values[idx.min(values.len() - 1)]
}

fn bump_confidence_count(summary: &mut ReplaySummary, confidence: Confidence) {
    match confidence {
        Confidence::Definite => summary.definite += 1,
        Confidence::VeryHigh => summary.very_high += 1,
        Confidence::High => summary.high += 1,
        Confidence::Medium => summary.medium += 1,
        Confidence::Low => summary.low += 1,
        Confidence::None => {}
    }
}
