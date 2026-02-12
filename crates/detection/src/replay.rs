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
