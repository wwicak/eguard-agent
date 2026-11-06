//! Calibrated behavioral context. Raw entropy and event cadence are not evidence.
use std::collections::{HashMap, HashSet, VecDeque};

use crate::information::{self, ConformalCalibrator};
use crate::types::{EventClass, TelemetryEvent};

/// Behavioral alarm with provenance.
#[derive(Debug, Clone)]
pub struct BehavioralAlarm {
    pub dimension: String,
    pub magnitude: f64,
    pub wasserstein_distance: Option<f64>,
    pub current_entropy: Option<f64>,
    pub p_value: Option<f64>,
    pub gated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BehavioralEngine {
    calibrator: Option<ConformalCalibrator>,
    // A bounded five-minute query history per process, not a global entropy sum.
    dns: HashMap<u32, VecDeque<(i64, String)>>,
    pub alarms: Vec<BehavioralAlarm>,
    pub total_alarms: u64,
}

impl BehavioralEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, event: &TelemetryEvent) -> Vec<BehavioralAlarm> {
        self.alarms.clear();
        if event.event_class == EventClass::ProcessExec && encoded_blob(event) {
            self.emit_alarm("cmdline_encoded_blob", 1.5);
        }
        if event.event_class == EventClass::DnsQuery {
            self.observe_dns(event);
        }
        self.total_alarms += self.alarms.len() as u64;
        self.alarms.clone()
    }

    pub fn calibrate(&mut self, scores: Vec<f64>, alpha: f64) {
        self.calibrator = Some(ConformalCalibrator::new(scores, alpha));
    }

    pub fn guaranteed_fp_rate(&self) -> Option<f64> {
        self.calibrator
            .as_ref()
            .filter(|c| c.calibration_size() >= 100)
            .map(|c| 1.0 - c.coverage_guarantee())
    }

    fn emit_alarm(&mut self, dimension: &str, magnitude: f64) {
        let p_value = self
            .calibrator
            .as_ref()
            .filter(|c| c.calibration_size() >= 100)
            .map(|c| c.p_value(magnitude));
        self.alarms.push(BehavioralAlarm {
            dimension: dimension.into(),
            magnitude,
            wasserstein_distance: None,
            current_entropy: None,
            p_value,
            gated: p_value.is_some_and(|p| p <= 0.01),
        });
    }

    fn observe_dns(&mut self, event: &TelemetryEvent) {
        let Some(domain) = event.dst_domain.as_deref() else {
            return;
        };
        if domain.len() > 253 || domain.split('.').any(|l| l.len() > 63) {
            return;
        }
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.split('.').count() < 2 {
            return;
        }
        let now = event.ts_unix;
        self.dns.retain(|_, q| {
            q.back()
                .is_some_and(|(ts, _)| now.saturating_sub(*ts) <= 300)
        });
        if self.dns.len() >= 1024 && !self.dns.contains_key(&event.pid) {
            return;
        }
        let queries = self.dns.entry(event.pid).or_default();
        // Ignore timestamps moving backwards rather than extending stale windows.
        if queries.back().is_some_and(|(ts, _)| now < *ts) {
            return;
        }
        while queries
            .front()
            .is_some_and(|(ts, _)| now.saturating_sub(*ts) > 300)
        {
            queries.pop_front();
        }
        queries.push_back((now, domain.clone()));
        if queries.len() > 512 {
            queries.pop_front();
        }
        let parent = dns_parent(&domain);
        let labels: HashSet<&str> = queries
            .iter()
            .filter(|(_, d)| dns_parent(d) == parent)
            .filter_map(|(_, d)| d.split('.').next())
            .collect();
        let tunnel = labels.len() >= 40
            && labels
                .iter()
                .map(|l| information::dns_entropy(l))
                .sum::<f64>()
                / labels.len() as f64
                >= 0.7;
        let parents: HashSet<&str> = queries
            .iter()
            .map(|(_, d)| dns_parent(d))
            .filter(|p| {
                p.split('.')
                    .next()
                    .is_some_and(|sld| sld.len() >= 10 && information::dns_entropy(sld) >= 0.75)
            })
            .collect();
        let dga = parents.len() >= 25;
        // Report on the crossing, not on every later query in the same window.
        let tunnel_crossing = tunnel
            && labels.len() == 40
            && !queries.iter().rev().skip(1).any(|(_, d)| d == &domain);
        let dga_crossing = dga
            && parents.len() == 25
            && !queries
                .iter()
                .rev()
                .skip(1)
                .any(|(_, d)| dns_parent(d) == parent);
        if tunnel_crossing {
            self.emit_alarm("dns_tunnel", 1.5);
        }
        if dga_crossing {
            self.emit_alarm("dns_dga", 1.5);
        }
    }
}

// Deliberately conservative approximation, not a public-suffix-list implementation.
fn dns_parent(domain: &str) -> &str {
    let labels: Vec<(usize, &str)> = domain
        .split('.')
        .scan(0, |pos, label| {
            let start = *pos;
            *pos += label.len() + 1;
            Some((start, label))
        })
        .collect();
    let n = labels.len();
    let suffix = if n >= 3
        && matches!(labels[n - 2].1, "co" | "com" | "net" | "org" | "gov" | "ac")
        && labels[n - 1].1.len() == 2
    {
        3
    } else {
        2
    };
    &domain[labels[n.saturating_sub(suffix)].0..]
}

pub(crate) fn basename(process: &str) -> String {
    process
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(process)
        .to_ascii_lowercase()
        .trim_end_matches(".exe")
        .into()
}

pub(crate) fn encoded_blob(event: &TelemetryEvent) -> bool {
    if event.event_class != EventClass::ProcessExec
        || matches!(
            basename(&event.process).as_str(),
            "chrome" | "chromium" | "msedge" | "teams" | "code" | "electron" | "slack"
        )
    {
        return false;
    }
    event.command_line.as_deref().is_some_and(|cmd| {
        cmd.split(|c: char| c.is_whitespace() || matches!(c, '\"' | '\'' | ','))
            .any(|t| {
                t.len() >= 100
                    && !t.starts_with("--")
                    && t.bytes()
                        .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
                        .count()
                        * 100
                        >= t.len() * 97
                    && information::char_entropy(t.as_bytes()) >= 5.0
            })
    })
}
