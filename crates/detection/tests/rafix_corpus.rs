//! External read-only audit corpora. Emits counts only; never rows or identities.
use detection::{Confidence, DetectionEngine, EventClass, TelemetryEvent};
use serde_json::Value;
use std::collections::BTreeMap;

fn class(s: &str) -> EventClass {
    match s {
        "process_exec" => EventClass::ProcessExec,
        "process_exit" => EventClass::ProcessExit,
        "file_open" => EventClass::FileOpen,
        "network_connect" => EventClass::NetworkConnect,
        "dns_query" => EventClass::DnsQuery,
        "module_load" => EventClass::ModuleLoad,
        "login" => EventClass::Login,
        _ => EventClass::Alert,
    }
}
fn event(
    process: &str,
    parent: &str,
    event_class: EventClass,
    ts: i64,
    pid: u32,
    uid: u32,
) -> TelemetryEvent {
    serde_json::from_value(serde_json::json!({"event_class":event_class, "ts_unix":ts,
        "pid":pid, "ppid":4, "uid":uid, "process":process, "parent_process":parent,
        "session_id":4, "file_write":false, "container_escape":false, "container_privileged":false})).expect("synthetic event shape")
}
fn string(v: &Value, key: &str) -> Option<String> {
    v[key].as_str().filter(|s| !s.is_empty()).map(str::to_owned)
}
#[derive(Default)]
struct Counts {
    total: usize,
    exec: usize,
    medium: usize,
    high: usize,
    behavioral_only_medium: usize,
    ml_positive: usize,
    gated: usize,
    high_causes: BTreeMap<String, usize>,
}
impl Counts {
    fn observe(&mut self, d: &mut DetectionEngine, e: &TelemetryEvent) {
        let o = d.process_event(e);
        self.total += 1;
        self.exec += usize::from(e.event_class == EventClass::ProcessExec);
        self.medium += usize::from(o.confidence == Confidence::Medium);
        self.high += usize::from(o.confidence >= Confidence::High);
        if o.confidence >= Confidence::High {
            for name in o.temporal_hits.iter().chain(o.kill_chain_hits.iter()) {
                *self.high_causes.entry(name.clone()).or_default() += 1;
            }
        }
        self.ml_positive += usize::from(o.ml_score.as_ref().is_some_and(|s| s.positive));
        self.gated += o.behavioral_alarms.iter().filter(|a| a.gated).count();
        self.behavioral_only_medium += usize::from(
            o.confidence == Confidence::Medium
                && o.behavioral_alarms.iter().any(|a| a.gated)
                && !o.anomaly.as_ref().is_some_and(|a| a.high || a.medium)
                && o.temporal_hits.is_empty()
                && o.kill_chain_hits.is_empty()
                && o.exploit_indicators.is_empty()
                && o.tamper_indicators.is_empty()
                && o.kernel_integrity_indicators.is_empty()
                && o.yara_hits.is_empty(),
        );
    }
    fn print(&self, label: &str) {
        println!("RAFIX_CORPUS {label} total={} exec={} medium={} high_plus={} behavioral_only_medium={} ml_positive={} gated_alarms={}",
            self.total,self.exec,self.medium,self.high,self.behavioral_only_medium,self.ml_positive,self.gated);
        println!(
            "RAFIX_CORPUS {label} high_rule_counts={:?}",
            self.high_causes
        );
    }
}
#[test]
#[ignore = "requires the external read-only audit corpus; aggregate output only"]
fn rafix_corpus_v2_aggregates() {
    let raw = std::fs::read_to_string("/home/dimas/eg-work/RULEFP/corpus/events-v2.json")
        .expect("read audit corpus");
    let rows: Vec<Value> = serde_json::from_str(&raw).expect("parse audit corpus");
    for platform in ["windows", "linux"] {
        let mut d = DetectionEngine::default_with_rules();
        let mut counts = Counts::default();
        let mut ts = 1_760_000_000;
        for row in rows
            .iter()
            .rev()
            .filter(|r| r["platform"].as_str() == Some(platform))
        {
            ts += 2;
            let process = row["process"].as_str().unwrap_or("unknown");
            let parent = row["parent"].as_str().unwrap_or("unknown");
            let pid = 1000 + process.bytes().map(u32::from).sum::<u32>() % 5000;
            let uid = if platform == "windows" || process == "root" {
                0
            } else {
                1000
            };
            let mut e = event(
                process,
                parent,
                class(row["event_class"].as_str().unwrap_or("")),
                ts,
                pid,
                uid,
            );
            e.command_line = string(row, "cmdline");
            e.file_path = string(row, "file_path");
            e.file_write = row["file_write"].as_bool().unwrap_or(false);
            counts.observe(&mut d, &e);
        }
        counts.print(platform);
    }
}
#[test]
#[ignore = "requires the external read-only audit corpus; aggregate output only"]
fn rafix_corpus_snapshot_aggregates() {
    let raw = std::fs::read_to_string("/home/dimas/eg-work/SIGFIX-corpus/events-full.json")
        .expect("read audit snapshot");
    let corpus: Value = serde_json::from_str(&raw).expect("parse audit snapshot");
    let mut engines = BTreeMap::new();
    let mut counts = Counts::default();
    for row in corpus["events"]
        .as_array()
        .expect("audit events array")
        .iter()
        .rev()
    {
        let data = if let Some(raw) = row["event_data"].as_str() {
            serde_json::from_str(raw).expect("parse event data")
        } else {
            row["event_data"].clone()
        };
        let v = &data["event"];
        let mut e = event(
            v["process"].as_str().unwrap_or("unknown"),
            v["parent_process"].as_str().unwrap_or("unknown"),
            class(v["event_class"].as_str().unwrap_or("")),
            v["ts_unix"].as_i64().unwrap_or(0),
            v["pid"].as_u64().unwrap_or(0) as u32,
            v["uid"].as_u64().unwrap_or(0) as u32,
        );
        e.ppid = v["ppid"].as_u64().unwrap_or(0) as u32;
        e.session_id = v["session_id"].as_u64().unwrap_or(0) as u32;
        e.command_line = string(v, "command_line");
        e.file_path = string(v, "file_path");
        e.file_hash = string(v, "file_hash");
        e.file_write = v["file_write"].as_bool().unwrap_or(false);
        e.dst_ip = string(v, "dst_ip");
        e.dst_domain = string(v, "dst_domain");
        e.dst_port = v["dst_port"].as_u64().map(|p| p as u16);
        e.event_size = v["event_size"].as_u64();
        let d = engines
            .entry(row["agent_id"].as_str().unwrap_or("unknown").to_owned())
            .or_insert_with(DetectionEngine::default_with_rules);
        counts.observe(d, &e);
    }
    counts.print("snapshot");
}
