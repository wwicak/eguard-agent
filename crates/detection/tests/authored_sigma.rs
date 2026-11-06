use std::path::Path;

use detection::{compile_sigma_rule, EventClass, TelemetryEvent, TemporalEngine};
use serde_json::Value;

fn event(v: &Value, ts: i64) -> TelemetryEvent {
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    TelemetryEvent {
        ts_unix: ts,
        event_class: match s("class").as_str() {
            "file_open" => EventClass::FileOpen,
            _ => EventClass::ProcessExec,
        },
        pid: 42,
        ppid: 1,
        uid: 1000,
        process: s("process"),
        parent_process: s("parent"),
        session_id: 42,
        file_path: v["file_path"].as_str().map(String::from),
        file_write: v["file_write"].as_bool().unwrap_or(false),
        command_line: v["cmdline"].as_str().map(String::from),
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    }
}

#[test]
fn authored_verdict_recall_and_precision() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/authored_sigma_cases.json")).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut failures = Vec::new();
    let mut total = 0;
    for case in cases {
        let path = root.join(case["file"].as_str().unwrap());
        let source = std::fs::read_to_string(&path).unwrap();
        // Exercise Windows selection semantics on Linux too; the independent fidelity
        // suite proves foreign-platform rejection in the production compiler.
        let source = source
            .replace("  product: windows\n", "")
            .replace("  product: linux\n", "");
        let rule = compile_sigma_rule(&source).unwrap();
        for (kind, expected) in [("must_fire", true), ("must_not_fire", false)] {
            for (i, sequence) in case[kind].as_array().unwrap().iter().enumerate() {
                total += 1;
                let mut engine = TemporalEngine::new();
                engine.add_rule(rule.clone());
                let fired = sequence
                    .as_array()
                    .unwrap()
                    .iter()
                    .enumerate()
                    .any(|(t, v)| !engine.observe(&event(v, 100 + t as i64)).is_empty());
                if fired != expected {
                    failures.push(format!(
                        "{} {kind}[{i}] expected={expected} fired={fired}",
                        case["id"]
                    ));
                }
            }
        }
    }
    println!(
        "authored cases: {}/{} passed",
        total - failures.len(),
        total
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
