//! Offline bundle qualification using the exact agent compiler and matcher.
use detection::{compile_sigma_rule, TelemetryEvent};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.is_dir() {
            walk(&p, out)?;
        } else if matches!(p.extension().and_then(|s| s.to_str()), Some("yml" | "yaml")) {
            out.push(p);
        }
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().ok_or(
        "usage: sigma_gate RULE_DIR BENIGN_EVENTS_JSON [--filter] [--manifest IDS] [--report JSON]",
    )?);
    let events: Vec<TelemetryEvent> = serde_json::from_str(&fs::read_to_string(
        args.next().ok_or("missing benign events")?,
    )?)?;
    if events.is_empty() {
        return Err("benign corpus must not be empty".into());
    }
    let (mut filter, mut manifest, mut report) = (false, None, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--filter" => filter = true,
            "--manifest" => {
                manifest = Some(PathBuf::from(args.next().ok_or("missing manifest path")?))
            }
            "--report" => report = Some(PathBuf::from(args.next().ok_or("missing report path")?)),
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    let mut paths = Vec::new();
    walk(&dir, &mut paths)?;
    paths.sort();
    if paths.is_empty() {
        return Err("no sigma rules to qualify".into());
    }
    let mut rejected = BTreeMap::<String, usize>::new();
    let (mut failed, mut evaluations, mut hits) = (0, 0u64, 0u64);
    let mut elapsed = Duration::ZERO;
    let mut accepted = BTreeSet::new();
    let mut reasons = Vec::new();
    let mut fp_findings = Vec::new();
    for path in paths {
        let source = fs::read_to_string(&path)?;
        let relative = path
            .strip_prefix(&dir)?
            .to_string_lossy()
            .replace('\\', "/");
        let rule = match compile_sigma_rule(&source) {
            Ok(rule) => rule,
            Err(err) => {
                *rejected
                    .entry(
                        err.to_string()
                            .split(':')
                            .next()
                            .unwrap_or("unknown")
                            .to_string(),
                    )
                    .or_default() += 1;
                reasons.push(json!({"path":relative,"reason":err.to_string()}));
                eprintln!("SKIP {relative}: {err}");
                if filter {
                    fs::remove_file(&path)?;
                } else {
                    failed += 1;
                }
                continue;
            }
        };
        let doc: serde_yaml::Value = serde_yaml::from_str(&source)?;
        let id = doc["id"]
            .as_str()
            .ok_or("qualified rule lacks upstream id")?;
        if !accepted.insert(id.to_string()) {
            return Err(format!("duplicate rule id: {id}").into());
        }
        if rule.stages.len() != 1 {
            return Err("bundle contains temporal sequence; explicit replay required".into());
        }
        let predicate = &rule.stages[0].predicate;
        let class = predicate.event_class;
        let eligible = events.iter().filter(|e| e.event_class == class).count();
        if eligible == 0 {
            return Err(format!("no benign coverage for {}", class.as_str()).into());
        }
        let start = Instant::now();
        let count = events
            .iter()
            .filter(|e| e.event_class == class && predicate.matches(e))
            .count();
        elapsed += start.elapsed();
        evaluations += eligible as u64;
        hits += count as u64;
        let alerting = !matches!(doc["level"].as_str(), Some("low" | "informational"));
        if alerting && count * 100 >= eligible {
            fp_findings.push(json!({"id":id,"path":relative,"hits":count,"eligible":eligible}));
            eprintln!("FP_GATE {relative}: {count}/{eligible}");
            failed += 1;
        }
    }
    if let Some(manifest) = manifest {
        let expected: BTreeSet<String> = fs::read_to_string(manifest)?
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .map(String::from)
            .collect();
        let added: Vec<_> = accepted.difference(&expected).collect();
        let removed: Vec<_> = expected.difference(&accepted).collect();
        if !added.is_empty() || !removed.is_empty() {
            eprintln!("MANIFEST_MISMATCH added={added:?} removed={removed:?}");
            failed += 1;
        }
    }
    let output = json!({"compiled":accepted.len(),"accepted_ids":accepted,"rejected_by_reason":rejected,"rejections":reasons,
        "gate_failures":failed,"fp_findings":fp_findings,"evaluations":evaluations,"hits":hits,
        "evaluation_secs":elapsed.as_secs_f64(),"evaluations_per_sec":evaluations as f64 / elapsed.as_secs_f64()});
    if let Some(report) = report {
        fs::write(report, serde_json::to_string_pretty(&output)?)?;
    }
    println!("{output}");
    if accepted.is_empty() || failed > 0 {
        return Err("sigma qualification failed".into());
    }
    Ok(())
}
