//! Build-only qualification of the exact shipped YARA pack (never executes samples).
#[path = "../tests/support/yara_fixtures.rs"]
mod fixtures;
#[path = "../tests/support/yara_metrics.rs"]
mod metrics;
use detection::{Confidence, YaraEngine};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::PathBuf, time::Instant};

fn percentile(samples: &mut [u128], percentile: usize) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    samples.sort_unstable();
    samples[(samples.len() * percentile).div_ceil(100).saturating_sub(1)]
}
fn verify_hashes(
    root: &std::path::Path,
    manifest: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut expected = BTreeMap::new();
    for rule in manifest["rules"]
        .as_array()
        .ok_or("missing rule manifest")?
    {
        expected.insert(
            format!("{}.yar", rule["id"].as_str().ok_or("missing id")?),
            rule["rule_sha256"]
                .as_str()
                .ok_or("missing rule hash")?
                .to_string(),
        );
    }
    expected.insert(
        "default.yar".into(),
        manifest["eicar_sha256"]
            .as_str()
            .ok_or("missing EICAR hash")?
            .to_string(),
    );
    let mut observed = BTreeMap::new();
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    let mut entries = 0;
    while let Some((directory, depth)) = pending.pop() {
        if depth > 8 {
            return Err("rule directory depth limit".into());
        }
        for entry in directory.read_dir()? {
            let entry = entry?;
            entries += 1;
            if entries > 1024 {
                return Err("rule entry limit".into());
            }
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                return Err("symlink in curated pack".into());
            }
            if kind.is_dir() {
                pending.push((entry.path(), depth + 1));
                continue;
            }
            let path = entry.path();
            if entry.metadata()?.len() > 512 * 1024 {
                return Err("oversized curated pack file".into());
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let extension = path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if extension != "yar" && extension != "yara" {
                if !matches!(
                    name.as_str(),
                    "THIRD-PARTY-NOTICES.txt" | "provenance.json" | ".gitkeep"
                ) {
                    return Err("unexpected file in curated pack".into());
                }
                continue;
            }
            let hash = format!("{:x}", Sha256::digest(std::fs::read(path)?));
            if observed.insert(name, hash).is_some() {
                return Err("duplicate rule filename".into());
            }
        }
    }
    if observed != expected {
        return Err("curated rule hash/set differs from approved originals".into());
    }
    let provenance: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("provenance.json"))?)?;
    if &provenance != manifest {
        return Err("curated provenance differs from approved pins".into());
    }
    let notices = format!(
        "{:x}",
        Sha256::digest(std::fs::read(root.join("THIRD-PARTY-NOTICES.txt"))?)
    );
    if Some(notices.as_str()) != manifest["notices_sha256"].as_str() {
        return Err("third-party notices missing or altered".into());
    }
    Ok(())
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut options = BTreeMap::new();
    let mut bench = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bench-executables" => bench = true,
            "--rules" | "--manifest" | "--benign-list" | "--metrics" => {
                let value = args.next().ok_or("missing option value")?;
                options.insert(arg, value);
            }
            _ => return Err(format!("unknown option {arg}").into()),
        }
    }
    let rules = PathBuf::from(options.get("--rules").ok_or("--rules required")?);
    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(
        options.get("--manifest").ok_or("--manifest required")?,
    )?)?;
    let mut expected = manifest["rules"]
        .as_array()
        .ok_or("manifest rules missing")?
        .iter()
        .map(|rule| {
            rule["id"]
                .as_str()
                .ok_or("manifest rule id missing")
                .map(str::to_string)
        })
        .collect::<Result<Vec<_>, _>>()?;
    expected.push("eguard_eicar_test_file".into());
    expected.sort();
    verify_hashes(&rules, &manifest)?;
    let rss_before = metrics::rss_kib();
    let started = Instant::now();
    let mut engine = YaraEngine::new();
    if engine.backend_name() != "yara-x" {
        return Err("real YARA backend required".into());
    }
    let loaded = engine.load_rules_from_dir(&rules)?;
    let compile_ms = started.elapsed().as_secs_f64() * 1000.;
    if loaded != 10 || engine.rule_names() != expected {
        return Err(format!(
            "curated rule count/id drop: loaded={loaded}, actual={:?}",
            engine.rule_names()
        )
        .into());
    }
    let rss_compiled = metrics::rss_kib();
    let mut recall = 0;
    for (name, positive, negative) in fixtures::cases() {
        if !engine
            .scan_bytes(name, &positive)
            .iter()
            .any(|hit| hit.rule_name == name && hit.severity == Confidence::High)
        {
            return Err(format!("missing family positive {name}").into());
        }
        if !engine.scan_bytes("near-negative", &negative).is_empty() {
            return Err(format!("family near-negative matched {name}").into());
        }
        recall += 1;
    }
    let mut benign = 0;
    let mut high = 0;
    let mut all_matches = 0;
    let mut elapsed = Vec::new();
    let mut benign_scan_cpu = Vec::new();
    let mut benign_scan_wall = Vec::new();
    let mut incomplete = engine.take_incomplete();
    if let Some(list) = options.get("--benign-list") {
        for path in std::fs::read_to_string(list)?
            .lines()
            .filter(|line| !line.is_empty())
        {
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > 16 * 1024 * 1024
            {
                continue;
            }
            let mut file = std::fs::File::open(path)?;
            let mut header = [0u8; 4];
            let count = file.read(&mut header)?;
            let cap = engine.scan_cap(&header[..count]);
            if metadata.len() > cap as u64 {
                continue;
            }
            let started = Instant::now();
            let mut bytes = header[..count].to_vec();
            file.take(cap as u64 + 1).read_to_end(&mut bytes)?;
            if bytes.len() != metadata.len() as usize {
                return Err("benign file changed during read".into());
            }
            let _sha = Sha256::digest(&bytes);
            let scan_cpu = metrics::thread_cpu_ns();
            let scan_wall = Instant::now();
            let hits = engine.scan_bytes(path, &bytes);
            benign_scan_wall.push(scan_wall.elapsed().as_micros());
            if let (Some(before), Some(after)) = (scan_cpu, metrics::thread_cpu_ns()) {
                benign_scan_cpu.push((after - before) / 1000);
            }
            elapsed.push(started.elapsed().as_micros());
            benign += 1;
            high += usize::from(hits.iter().any(|hit| hit.severity >= Confidence::High));
            all_matches += hits.len();
            incomplete.extend(engine.take_incomplete());
        }
        if benign < 500 {
            return Err(format!("only {benign} eligible benign files; require500").into());
        }
    }
    let mut executable = Vec::new();
    if bench {
        let directory = tempfile::tempdir()?;
        for size in [1usize, 4, 8, 16] {
            for kind in ["PE", "ELF"] {
                let path = directory.path().join(format!("{kind}-{size}"));
                let data = if kind == "PE" {
                    fixtures::pe(size * 1024 * 1024, 128, false)
                } else {
                    let mut data = vec![0; size * 1024 * 1024];
                    data[..4].copy_from_slice(b"\x7fELF");
                    data
                };
                if data.len() > engine.scan_cap(&data) {
                    executable.push(
                        serde_json::json!({"kind":kind,"mib":size,"skipped_size_policy":true}),
                    );
                    continue;
                }
                std::fs::write(&path, &data)?;
                drop(data);
                let mut times = Vec::new();
                let mut scan_cpu_times = Vec::new();
                let mut scan_wall_times = Vec::new();
                let mut cpu_times = Vec::new();
                for _ in 0..50 {
                    let cpu_started = metrics::thread_cpu_ns();
                    let started = Instant::now();
                    let bytes = std::fs::read(&path)?;
                    let _digest = Sha256::digest(&bytes);
                    let scan_cpu = metrics::thread_cpu_ns();
                    let scan_wall = Instant::now();
                    let hits = engine.scan_bytes("synthetic executable benchmark", &bytes);
                    scan_wall_times.push(scan_wall.elapsed().as_micros());
                    if let (Some(before), Some(after)) = (scan_cpu, metrics::thread_cpu_ns()) {
                        scan_cpu_times.push((after - before) / 1000);
                    }
                    if !hits.is_empty() {
                        return Err("synthetic executable benchmark unexpectedly matched".into());
                    }
                    times.push(started.elapsed().as_micros());
                    if let (Some(before), Some(after)) = (cpu_started, metrics::thread_cpu_ns()) {
                        cpu_times.push((after - before) / 1000);
                    }
                    incomplete.extend(engine.take_incomplete());
                }
                let p50 = percentile(&mut times, 50);
                let p99 = percentile(&mut times, 99);
                executable
                    .push(serde_json::json!({"kind":kind,"mib":size,"samples":50,"p50_us":p50,"p99_us":p99,"cpu_p50_us":percentile(&mut cpu_times,50),"cpu_p99_us":percentile(&mut cpu_times,99),"scan_wall_p50_us":percentile(&mut scan_wall_times,50),"scan_wall_p99_us":percentile(&mut scan_wall_times,99),"scan_cpu_p50_us":percentile(&mut scan_cpu_times,50),"scan_cpu_p99_us":percentile(&mut scan_cpu_times,99)}));
            }
        }
    }
    let error_count = engine.status_handle().scan_error_count();
    let benign_p50 = if elapsed.is_empty() {
        0
    } else {
        percentile(&mut elapsed, 50)
    };
    let benign_p99 = if elapsed.is_empty() {
        0
    } else {
        percentile(&mut elapsed, 99)
    };
    let report = serde_json::json!({"backend":engine.backend_name(),"rule_count":loaded,"rule_ids":engine.rule_names(),"compile_ms":compile_ms,"rss_before_kib":rss_before,"rss_compiled_kib":rss_compiled,"rss_final_kib":metrics::rss_kib(),"family_positives":recall,"family_near_negatives":recall,"benign_files":benign,"benign_high":high,"benign_all_matches":all_matches,"benign_p50_us":benign_p50,"benign_p99_us":benign_p99,"benign_scan_wall_p50_us":percentile(&mut benign_scan_wall,50),"benign_scan_wall_p99_us":percentile(&mut benign_scan_wall,99),"benign_scan_cpu_p50_us":percentile(&mut benign_scan_cpu,50),"benign_scan_cpu_p99_us":percentile(&mut benign_scan_cpu,99),"executable_cap_mib":engine.scan_cap(b"MZ")/(1024*1024),"loadavg":std::fs::read_to_string("/proc/loadavg").ok(),"scan_errors":error_count,"incomplete":incomplete,"executable_benchmarks":executable,"health":engine.status_handle().health()});
    if let Some(path) = options.get("--metrics") {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(&report)? + "\n")?;
    }
    println!("{}", serde_json::to_string(&report)?);
    if high != 0 || error_count != 0 {
        return Err("YARA precision/incomplete qualification failed; see metrics".into());
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("YARA GATE FAILED: {error}");
        std::process::exit(1)
    }
}
