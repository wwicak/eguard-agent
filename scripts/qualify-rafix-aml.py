#!/usr/bin/env python3
"""Bounded semantic mutation checks for RAFIX-AML. Run only in this worktree.
Each mutant is restored in finally; compilation/setup errors never count as kills.
Logs contain synthetic test output only. No deployment, kernel hooks or network.
"""
import argparse
import json
import os
import signal
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidence"
OUT.mkdir(exist_ok=True)
(OUT / "tmp").mkdir(exist_ok=True)
(OUT / "tmp/empty-replay").write_text("")
ENV = dict(os.environ, CARGO_TARGET_DIR="/home/dimas/eg-work/rafix-target-aml",
           CARGO_BUILD_JOBS="4", TMPDIR=str(OUT / "tmp"),
           EGUARD_EBPF_REPLAY_PATH=str(OUT / "tmp/empty-replay"), EGUARD_DETECTION_SHARDS="1")
CASES = []


def interrupted(_signal, _frame):
    raise KeyboardInterrupt("qualification interrupted; restoring active mutant")


signal.signal(signal.SIGTERM, interrupted)


def case(name, path, old, new, package="detection", test="rafix_", group="detection"):
    CASES.append((name, path, old, new, package, test, group))


def function(text, name):
    start = text.index("fn " + name + "(")
    end = text.find("\nfn ", start + 3)
    return text[start:end if end >= 0 else len(text)].rstrip()


def restore_function(name, path, symbol, test="rafix_"):
    current = (ROOT / path).read_text()
    base = subprocess.check_output(["git", "show", "fe43f8a:" + path], cwd=ROOT, text=True)
    case(name, path, function(current, symbol), function(base, symbol), test=test)


B = "crates/detection/src/behavioral.rs"
F = "crates/detection/src/layer5/features.rs"
M = "crates/detection/src/layer5/model.rs"
E = "crates/detection/src/layer5/engine.rs"
X = "crates/detection/src/exploit.rs"
K = "crates/detection/src/kernel_integrity.rs"
T = "crates/detection/src/tamper.rs"
R = "crates/agent-core/src/lifecycle/response_pipeline.rs"
S = "crates/agent-core/src/lifecycle/kernel_integrity_scan.rs"
L = "crates/platform-linux/src/kernel_integrity.rs"

case("behavioral-maturity", B, "c.calibration_size() >= 100", "c.calibration_size() >= 1")
case("cmdline-magnitude", B, 'self.emit_alarm("cmdline_encoded_blob", 1.5)', 'self.emit_alarm("cmdline_encoded_blob", 3.0)')
case("info-shift-cadence", B, "self.alarms.clear();", 'self.alarms.clear();\n        if event.ts_unix % 64 == 0 { self.emit_alarm("cmdline_entropy_shift", 6.0); }')
case("root-exec-cadence", B, "self.alarms.clear();", 'self.alarms.clear();\n        if event.uid == 0 && event.ts_unix % 6 == 0 { self.emit_alarm("root_exec_rate", 1.0); }')
case("dns-service-entropy", B, "if tunnel_crossing {", "if tunnel_crossing || domain.len() > 12 {")
case("ml-uncalibrated", E, "let mut positive = raw_positive && calibrated;", "let mut positive = raw_positive;")
case("ml-maturity", E, "c.calibration_size() >= 100", "c.calibration_size() >= 1")
case("ml-reload", E, "self.calibrator = None;", "// retained stale model calibration")
case("windows-root", F, "event.uid == 0 && !windows", "event.uid == 0")
for name, symbol in [("credential", "credential_access_indicator"), ("lsass", "lsass_access_indicator"),
                     ("sam", "sam_access_indicator"), ("token", "token_theft_indicator"),
                     ("process-basename", "rare_parent_child_pair"), ("lolbin-basename", "lolbin_credential_chain"),
                     ("file-extension", "executable_write_ratio"), ("ip-address", "unique_dst_ip_norm")]:
    restore_function(name, F, symbol)
case("cmdline-feature", F, "crate::behavioral::encoded_blob(event)", "event.command_line.is_some()")
case("model-label-source", M, "if !real_labels || !calibrated {", "if !calibrated {")
case("model-calibration", M, "if !real_labels || !calibrated {", "if !real_labels {")
case("tree-feature", M, "node.leaf.is_none() && !FEATURE_NAMES.contains(&node.feature.as_str())", "false")
case("tmp-strong-signal", X, '"fileless_fd_exec"\n            | "exec_from_shm"', '"fileless_fd_exec"\n            | "exec_from_tmp"\n            | "exec_from_shm"')
case("fd-regular-image", X, "&& !regular_system", "&& true")
case("fd-runc-clone", X, "&& !clone", "&& true")
case("stdin-interpreter", X, "&& args\n        .iter()\n        .skip(1)\n        .all(|a| matches!(*a, \"-s\" | \"-\" | \"-x\" | \"--\"))", "&& true")
case("preload-builder", X, "if !build_parent", "if true")
case("decoded-execution", X, "decode = true;", 'decode = true; indicators.push("encoded_payload_exec".into());')
case("tamper-read", T, "!(event.file_write || event.file_unlink)", "false")
case("tamper-unlink", T, "event.file_write || event.file_unlink", "event.file_write")
case("tamper-installer", T, 'process.as_str(),\n        "dpkg"', 'process.as_str(),\n        "not_an_installer"')
case("kernel-medium-boolean", "crates/detection/src/engine.rs", ">= Confidence::High,", ">= Confidence::Medium,")
case("kernel-known-rootkits", K, "KNOWN_ROOTKITS.contains(&name.as_str())", "false")
case("kernel-module-substring", K, "if KNOWN_ROOTKITS.contains(&name.as_str()) {", 'if name.contains("rk") || KNOWN_ROOTKITS.contains(&name.as_str()) {')
case("memory-jit", "crates/detection/src/memory_scanner.rs", "!jit\n                    &&", "true\n                    &&")
case("hunting-basename", "crates/detection/src/threat_hunting.rs", "lower == crate::behavioral::basename(sub.trim())", "lower.contains(&crate::behavioral::basename(sub.trim()))")
case("deception-defaults", "crates/detection/src/deception.rs", "pub fn default_tokens() -> Vec<DeceptionToken> {\n    Vec::new()\n}", 'pub fn default_tokens() -> Vec<DeceptionToken> { vec![DeceptionToken { name: "fixture".into(), token_type: TokenType::CredentialFile, path: "/var/lib/eguard-agent/decoy/synthetic".into(), deployed: true, triggered_count: 0 }] }')
case("zero-trust-coverage", "crates/detection/src/zero_trust.rs", "if total_weight < 0.5 {", "if false {")
case("usb-wireless", "crates/detection/src/usb_control.rs", "USB_CLASS_CDC => UsbDeviceClass::Network,", "USB_CLASS_CDC | 0xe0 => UsbDeviceClass::Network,")
case("fim-network", "crates/detection/src/fim.rs", '    "/etc/passwd",', '    "/etc/resolv.conf",\n    "/etc/passwd",')
case("replay-heuristics", "crates/detection/src/replay.rs", 'rule_hits.extend(indicators.iter().map(|name| format!("{kind}:{name}")));', 'let _ = (kind, indicators);')

case("ml-rule-echo-low", "crates/detection/src/engine.rs", "Confidence::None if calibrated", "Confidence::Low if ml.positive => Confidence::Medium,\n        Confidence::None if calibrated")
case("ml-rule-echo-high", "crates/detection/src/engine.rs", "Confidence::None if calibrated", "Confidence::High if ml.positive => Confidence::VeryHigh,\n        Confidence::None if calibrated")
case("ml-only-calibration", "crates/detection/src/engine.rs", "calibrated && ml.positive", "ml.positive")
case("gated-alarm-feature", "crates/detection/src/engine.rs", "behavioral_alarms.iter().filter(|a| a.gated).count()", "behavioral_alarms.len()")
case("placeholder-values", F, "Self { values }", "values[27] = 0.32; Self { values }")
case("placeholder-weights", M, "0.0, // event_size_norm", "0.2, // event_size_norm")
restore_function("file-read-churn", F, "rename_churn_norm")
restore_function("file-windows-path", F, "temp_to_system_write_ratio")
restore_function("network-port-risk", F, "dst_port_risk_score")
case("lateral-native-names", "crates/detection/src/lateral_movement.rs", '"psexesvc" | "chisel" | "ligolo"', '"wmic" | "schtasks" | "psexesvc" | "chisel" | "ligolo"')
case("lateral-ssh-process", "crates/detection/src/lateral_movement.rs", 'matches!(process.as_str(), "ssh" | "plink" | "autossh")', 'true')
case("lateral-auth-reader", "crates/detection/src/lateral_movement.rs", "&& !unix_owner", "&& true")
case("deception-reader", "crates/detection/src/deception.rs", '"low"', '"high"')
case("zero-trust-unknown", "crates/detection/src/zero_trust.rs", "f.known &&", "true &&")
case("hunting-deleted-defaults", "crates/detection/src/threat_hunting.rs", 'vec![HuntingQuery {', 'vec![HuntingQuery { name: "reverse_shell_listener".into(), description: "fixture".into(), technique_id: None, interval_secs: 300, check: HuntingCheck::ListeningPorts { suspicious_ports: vec![8888] }, last_run: 0, findings_count: 0 }, HuntingQuery {')
case("vulnerability-module", "crates/detection/src/engine.rs", "let vulnerable_software = false;", "let vulnerable_software = event.event_class == EventClass::ModuleLoad && event.file_path.as_deref().is_some_and(|p| self.cve.check_module_path(p));")
case("scan-initstate", L, 'read_trimmed(&initstate_path).as_deref() != Some("live")', '!initstate_path.exists()', "platform-linux", "rafix_kscan", "linux")
case("scan-lsm-inventory", L, "report.lsm_list = list.clone();", 'report.lsm_list = list.clone(); report.indicators.push("lsm_bpf_enabled".into());', "platform-linux", "rafix_kscan", "linux")
case("scan-probe-inventory", L, "report.kprobe_count = count;", 'report.kprobe_count = count; report.indicators.push(format!("kprobe_hook_count:{count}"));', "platform-linux", "rafix_kscan", "linux")

# Linux fixture tests never read real /proc or tracefs.
case("scan-taint", L, "if taint.contains('O') && taint.contains('E') {", "if taint.parse::<u64>().is_ok() {", "platform-linux", "rafix_kscan", "linux")
case("scan-probe-token", L, "parts[1].split('+')", "parts[parts.len()-1].split('+')", "platform-linux", "rafix_kscan", "linux")
case("scan-ftrace-comment", L, "!line.is_empty() && !line.starts_with('#')", "!line.is_empty()", "platform-linux", "rafix_kscan", "linux")
case("scan-stock-pins", L, '"snap" | "tc" | "ip" | "xdp" | "cilium" | "calico" | "systemd"', '"not_a_stock_pin"', "platform-linux", "rafix_kscan", "linux")

# Pure response tests: no runtime construction, network or destructive calls.
for name, old in [("response-pid", "&& w.pid == event.pid"), ("response-session", "&& w.session_id == event.session_id"),
                  ("response-timestamp", "&& w.ts_unix == event.ts_unix"), ("response-file", "&& w.file_path.as_deref() == Some(path)")]:
    case(name, R, old, "&& true", "agent-core", "rafix_response", "core")
case("response-current-event", R, "w.event_id == id", "true", "agent-core", "rafix_response", "core")
case("response-template", R, "&& outcome.kill_chain_hits.contains(&chain.template)", "&& true", "agent-core", "rafix_response", "core")
case("response-yara-source", R, "&& hit.source == path", "&& true", "agent-core", "rafix_response", "core")
case("response-exact-hash", R, '.exact_matched_fields\n                .iter()\n                .any(|f| f == "file_hash")', '.matched_fields\n                .iter()\n                .any(|f| f == "file_hash")', "agent-core", "rafix_response", "core")
case("response-hash-required", R, 'h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())', "true", "agent-core", "rafix_response", "core")
case("response-deception", R, 'let file_event =', 'if outcome.signals.deception_triggered { return true; }\n        let file_event =', "agent-core", "rafix_response", "core")
case("scan-confirmation", S, "!persistent || now.saturating_sub(*first) >= 2", "true", "agent-core", "rafix_kernel_scan", "core")
case("scan-baseline", S, "if inventory(i) && self.baseline.contains(*i) {", "if false {", "agent-core", "rafix_kernel_scan", "core")
case("memory-silent-drop", "crates/agent-core/src/lifecycle/memory_scan.rs", "if detection.hits.is_empty() {", "if true {", "agent-core", "rafix_memory_hits", "core")
case("memory-forced-confidence", "crates/agent-core/src/lifecycle/memory_scan.rs", 'if strong { "high" } else { "medium" }', 'if strong { "very_high" } else { "very_high" }', "agent-core", "rafix_memory_hits", "core")

case("response-confidence", R, "outcome.confidence < detection::Confidence::VeryHigh", "false", "agent-core", "rafix_response", "core")
case("response-unlink", R, "|| event.file_unlink", "|| false", "agent-core", "rafix_response", "core")
case("response-file-event", R, "if !file_event {", "if false {", "agent-core", "rafix_response", "core")
case("response-yara-rule", R, "!hit.rule_name.is_empty() &&", "true &&", "agent-core", "rafix_response", "core")
case("response-template-name", R, "!chain.template.is_empty()", "true", "agent-core", "rafix_response", "core")
case("response-yara-required", R, '&& outcome\n                .yara_hits\n                .iter()\n                .any(|hit| !hit.rule_name.is_empty() && hit.source == path)', '&& true', "agent-core", "rafix_response", "core")
case("scan-restart-persistence", S, "fn save_scan_state(path: &Path, state: &KernelScanState) {", "fn save_scan_state(path: &Path, state: &KernelScanState) { return;", "agent-core", "fresh_kernel_runtime_confirms", "core")

case("exact-field-provenance", "crates/detection/src/layer1.rs", 'Layer1Result::PrefilterOnly => {', 'Layer1Result::PrefilterOnly => { hit.exact_matched_fields.push(field.to_string());')
case("exec-warmup", B, "if warmed", "if true")
case("exec-sample-maturity", B, "rate.samples >= 300", "true")
case("exec-parent-scope", B, ".entry(event.ppid)", ".entry(event.pid)")
case("exec-once-per-second", B, "&& !rate.alerted", "&& true")
case("exec-minimum-count", B, "rate.count >= 50", "rate.count >= 1")
case("exec-relative-rate", B, "count >= 10.0 * rate.mean.max(1.0)", "count >= rate.mean.max(1.0)")
case("exec-magnitude", B, 'self.emit_alarm("exec_burst", 1.5)', 'self.emit_alarm("exec_burst", 3.0)')
case("exec-mean-learning", B, "rate.mean += 0.05 * delta;", "// no mean learning")
case("beacon-cv", "crates/detection/src/beaconing.rs", "detected: cv <= 0.25", "detected: false")
case("beacon-private", "crates/detection/src/beaconing.rs", "host.parse::<IpAddr>().ok().is_some_and(local_address)", "false")
case("beacon-configured-peer", "crates/detection/src/engine.rs", "&& !self.layer4.peer_is_configured_server(event)", "&& true")
case("beacon-sample-maturity", "crates/detection/src/beaconing.rs", "state.intervals.len() < MIN_INTERVALS", "false")
case("beacon-timescale", "crates/detection/src/beaconing.rs", "!(10.0..=21600.0).contains(&mean)", "false")
case("beacon-event-size", "crates/detection/src/beaconing.rs", "self.tick = self.tick.wrapping_add(1);", "if _event_size == 0 { return quiet; } self.tick = self.tick.wrapping_add(1);")

case("noise-ungated-alarms", "crates/agent-core/src/lifecycle/telemetry_noise.rs", "outcome.behavioral_alarms.iter().any(|a| a.gated)", "!outcome.behavioral_alarms.is_empty()", "agent-core", "rafix_noise_evidence", "core")

case("hash-attribution", "crates/agent-core/src/lifecycle/detection_event.rs", 'enriched.file_sha256.clone()\n        },\n        dst_port', 'enriched.file_sha256.clone().or_else(|| enriched.process_exe_sha256.clone())\n        },\n        dst_port', "agent-core", "rafix_mapping", "core")
case("scan-forced-high", S, 'detection::kernel_integrity_confidence(&outcome.kernel_integrity_indicators);', 'detection::kernel_integrity_confidence(&outcome.kernel_integrity_indicators).max(Confidence::High);', "agent-core", "identical_kernel_integrity_scans_emit", "core")

case("image-cache-invocation-fallback", "crates/platform-linux/src/lib.rs", '.map(|p| p.to_string_lossy().into_owned());', '.map(|p| p.to_string_lossy().into_owned()).or_else(|| payload_meta.and_then(|m| m.file_path.clone()));', "platform-linux", "rafix_", "linux")
case("image-output-invocation-fallback", "crates/platform-linux/src/lib.rs", 'let process_exe = entry.process_exe;', 'let process_exe = entry.process_exe.or_else(|| payload_meta.file_path.clone());', "platform-linux", "rafix_", "linux")
case("image-reexec-refresh", "crates/platform-linux/src/lib.rs", 'if same_process_instance && same_exec {', 'if same_process_instance {', "platform-linux", "rafix_", "linux")
case("image-prime-continuity", "crates/platform-linux/src/lib.rs", 'if same_process_instance && same_exec {', 'if false {', "platform-linux", "rafix_", "linux")
case("image-display-fallback", "crates/agent-core/src/lifecycle/detection_event.rs", '.or(process_name_from_invocation)', '', "agent-core", "rafix_mapping", "core")


def run(package, test, log):
    cmd = ["cargo", "test", "--offline", "-p", package, test, "--", "--test-threads=1"]
    result = subprocess.run(cmd, cwd=ROOT, env=ENV, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=2700)
    log.write_bytes(result.stdout)
    return result.returncode, result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("group", choices=["detection", "linux", "core"])
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    selected = [c for c in CASES if c[-1] == args.group and (not args.only or c[0] in args.only.split(','))]
    results = []
    for package, test in sorted({(c[4], c[5]) for c in selected}):
        rc, output = run(package, test, OUT / f"mutant-green-{package}-{test}.log")
        if rc or b"test result: ok" not in output:
            raise SystemExit(f"unmutated baseline failed: {package} {test}")
    for name, relative, old, new, package, test, _ in selected:
        path = ROOT / relative
        original = path.read_text()
        if old not in original:
            results.append({"name": name, "result": "not-run", "reason": "anchor missing"})
            print(name, "ANCHOR MISSING", flush=True)
            continue
        try:
            path.write_text(original.replace(old, new) if name == "behavioral-maturity" else original.replace(old, new, 1))
            rc, output = run(package, test, OUT / f"mutant-{name}.log")
            killed = rc != 0 and b"test result: FAILED" in output and b"could not compile" not in output
            results.append({"name": name, "result": "killed" if killed else "survived-or-invalid"})
            print(name, results[-1]["result"], flush=True)
        finally:
            path.write_text(original)
    result_path = OUT / f"mutants-{args.group}.json"
    previous = json.loads(result_path.read_text()) if result_path.exists() else []
    updated = {r["name"]: r for r in previous}
    updated.update({r["name"]: r for r in results})
    result_path.write_text(json.dumps(list(updated.values()), indent=2) + "\n")
    if any(r["result"] != "killed" for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
