"""Precision gates use synthetic indicators only; no customer data."""
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "threat-intel/processing"))
import ioc_allowlist
import ioc_dedup
import sigma_filter


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


@pytest.mark.parametrize("host", ["docs.google.com", "drive.google.com", "sites.google.com", "pastebin.com", "tinyurl.com", "a.docs.google.com", "firebasestorage.googleapis.com", "dweb.link", "synthetic.sharepoint.com", "onedrive.live.com", "objects.githubusercontent.com", "dropbox.com", "dl.dropboxusercontent.com", "synthetic.blob.core.windows.net", "ipfs.io", "synthetic.workers.dev", "synthetic.pages.dev", "synthetic.web.app", "synthetic.firebaseapp.com", "synthetic.github.io", "synthetic.vercel.app", "synthetic.netlify.app"])
def test_shared_hosts_never_survive_domain_curation(tmp_path, host):
    src, dst = tmp_path / "in", tmp_path / "out"
    write_jsonl(src, [{"value": host, "sources": ["urlhaus"]}, {"value": "dedicated-c2.example", "sources": ["urlhaus"]}])
    ioc_allowlist.filter_iocs(str(src), str(dst), set())
    assert [row["value"] for row in read_jsonl(dst)] == ["dedicated-c2.example"]


def test_bogons_and_overlapping_special_networks_are_removed(tmp_path):
    src, dst = tmp_path / "in", tmp_path / "out"
    special = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15", "224.0.0.0/3", "239.255.255.250", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "0.0.0.0/0", "::1", "::1234", "2001:db8::/32", "fc00::/7", "ff00::/8", "not-an-ip"]
    write_jsonl(src, [{"value": v} for v in special + ["8.8.8.9", "193.0.0.0/24"]])
    ioc_allowlist.filter_ip_iocs(str(src), str(dst), set(), [])
    assert {row["value"] for row in read_jsonl(dst)} == {"8.8.8.9", "193.0.0.0/24"}


def test_cidr_cannot_cover_an_allowlisted_resolver(tmp_path):
    src, dst = tmp_path / "in", tmp_path / "out"
    write_jsonl(src, [{"value": "8.0.0.0/8"}])
    ioc_allowlist.filter_ip_iocs(str(src), str(dst), {"8.8.8.8"}, [])
    assert read_jsonl(dst) == []


def test_staleness_uses_feed_observation_dates_before_corroboration():
    old = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
    fresh = datetime.now(timezone.utc).isoformat()
    rows = [{"value": "synthetic-c2.example", "source": "feodo", "last_seen": old},
            {"value": "synthetic-c2.example", "source": "otx", "last_seen": fresh},
            {"value": "expired.example", "source": "urlhaus", "timestamp": old}]
    result = ioc_dedup.deduplicate(rows, "domains")
    assert len(result) == 1
    assert result[0]["sources"] == ["otx"]
    assert result[0]["confidence"] == "low"
    assert result[0]["last_seen"] == fresh


def test_dedup_preserves_merged_provenance_and_recomputes_confidence():
    fresh = datetime.now(timezone.utc).isoformat()
    rows = [{"value": "DEDICATED.example.", "sources": ["threatfox", "urlhaus"], "confidence": "low", "last_seen": fresh},
            {"value": "dedicated.example", "source": "otx", "timestamp": fresh}]
    result = ioc_dedup.deduplicate(rows, "domains")
    assert len(result) == 1
    assert result[0]["sources"] == ["otx", "threatfox", "urlhaus"]
    assert result[0]["confidence"] == "high"


def test_supplemental_merge_does_not_refresh_old_feed_dates(tmp_path):
    import merge_plain_iocs
    target, supplement = tmp_path / "target", tmp_path / "plain"
    write_jsonl(target, [{"value": "expired.example", "sources": ["urlhaus"], "first_seen": "2020-01-01T00:00:00Z", "last_seen": "2020-01-02T00:00:00Z"}])
    supplement.write_text("expired.example\nnew.example\n")
    merge_plain_iocs.main(["--target", str(target), "--merge", f"{supplement}:phishing_database:medium"])
    rows = {row["value"]: row for row in read_jsonl(target)}
    assert rows["expired.example"]["last_seen"] == "2020-01-02T00:00:00Z"
    assert rows["new.example"]["first_seen"] == rows["new.example"]["last_seen"] == ""


@pytest.mark.parametrize("filename,origin", [("otx.txt", "otx"), ("unknown_raw.txt", "other")])
def test_raw_feed_cannot_claim_another_sources_confidence(tmp_path, filename, origin):
    path = tmp_path / filename
    write_jsonl(path, [{"value": "dedicated-c2.example", "source": "spamhaus", "sources": ["spamhaus", "urlhaus"], "last_seen": datetime.now(timezone.utc).isoformat()}])
    rows = ioc_dedup.deduplicate(ioc_dedup.parse_ioc_file(str(path)), "domains")
    assert rows[0]["sources"] == [origin]
    assert rows[0]["confidence"] == "low"


def test_dedup_canonicalizes_equivalent_ip_networks():
    rows = [{"value": "193.0.0.1/24", "source": "spamhaus"}, {"value": "193.0.0.0/24", "source": "feodo"}, {"value": "2606:4700:0000:0000::1", "source": "feodo"}, {"value": "2606:4700::1", "source": "urlhaus"}]
    result = ioc_dedup.deduplicate(rows, "ips")
    assert len(result) == 2
    assert {row["value"] for row in result} == {"193.0.0.0/24", "2606:4700::1"}


def test_undated_plain_feeds_do_not_fabricate_observation_dates(tmp_path):
    path = tmp_path / "feodo.txt"
    path.write_text("8.8.8.9\n")
    rows = ioc_dedup.parse_ioc_file(str(path))
    assert not rows[0].get("timestamp")
    result = ioc_dedup.deduplicate(rows, "ips")
    assert result[0]["first_seen"] == ""
    assert result[0]["last_seen"] == ""


@pytest.mark.parametrize("logsource,keep", [
    ({"category": "process_creation", "product": "linux"}, True),
    ({"category": "process_creation", "product": "windows"}, False),
    ({"category": "process_creation", "service": "auditd", "product": "linux"}, False),
    ({"category": "proxy"}, False), ({"category": "webserver", "product": "linux"}, False),
    ({"category": "dns", "product": "linux"}, True), ({}, False)])
def test_sigma_filter_only_keeps_observable_logs(logsource, keep):
    assert sigma_filter.should_keep_rule({"status": "stable", "logsource": logsource}, {"linux"}, "stable") == keep


def test_bundle_excludes_restricted_sigma_sources_and_counts_rules_not_metadata(tmp_path):
    import os
    import subprocess
    pack = tmp_path / "sigma"
    for name in ["rules", "mdecrevoisier", "joesecurity", "tsale", "rules-threat-hunting"]:
        (pack / name).mkdir(parents=True)
        (pack / name / "rule.yml").write_text(f"title: {name}\nid: {name}\n")
    (pack / "sigma-provenance.json").write_text(json.dumps({"commit": "a" * 40, "rules": {}}))
    yara = tmp_path / "yara/gcti"
    yara.mkdir(parents=True)
    (yara / "rule.yar").write_text("rule fixture { condition: true }\n")
    (yara / "README.txt").write_text("attribution, not a rule\n")
    output = tmp_path / "bundle"
    env = dict(os.environ, EGUARD_INCLUDE_RESTRICTED_SOURCES="")
    subprocess.run([sys.executable, str(ROOT / "threat-intel/processing/build_bundle.py"), "--sigma", str(pack), "--yara", str(yara.parent), "--output", str(output)], env=env, check=True, capture_output=True)
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["sigma_count"] == 1
    assert manifest["yara_count"] == 1
    assert manifest["sigmahq_commit"] == "a" * 40
    assert {p.name for p in (output / "sigma").iterdir() if p.is_dir()} == {"rules"}


def test_ioc_tombstones_keep_all_32_matchers_and_names():
    rows = json.loads((ROOT / "threat-intel/rules/ioc_behavior_rules.json").read_text())["rules"]
    assert len(rows) == 32
    assert len({row["name"] for row in rows}) == 32
    import hashlib
    match_content = [{key: value for key, value in row.items() if key != "enabled"} for row in rows]
    assert hashlib.sha256(json.dumps(match_content, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == "8854e9cb9791ef51e8b334813190cf9db11d413a3f8d1294d5762a1c4bb56cc6"
    assert all(row.get("enabled") is False for row in rows)
    assert all(any(row.get(key) for key in ("cmdline_contains", "path_contains", "file_path_contains", "process_names", "process_any_of", "parent_process_names", "cmdline_all_contains", "file_path_suffix")) for row in rows)


def test_sigma_sources_have_no_rust_option_placeholders():
    def inspect(value):
        if isinstance(value, str):
            assert value not in {"None", "None,"} and not value.startswith("Some("), f"Rust Option leaked into YAML: {value}"
        elif isinstance(value, list):
            for child in value: inspect(child)
        elif isinstance(value, dict):
            for key, child in value.items():
                if key not in {"within_secs", "event_class"}: inspect(child)
    for path in (ROOT / "rules/sigma").rglob("*.yml"):
        inspect(yaml.safe_load(path.read_text())["detection"])
    bootstrap = (ROOT / "crates/agent-core/src/lifecycle/detection_bootstrap.rs").read_text()
    for body in re.findall(r'const SIGMA_\w+: &str = r#"(.*?)"#;', bootstrap, re.S):
        inspect(yaml.safe_load(body)["detection"])


def test_sigmahq_is_pinned_and_unsupported_sources_are_not_cloned():
    workflow = (ROOT / ".github/workflows/collect-sigma.yml").read_text()
    assert re.search(r"SIGMAHQ_COMMIT: [\"']?[0-9a-f]{40}", workflow)
    assert "fetch --depth 1 origin" in workflow
    for source in ["mdecrevoisier/SIGMA", "joesecurity/sigma", "tsale/Sigma"]:
        assert source not in workflow


def test_bundle_recurates_after_all_supplemental_merges():
    workflow = (ROOT / ".github/workflows/build-bundle.yml").read_text()
    assert workflow.index("finalize_iocs.py") > workflow.index("phishing_domains.txt:phishing_database")
    assert "sigma_gate" in workflow
    assert "--manifest threat-intel/sigmahq-qualified-53423dac.txt" in workflow
    assert 'EGUARD_REQUIRED_SIGMA_SOURCES: "rules,rules-emerging-threats"' in workflow
    assert "test_rafix_packs.py" in (ROOT / ".github/workflows/verification-suite.yml").read_text()


def test_urlhaus_does_not_collapse_shared_urls_and_retains_dedicated_hosts():
    from ioc_feed import urlhaus_entries
    rows = urlhaus_entries("# public feed\nhttps://docs.google.com/document/d/synthetic\nhttps://drive.google.com/f/x\nhttps://sites.google.com/view/x\nhttps://dedicated-c2.example/payload\n")
    assert [row["value"] for row in rows] == ["dedicated-c2.example"]
    workflow = (ROOT / ".github/workflows/collect-ioc.yml").read_text()
    assert "ioc_feed.py urlhaus" in workflow
    assert "ipblocklist_recommended.txt" in workflow and "ipblocklist_aggressive.txt" not in workflow


def test_threatfox_feed_retains_its_actual_observation_dates():
    from ioc_feed import threatfox_entries
    text = '# "first_seen_utc","ioc_id","ioc_value","ioc_type","last_seen_utc"\n"2020-01-01 00:00:00","1","expired.example","domain","2020-01-02 00:00:00"\n'
    rows = threatfox_entries(text)["domains"]
    assert rows[0]["last_seen"] == "2020-01-02 00:00:00"
    assert ioc_dedup.deduplicate(rows, "domains") == []


def test_final_allowlist_after_phishing_merge_and_recorroboration(tmp_path):
    from finalize_iocs import finalize
    import merge_plain_iocs
    src, dst, allowed = tmp_path / "curated", tmp_path / "final", tmp_path / "allow"
    allowed.mkdir()
    (allowed / "known_good_domains.txt").write_text("safe.example\n")
    write_jsonl(src / "hashes.txt", [{"value": "a" * 64, "sources": ["malwarebazaar"]}])
    write_jsonl(src / "ips.txt", [{"value": "100.64.1.1", "sources": ["firehol_l1"]}, {"value": "193.0.0.0/24", "sources": ["spamhaus"]}])
    write_jsonl(src / "domains.txt", [{"value": "dedicated-c2.example", "sources": ["urlhaus"]}])
    supplement = tmp_path / "phishing.txt"
    supplement.write_text("docs.google.com\nsafe.example\ndedicated-c2.example\n")
    merge_plain_iocs.main(["--target", str(src / "domains.txt"), "--merge", f"{supplement}:phishing_database:medium"])
    finalize(src, dst, allowed)
    rows = read_jsonl(dst / "domains.txt")
    assert len(rows) == 1 and rows[0]["value"] == "dedicated-c2.example"
    assert rows[0]["sources"] == ["phishing_database", "urlhaus"]
    assert rows[0]["confidence"] == "high"
    assert [row["value"] for row in read_jsonl(dst / "ips.txt")] == ["193.0.0.0/24"]
    assert read_jsonl(dst / "hashes.txt")[0]["value"] == "a" * 64


def test_sigma_filter_does_not_let_rejected_duplicate_hide_a_valid_rule(tmp_path):
    import subprocess
    first, second, output = tmp_path / "first", tmp_path / "second", tmp_path / "out"
    for directory, status in [(first, "experimental"), (second, "stable")]:
        directory.mkdir()
        (directory / "rule.yml").write_text(f"title: duplicate\nid: same-id\nstatus: {status}\nlogsource:\n  product: linux\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: /bash\n  condition: selection\n")
    subprocess.run([sys.executable, str(ROOT / "threat-intel/processing/sigma_filter.py"), "--input", str(first), "--input", str(second), "--output", str(output)], check=True, capture_output=True)
    assert len(list(output.rglob("*.yml"))) == 1
    assert (output / "second/rule.yml").exists()


def test_rule_provenance_requires_every_path_id_and_pin(tmp_path):
    from sigma_provenance import verify
    root = tmp_path / "pack"
    (root / "rules").mkdir(parents=True)
    (root / "rules/a.yml").write_text("id: synthetic-id\n")
    document = {"commit": "a" * 40, "rules": {"rules/a.yml": {"source_path": "rules/a.yml", "id": "synthetic-id", "commit": "a" * 40}}}
    (root / "sigma-provenance.json").write_text(json.dumps(document))
    assert verify(root, "a" * 40) == 1
    with pytest.raises(ValueError, match="pin mismatch"): verify(root, "b" * 40)
    document["rules"]["rules/a.yml"]["id"] = "wrong"
    (root / "sigma-provenance.json").write_text(json.dumps(document))
    with pytest.raises(ValueError, match="provenance mismatch"): verify(root, "a" * 40)


def test_real_agent_compile_fp_and_exact_manifest_gates(tmp_path):
    import os
    import subprocess
    binary = os.environ.get("SIGMA_GATE_BIN")
    if not binary:
        pytest.skip("set SIGMA_GATE_BIN to the built detection sigma_gate example (required in CI)")
    root = tmp_path / "pack"
    root.mkdir()
    rule = "title: synthetic\nid: synthetic-id\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: ATTACK_ONLY\n  condition: selection\nlevel: high\n"
    (root / "good.yml").write_text(rule)
    corpus = tmp_path / "events.json"
    sys.path.insert(0, str(ROOT / "threat-intel/tests"))
    from sigma_benign_events import build_events
    corpus.write_text(json.dumps(build_events()))
    ids, report = tmp_path / "ids", tmp_path / "report.json"
    ids.write_text("synthetic-id\n")
    cmd = [str(Path(binary).resolve()), str(root), str(corpus), "--manifest", str(ids), "--report", str(report)]
    assert subprocess.run(cmd, capture_output=True).returncode == 0
    ids.write_text("synthetic-id\nmissing-id\n")
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode != 0 and "MANIFEST_MISMATCH" in result.stderr and "missing-id" in result.stderr
    ids.write_text("synthetic-id\n")
    (root / "good.yml").write_text(rule.replace("ATTACK_ONLY", "git status"))
    result = subprocess.run(cmd, capture_output=True)
    assert result.returncode != 0 and json.loads(report.read_text())["fp_findings"]
    (root / "good.yml").write_text(rule)
    (root / "unsupported.yml").write_text(rule.replace("synthetic-id", "unsupported-id").replace("CommandLine|contains", "ParentCommandLine|contains"))
    assert subprocess.run(cmd + ["--filter"], capture_output=True).returncode == 0
    assert not (root / "unsupported.yml").exists()
    assert json.loads(report.read_text())["rejected_by_reason"] == {"unsupported_field": 1}


def test_collector_uses_fresh_job_scratch_not_checkout_snapshots():
    workflow = (ROOT / ".github/workflows/collect-ioc.yml").read_text()
    assert "sources/ioc" not in workflow
    assert 'IOC_DIR=$RUNNER_TEMP/ioc-collected' in workflow
    assert "${{ env.IOC_DIR }}/consolidated/" in workflow
    assert "ioc-curated" in workflow


def test_malwarebazaar_api_dates_survive_collection(tmp_path, monkeypatch):
    import urllib.request
    workflow = yaml.safe_load((ROOT / ".github/workflows/collect-ioc.yml").read_text())
    step = next(step for job in workflow["jobs"].values() for step in job["steps"]
                if "MalwareBazaar full SHA256" in step.get("name", ""))
    code = step["run"].split("python - <<'PY'\n", 1)[1].split("\nPY", 1)[0]
    output = tmp_path / "api.jsonl"
    code = code.replace("/tmp/bazaar_api_hashes.txt", str(output))
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({"query_status":"ok","data":[{"sha256_hash":"a"*64,"first_seen":"2020-01-01 00:00:00"}, {"sha256_hash":"not-a-hash","first_seen":"2020-01-01 00:00:00"}]}).encode()
    monkeypatch.setenv("MALWARE_BAZAAR_KEY", "synthetic-public-test-value")
    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: Response())
    exec(compile(code, "<synthetic-collector>", "exec"), {})
    lines = output.read_text().splitlines()
    assert lines and all(line.startswith("{") for line in lines), "dated API rows became undated plain hashes"
    rows = [json.loads(line) for line in lines]
    assert len(rows) == 1
    assert rows[0]["first_seen"] == rows[0]["last_seen"] == "2020-01-01 00:00:00"
    assert ioc_dedup.deduplicate(rows, "hashes") == [], "old API metadata must expire, not be refreshed"
    # The final collector must retain JSONL outside the plain-hash-only grep.
    assert 'cat /tmp/bazaar_api_hashes.txt >> "$IOC_DIR/hashes/malwarebazaar.txt"' in step["run"]
