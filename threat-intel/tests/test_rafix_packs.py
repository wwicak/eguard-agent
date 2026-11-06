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


@pytest.mark.parametrize("host", ["docs.google.com", "drive.google.com", "sites.google.com", "pastebin.com", "tinyurl.com", "a.docs.google.com", "firebasestorage.googleapis.com", "dweb.link"])
def test_shared_hosts_never_survive_domain_curation(tmp_path, host):
    src, dst = tmp_path / "in", tmp_path / "out"
    write_jsonl(src, [{"value": host, "sources": ["urlhaus"]}, {"value": "dedicated-c2.example", "sources": ["urlhaus"]}])
    ioc_allowlist.filter_iocs(str(src), str(dst), set())
    assert [row["value"] for row in read_jsonl(dst)] == ["dedicated-c2.example"]


def test_bogons_and_overlapping_special_networks_are_removed(tmp_path):
    src, dst = tmp_path / "in", tmp_path / "out"
    special = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15", "224.0.0.0/3", "239.255.255.250", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "0.0.0.0/0", "::1", "2001:db8::/32", "fc00::/7", "ff00::/8", "not-an-ip"]
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


def test_ioc_tombstones_keep_all_32_matchers_and_names():
    rows = json.loads((ROOT / "threat-intel/rules/ioc_behavior_rules.json").read_text())["rules"]
    assert len(rows) == 32
    assert len({row["name"] for row in rows}) == 32
    assert all(row.get("enabled") is False for row in rows)
    assert all(any(row.get(key) for key in ("cmdline_contains", "path_contains", "file_path_contains", "process_names", "process_any_of", "parent_process_names")) for row in rows)


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
    assert "test_rafix_packs.py" in (ROOT / ".github/workflows/verification-suite.yml").read_text()


def test_collector_uses_fresh_job_scratch_not_checkout_snapshots():
    workflow = (ROOT / ".github/workflows/collect-ioc.yml").read_text()
    assert "sources/ioc" not in workflow
    assert 'IOC_DIR=$RUNNER_TEMP/ioc-collected' in workflow
    assert "${{ env.IOC_DIR }}/consolidated/" in workflow
    assert "ioc-curated" in workflow
