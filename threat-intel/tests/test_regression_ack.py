import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "threat-intel" / "processing" / "coverage_regression_gate.py"


def write_metrics(path: Path, **overrides):
    metrics = {
        "sigma_count": 100,
        "yara_count": 100,
        "suricata_count": 100,
        "elastic_count": 100,
        "ioc_total": 100,
        "cve_count": 100,
        "signature_total": 400,
        "database_total": 600,
        "yara_source_count": 4,
        "sigma_source_count": 3,
    }
    metrics.update(overrides)
    path.write_text(json.dumps(metrics), encoding="utf-8")


def run_gate(tmp_path: Path, current: Path, previous: Path, *extra: str):
    output = tmp_path / "coverage-regression.json"
    cmd = [
        sys.executable,
        str(SCRIPT),
        "--current",
        str(current),
        "--previous",
        str(previous),
        "--output",
        str(output),
        "--max-drop-yara-pct",
        "25",
        "--max-drop-suricata-pct",
        "25",
        "--max-drop-elastic-pct",
        "25",
        "--max-drop-signature-total-pct",
        "15",
        *extra,
    ]
    return subprocess.run(cmd, text=True, capture_output=True), output


def test_regression_gate_fails_without_ack(tmp_path):
    previous = tmp_path / "previous.json"
    current = tmp_path / "current.json"
    write_metrics(previous)
    write_metrics(current, yara_count=70, suricata_count=0, elastic_count=0, signature_total=170)

    proc, output = run_gate(tmp_path, current, previous)

    assert proc.returncode != 0
    assert "Bundle coverage regression gate failed" in proc.stdout
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "fail"
    assert "acknowledged_reset" not in report


def test_regression_gate_acknowledges_failing_baseline_reset(tmp_path):
    previous = tmp_path / "previous.json"
    current = tmp_path / "current.json"
    reason = "license exclusions baseline reset"
    write_metrics(previous)
    write_metrics(current, yara_count=70, suricata_count=0, elastic_count=0, signature_total=170)

    proc, output = run_gate(
        tmp_path,
        current,
        previous,
        "--acknowledge-reset",
        "--acknowledge-reason",
        reason,
    )

    assert proc.returncode == 0
    assert "Bundle coverage regression gate failed" in proc.stdout
    assert f"regression failures acknowledged as intentional baseline reset: {reason}" in proc.stdout
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "fail"
    assert report["acknowledged_reset"]["reason"] == reason
    assert report["acknowledged_reset"]["failures"] == report["regressions"]
    assert report["acknowledged_reset"]["failures"]


def test_regression_gate_ack_is_noop_when_passing(tmp_path):
    previous = tmp_path / "previous.json"
    current = tmp_path / "current.json"
    write_metrics(previous)
    write_metrics(current, yara_count=100, suricata_count=100, elastic_count=100, signature_total=400)

    proc, output = run_gate(
        tmp_path,
        current,
        previous,
        "--acknowledge-reset",
        "--acknowledge-reason",
        "not used",
    )

    assert proc.returncode == 0
    assert "Bundle coverage regression gate passed" in proc.stdout
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "pass"
    assert "acknowledged_reset" not in report
