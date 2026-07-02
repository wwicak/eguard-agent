import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "processing" / "merge_plain_iocs.py"
spec = importlib.util.spec_from_file_location("merge_plain_iocs", SCRIPT)
merge_plain_iocs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge_plain_iocs)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_merge_plain_iocs_preserves_provenance_and_sorts(tmp_path, monkeypatch):
    monkeypatch.setattr(merge_plain_iocs, "utc_now", lambda: "2026-07-02T00:00:00+00:00")
    target = tmp_path / "ips.txt"
    target.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "value": "2.2.2.2",
                        "confidence": "low",
                        "sources": ["zeta"],
                        "first_seen": "2026-07-01T00:00:00+00:00",
                        "last_seen": "2026-07-01T01:00:00+00:00",
                    }
                ),
                "1.1.1.1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    plain = tmp_path / "plain.txt"
    plain.write_text("\n# ignored\n2.2.2.2\n3.3.3.3\n\n", encoding="utf-8")

    rc = merge_plain_iocs.main(
        [
            "--target",
            str(target),
            "--merge",
            f"{plain}:c2_tracker:medium",
        ]
    )

    assert rc == 0
    rows = read_jsonl(target)
    assert [row["value"] for row in rows] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

    bare = rows[0]
    assert bare["confidence"] == "low"
    assert bare["sources"] == ["other"]

    merged = rows[1]
    assert merged["confidence"] == "medium"
    assert merged["sources"] == ["c2_tracker", "zeta"]
    assert merged["first_seen"] == "2026-07-01T00:00:00+00:00"
    assert merged["last_seen"] == "2026-07-02T00:00:00+00:00"

    added = rows[2]
    assert added["confidence"] == "medium"
    assert added["sources"] == ["c2_tracker"]


def test_missing_plain_file_is_noop_and_missing_target_is_created(tmp_path, monkeypatch):
    monkeypatch.setattr(merge_plain_iocs, "utc_now", lambda: "2026-07-02T00:00:00+00:00")
    target = tmp_path / "domains.txt"
    missing = tmp_path / "missing.txt"

    rc = merge_plain_iocs.main(
        [
            "--target",
            str(target),
            "--merge",
            f"{missing}:phishing_database:medium",
        ]
    )

    assert rc == 0
    assert target.exists()
    assert read_jsonl(target) == []


def test_merge_plain_iocs_uses_max_confidence_and_min_max_times(tmp_path, monkeypatch):
    monkeypatch.setattr(merge_plain_iocs, "utc_now", lambda: "2026-07-02T00:00:00+00:00")
    target = tmp_path / "domains.txt"
    target.write_text(
        json.dumps(
            {
                "value": "bad.example",
                "confidence": "high",
                "sources": ["abusech"],
                "first_seen": "2026-06-01T00:00:00+00:00",
                "last_seen": "2026-06-02T00:00:00+00:00",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    plain = tmp_path / "plain.txt"
    plain.write_text("bad.example\n", encoding="utf-8")

    merge_plain_iocs.main(
        [
            "--target",
            str(target),
            "--merge",
            f"{plain}:phishing_database:medium",
        ]
    )

    row = read_jsonl(target)[0]
    assert row["confidence"] == "high"
    assert row["sources"] == ["abusech", "phishing_database"]
    assert row["first_seen"] == "2026-06-01T00:00:00+00:00"
    assert row["last_seen"] == "2026-07-02T00:00:00+00:00"
