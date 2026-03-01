#!/usr/bin/env python3
"""Build deterministic signature-ML training corpus from bundle artifacts.

Generates a synthetic but deterministic dataset aligned with runtime ML features
(z1..z4 signals, info-theoretic metrics, and event metadata). Optionally merges
external, artifact-sourced signals (NDJSON) for supervised label ingestion.
This keeps the CI model compatible with the agent's Layer-5 feature schema
while preserving determinism (no ML frameworks, no random seeds).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from signature_ml_feature_contract import FEATURES as FEATURE_CONTRACT_FIELDS
from signature_ml_feature_contract import load_feature_contract


EVENT_CLASSES = (
    "process_exec",
    "file_open",
    "network_connect",
    "dns_query",
    "module_load",
    "login",
    "process_exit",
    "alert",
)

EVENT_CLASS_RISK = {
    "module_load": 0.9,
    "network_connect": 0.6,
    "dns_query": 0.5,
    "process_exec": 0.5,
    "file_open": 0.4,
    "login": 0.3,
    "process_exit": 0.1,
    "alert": 1.0,
}

SIGNAL_FEATURE_FIELDS = tuple(FEATURE_CONTRACT_FIELDS)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso_utc(raw: datetime) -> str:
    return raw.isoformat().replace("+00:00", "Z")


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    raw = str(value).strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw.replace("Z", "+00:00")
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _normalize_label(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        ivalue = int(value)
        if ivalue in (0, 1):
            return ivalue
    if isinstance(value, str):
        trimmed = value.strip().lower()
        if trimmed in {"0", "false", "no"}:
            return 0
        if trimmed in {"1", "true", "yes"}:
            return 1
    return None


def _parse_bool(raw: Any) -> bool:
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _load_json(path: Path, label: str, *, required: bool) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise FileNotFoundError(f"missing {label}: {path}")
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return payload


def _normalize_external_row(
    row: dict[str, Any],
    sample_id: str,
    observed_at: datetime,
    feature_fields: tuple[str, ...],
) -> dict[str, Any] | None:
    event_class = str(row.get("event_class") or "process_exec").strip()
    if event_class not in EVENT_CLASSES:
        event_class = "process_exec"

    label = _normalize_label(row.get("label"))
    label_source = str(row.get("label_source") or "external").strip() or "external"

    adjudicated_at_raw = row.get("adjudicated_at_utc") or row.get("adjudicated_at") or ""
    adjudicated_at = _parse_ts(adjudicated_at_raw)
    adjudicated_at_utc = _iso_utc(adjudicated_at) if adjudicated_at else ""

    model_score = _clamp(_as_float(row.get("model_score"), 0.0), 0.0, 1.0)

    normalized: dict[str, Any] = {
        "sample_id": sample_id,
        "observed_at_utc": _iso_utc(observed_at),
        "adjudicated_at_utc": adjudicated_at_utc,
        "host_id": str(row.get("host_id", "")).strip(),
        "rule_id": str(row.get("rule_id", "")).strip(),
        "event_class": event_class,
        "model_score": round(model_score, 6),
        "label": label,
        "label_source": label_source,
    }

    for feature in feature_fields:
        normalized[feature] = _as_float(row.get(feature), 0.0)

    return normalized


def _load_external_signals(
    path: Path,
    sample_cap: int,
    now: datetime,
    feature_fields: tuple[str, ...],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    if not path.is_file():
        return [], {"external_total": 0, "external_used": 0, "external_invalid": 0}

    raw_entries: list[tuple[datetime, dict[str, Any]]] = []
    invalid = 0

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            invalid += 1
            continue
        if not isinstance(payload, dict):
            invalid += 1
            continue
        observed = _parse_ts(payload.get("observed_at_utc") or payload.get("observed_at"))
        if observed is None:
            invalid += 1
            continue
        raw_entries.append((observed, payload))

    raw_entries.sort(
        key=lambda item: (
            item[0].isoformat(),
            str(item[1].get("host_id", "")),
            str(item[1].get("rule_id", "")),
            str(item[1].get("sample_id", "")),
        )
    )

    entries: list[dict[str, Any]] = []
    for idx, (observed, payload) in enumerate(raw_entries):
        sample_id = str(payload.get("sample_id") or f"external-{idx + 1:06d}")
        normalized = _normalize_external_row(payload, sample_id, observed or now, feature_fields)
        if normalized is None:
            invalid += 1
            continue
        entries.append(normalized)

    if sample_cap > 0:
        entries = entries[:sample_cap]

    return entries, {
        "external_total": len(raw_entries),
        "external_used": len(entries),
        "external_invalid": invalid,
    }


def _stable_row_key(row: dict[str, Any], fallback: str) -> str:
    sample_id = str(row.get("sample_id", "")).strip()
    if sample_id:
        return sample_id
    observed_at = str(row.get("observed_at_utc", "")).strip()
    host_id = str(row.get("host_id", "")).strip()
    rule_id = str(row.get("rule_id", "")).strip()
    return f"{fallback}|{host_id}|{rule_id}|{observed_at}"


def _dedupe_rows(rows: list[dict[str, Any]], prefix: str) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, row in enumerate(rows):
        key = _stable_row_key(row, f"{prefix}-{idx:08d}")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _cap_external_rows(
    rows: list[dict[str, Any]],
    max_per_host: int,
    max_per_rule: int,
) -> list[dict[str, Any]]:
    if not rows:
        return []

    capped: list[dict[str, Any]] = []
    host_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}

    for row in rows:
        host_id = str(row.get("host_id", "")).strip() or "host:unknown"
        rule_id = str(row.get("rule_id", "")).strip() or "rule:unknown"

        if max_per_host > 0 and host_counts.get(host_id, 0) >= max_per_host:
            continue
        if max_per_rule > 0 and rule_counts.get(rule_id, 0) >= max_per_rule:
            continue

        capped.append(row)
        host_counts[host_id] = host_counts.get(host_id, 0) + 1
        rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

    return capped


def _assemble_external_first_dataset(
    sample_count: int,
    synthetic_rows: list[dict[str, Any]],
    external_rows: list[dict[str, Any]],
    max_synthetic_ratio: float,
) -> tuple[list[dict[str, Any]], int]:
    if sample_count <= 0:
        return [], 0

    external_count = min(len(external_rows), sample_count)
    if external_count <= 0:
        selected_synth = synthetic_rows[:sample_count]
        return selected_synth, len(selected_synth)

    synth_budget = int(round(external_count * max(max_synthetic_ratio, 0.0)))
    synth_budget = max(0, synth_budget)
    synth_budget = min(synth_budget, max(sample_count - external_count, 0))

    selected_external = external_rows[:external_count]
    selected_synth = synthetic_rows[:synth_budget]
    dataset = [*selected_external, *selected_synth]
    return dataset[:sample_count], len(selected_synth)


def _rand01(seed: str) -> float:
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    value = int.from_bytes(digest[:8], "big")
    return value / float(2**64 - 1)


def _score_to_probability(linear: float) -> float:
    return 1.0 / (1.0 + math.exp(-linear))


def _base_component_score(readiness: dict[str, Any], component: str, fallback: float) -> float:
    components = readiness.get("components", {})
    if not isinstance(components, dict):
        return fallback
    payload = components.get(component, {})
    if not isinstance(payload, dict) or not payload.get("available"):
        return fallback
    return _clamp(_as_float(payload.get("score"), fallback), 0.0, 100.0)


def _choose_event_class(seed: str, severity: int) -> str:
    # Bias toward network/dns alerts for higher severity.
    bias = _clamp((severity - 1) / 4.0, 0.0, 1.0)
    weights = [
        ("process_exec", 0.30 - 0.05 * bias),
        ("file_open", 0.20 - 0.02 * bias),
        ("network_connect", 0.18 + 0.08 * bias),
        ("dns_query", 0.12 + 0.06 * bias),
        ("module_load", 0.06 + 0.02 * bias),
        ("login", 0.06),
        ("process_exit", 0.04),
        ("alert", 0.04 + 0.03 * bias),
    ]
    total = sum(weight for _, weight in weights)
    roll = _rand01(seed + "|event_class") * total
    running = 0.0
    for name, weight in weights:
        running += weight
        if roll <= running:
            return name
    return "process_exec"


def _dst_port_risk(seed: str, severity: int, event_class: str) -> float:
    roll = _rand01(seed + "|dst_port")
    bias = _clamp(severity / 5.0, 0.0, 1.0)
    if event_class in {"network_connect", "dns_query"} and roll < 0.18 + 0.25 * bias:
        return 0.95
    if roll < 0.15:
        return 0.1
    if roll < 0.35:
        return 0.2
    if roll < 0.50:
        return 0.8
    if roll < 0.70:
        return 0.6
    return 0.3


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build deterministic synthetic signature-ML corpus from threat-intel bundle reports"
    )
    parser.add_argument("--manifest", required=True, help="bundle/manifest.json")
    parser.add_argument("--coverage", required=True, help="bundle/coverage-metrics.json")
    parser.add_argument("--readiness", default="", help="signature-ml-readiness.json")
    parser.add_argument("--attack-coverage", default="", help="bundle/attack-coverage.json")
    parser.add_argument("--critical-gate", default="", help="bundle/attack-critical-technique-gate.json")
    parser.add_argument("--output-signals", required=True, help="Output NDJSON path")
    parser.add_argument("--output-summary", default="", help="Optional output summary JSON path")
    parser.add_argument("--output-feature-contract", default="", help="Optional output feature contract JSON path")
    parser.add_argument("--external-signals", default="", help="Optional external signals NDJSON")
    parser.add_argument("--external-sample-cap", type=int, default=0)
    parser.add_argument("--external-first", default="1", help="Prefer external rows before synthetic fallback")
    parser.add_argument("--max-synthetic-ratio", type=float, default=1.0, help="Max synthetic:external ratio when external-first mode is enabled")
    parser.add_argument("--max-external-per-host", type=int, default=0, help="Optional per-host cap for external samples (0 disables)")
    parser.add_argument("--max-external-per-rule", type=int, default=0, help="Optional per-rule cap for external samples (0 disables)")
    parser.add_argument("--sample-count", type=int, default=720)
    parser.add_argument("--window-days", type=int, default=45)
    parser.add_argument("--host-pool", type=int, default=160)
    parser.add_argument("--rule-pool", type=int, default=220)
    parser.add_argument("--unresolved-ratio", type=float, default=0.08)
    parser.add_argument("--label-noise", type=float, default=0.03)
    return parser


def main() -> int:
    args = _parser().parse_args()

    feature_contract = load_feature_contract()
    feature_fields = tuple(feature_contract.get("features", SIGNAL_FEATURE_FIELDS))

    manifest = _load_json(Path(args.manifest), "bundle manifest", required=True)
    coverage = _load_json(Path(args.coverage), "coverage report", required=True)
    readiness = (
        _load_json(Path(args.readiness), "signature ML readiness report", required=False)
        if args.readiness
        else {}
    )
    attack_coverage = (
        _load_json(Path(args.attack_coverage), "ATT&CK coverage report", required=False)
        if args.attack_coverage
        else {}
    )
    critical_gate = (
        _load_json(Path(args.critical_gate), "critical ATT&CK gate report", required=False)
        if args.critical_gate
        else {}
    )

    sample_count = max(args.sample_count, 50)
    window_days = max(args.window_days, 7)
    host_pool = max(args.host_pool, 8)
    rule_pool = max(args.rule_pool, 12)
    unresolved_ratio = _clamp(args.unresolved_ratio, 0.0, 0.80)
    label_noise = _clamp(args.label_noise, 0.0, 0.40)
    external_first = _parse_bool(args.external_first)
    max_synthetic_ratio = _clamp(args.max_synthetic_ratio, 0.0, 10.0)
    max_external_per_host = max(_as_int(args.max_external_per_host, 0), 0)
    max_external_per_rule = max(_as_int(args.max_external_per_rule, 0), 0)

    measured = coverage.get("measured", {})
    if not isinstance(measured, dict):
        measured = {}

    signature_total = max(_as_int(measured.get("signature_total"), 1), 1)
    database_total = max(_as_int(measured.get("database_total"), signature_total), signature_total)
    cve_count = max(_as_int(measured.get("cve_count"), 0), 0)

    attack_measured = attack_coverage.get("measured", {})
    if not isinstance(attack_measured, dict):
        attack_measured = {}
    attack_techniques = max(_as_int(attack_measured.get("total_techniques"), 0), 0)
    attack_tactics = max(_as_int(attack_measured.get("total_tactics"), 0), 0)

    critical_measured = critical_gate.get("measured", {})
    if not isinstance(critical_measured, dict):
        critical_measured = {}
    critical_ratio = _clamp(_as_float(critical_measured.get("covered_ratio"), 0.82), 0.0, 1.0)

    final_score = _clamp(
        _as_float((readiness.get("scores", {}) if isinstance(readiness.get("scores", {}), dict) else {}).get("final_score"), 82.0),
        0.0,
        100.0,
    )
    source_diversity_score = _base_component_score(readiness, "source_diversity", 78.0)
    attack_surface_score = _base_component_score(readiness, "attack_surface", 76.0)
    critical_resilience_score = _base_component_score(readiness, "critical_resilience", 79.0)

    version_seed = str(manifest.get("version", "unknown"))
    now = _now_utc()
    span = timedelta(days=window_days)
    start = now - span
    step_seconds = max(int(span.total_seconds() / max(sample_count - 1, 1)), 60)

    out_path = Path(args.output_signals)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    external_rows: list[dict[str, Any]] = []
    external_stats = {"external_total": 0, "external_used": 0, "external_invalid": 0}
    if args.external_signals:
        sample_cap = args.external_sample_cap if args.external_sample_cap > 0 else sample_count
        external_rows, external_stats = _load_external_signals(
            Path(args.external_signals),
            sample_cap,
            now,
            feature_fields,
        )
        external_rows = _dedupe_rows(external_rows, "external")
        external_rows = _cap_external_rows(
            external_rows,
            max_external_per_host,
            max_external_per_rule,
        )
        external_stats["external_used"] = len(external_rows)

    rows: list[dict[str, Any]] = []
    raw_rows: list[dict[str, Any]] = []
    adjudicated_count = 0
    positive_count = 0
    negative_count = 0
    unresolved_count = 0
    readiness_norm = final_score / 100.0

    for idx in range(sample_count):
        seed_prefix = f"{version_seed}|{idx}"
        observed_at = start + timedelta(seconds=step_seconds * idx)

        host_idx = 1 + int(_rand01(seed_prefix + "|host") * host_pool)
        rule_idx = 1 + int(_rand01(seed_prefix + "|rule") * rule_pool)
        host_id = f"host-{host_idx:03d}"
        rule_id = f"sig-rule-{rule_idx:04d}"

        severity = 1 + int(_rand01(seed_prefix + "|severity") * 5)
        source_jitter = (_rand01(seed_prefix + "|source_jitter") - 0.5) * 16.0
        attack_jitter = (_rand01(seed_prefix + "|attack_jitter") - 0.5) * 18.0
        critical_jitter = (_rand01(seed_prefix + "|critical_jitter") - 0.5) * 14.0

        source_div_score = _clamp(source_diversity_score + source_jitter, 0.0, 100.0)
        attack_surface = _clamp(
            attack_surface_score + attack_jitter + (attack_techniques / 200.0) * 4.0 + attack_tactics,
            0.0,
            100.0,
        )
        critical_resilience = _clamp(
            critical_resilience_score + critical_jitter + critical_ratio * 4.0,
            0.0,
            100.0,
        )

        attack_norm = attack_surface / 100.0
        critical_norm = critical_resilience / 100.0
        source_norm = source_div_score / 100.0

        event_class = _choose_event_class(seed_prefix, severity)
        event_class_risk = EVENT_CLASS_RISK.get(event_class, 0.5)
        dst_port_risk = _dst_port_risk(seed_prefix, severity, event_class)

        z1_ioc_hit = 1.0 if _rand01(seed_prefix + "|z1") < (0.08 + 0.12 * severity / 5.0 + (1 - readiness_norm) * 0.08) else 0.0
        temporal_count = int(_rand01(seed_prefix + "|z2") * (1.0 + severity * 0.7 + attack_norm * 2.0))
        z2_temporal_count = min(temporal_count, 3) / 3.0
        z3_anomaly_high = 1.0 if _rand01(seed_prefix + "|z3h") < (0.05 + (1 - readiness_norm) * 0.18 + severity * 0.02) else 0.0
        z3_anomaly_med = 1.0 if _rand01(seed_prefix + "|z3m") < (0.12 + (1 - readiness_norm) * 0.22 + severity * 0.03) else 0.0
        killchain_count = int(_rand01(seed_prefix + "|z4") * (1.0 + attack_norm * 3.2))
        z4_killchain_count = min(killchain_count, 3) / 3.0

        yara_count = int(_rand01(seed_prefix + "|yara") * (1.0 + severity + signature_total / 9000.0))
        yara_hit_count = min(yara_count, 5) / 5.0
        string_count = int(_rand01(seed_prefix + "|string") * (1.0 + severity * 0.6 + source_norm * 2.0))
        string_sig_count = min(string_count, 5) / 5.0

        uid_is_root = 1.0 if _rand01(seed_prefix + "|uid") < (0.1 + 0.15 * severity / 5.0 + 0.08 * attack_norm) else 0.0
        has_command_line = 1.0 if event_class in {"process_exec", "alert"} else (1.0 if _rand01(seed_prefix + "|cmdline") < 0.25 else 0.0)
        cmdline_length_norm = _clamp(0.15 + 0.65 * severity / 5.0 + (_rand01(seed_prefix + "|cmdlen") - 0.5) * 0.2, 0.0, 1.0)
        prefilter_hit = 1.0 if z1_ioc_hit > 0.0 or _rand01(seed_prefix + "|prefilter") < 0.05 else 0.0

        layer_count = sum(
            1
            for signal in [
                z1_ioc_hit > 0.0,
                z2_temporal_count > 0.0,
                z3_anomaly_high > 0.0 or z3_anomaly_med > 0.0,
                z4_killchain_count > 0.0,
            ]
            if signal
        )
        multi_layer_count = min(layer_count, 4) / 4.0

        cmdline_renyi_h2 = _clamp(0.15 + 0.55 * severity / 5.0 + (_rand01(seed_prefix + "|renyi") - 0.5) * 0.2, 0.0, 1.0)
        cmdline_compression = _clamp(0.25 + 0.50 * (1 - readiness_norm) + (_rand01(seed_prefix + "|compress") - 0.5) * 0.2, 0.0, 1.0)
        cmdline_min_entropy = _clamp(0.10 + 0.55 * source_norm + (_rand01(seed_prefix + "|minent") - 0.5) * 0.2, 0.0, 1.0)
        cmdline_entropy_gap = _clamp(0.10 + 0.55 * critical_norm + (_rand01(seed_prefix + "|gap") - 0.5) * 0.2, 0.0, 1.0)
        dns_entropy = 0.0
        if event_class == "dns_query":
            dns_entropy = _clamp(0.4 + 0.6 * _rand01(seed_prefix + "|dns"), 0.0, 1.0)
        event_size_norm = _clamp(
            0.15
            + (0.45 if event_class in {"file_open", "module_load"} else 0.25) * _rand01(seed_prefix + "|size")
            + 0.15 * (signature_total / 8000.0),
            0.0,
            1.0,
        )

        # Container risk
        container_risk = 0.0
        if _rand01(seed_prefix + "|container") < 0.15:
            container_risk = 0.5  # containerized
            if _rand01(seed_prefix + "|escape") < 0.1 + 0.15 * severity / 5.0:
                container_risk = 1.0  # escape/privileged

        # File path entropy (synthetic — higher for suspicious names)
        file_path_entropy = _clamp(
            0.3 + 0.4 * _rand01(seed_prefix + "|fpe") + 0.1 * severity / 5.0,
            0.0, 1.0,
        )

        # File path depth (synthetic)
        file_path_depth = _clamp(
            0.2 + 0.3 * _rand01(seed_prefix + "|fpd") + 0.1 * severity / 5.0,
            0.0, 1.0,
        )

        # Behavioral alarm count
        behavioral_alarm_count = _clamp(
            int(_rand01(seed_prefix + "|bac") * (1.0 + severity * 0.8)) / 5.0,
            0.0, 1.0,
        )

        # Interaction terms
        z1_z2_interaction = z1_ioc_hit * z2_temporal_count
        z1_z4_interaction = z1_ioc_hit * z4_killchain_count
        anomaly_behavioral = z3_anomaly_high * multi_layer_count

        linear = (
            -3.10
            + 2.25 * z1_ioc_hit
            + 1.25 * z2_temporal_count
            + 1.55 * z4_killchain_count
            + 1.80 * yara_hit_count
            + 1.25 * string_sig_count
            + 0.85 * event_class_risk
            + 0.45 * uid_is_root
            + 0.65 * dst_port_risk
            + 0.35 * cmdline_length_norm
            + 0.55 * cmdline_compression
            + 0.35 * dns_entropy
            + 0.25 * event_size_norm
            + 0.15 * multi_layer_count
            + 0.3 * container_risk
            + 0.2 * file_path_entropy
            + 0.15 * file_path_depth
            + 0.25 * behavioral_alarm_count
            + 0.5 * z1_z2_interaction
            + 0.4 * z1_z4_interaction
            + 0.3 * anomaly_behavioral
            + (_rand01(seed_prefix + "|noise") - 0.5) * 0.6
        )
        model_score = _clamp(_score_to_probability(linear), 0.001, 0.999)

        raw_rows.append(
            {
                "sample_id": f"sample-{idx + 1:06d}",
                "observed_at": observed_at,
                "seed_prefix": seed_prefix,
                "host_id": host_id,
                "rule_id": rule_id,
                "rule_severity": severity,
                "signature_total": signature_total,
                "database_total": database_total,
                "source_diversity_score": round(source_div_score, 4),
                "attack_surface_score": round(attack_surface, 4),
                "critical_resilience_score": round(critical_resilience, 4),
                "cve_count": cve_count,
                "event_class": event_class,
                "model_score": round(model_score, 6),
                "z1_ioc_hit": z1_ioc_hit,
                "z2_temporal_count": round(z2_temporal_count, 6),
                "z3_anomaly_high": z3_anomaly_high,
                "z3_anomaly_med": z3_anomaly_med,
                "z4_killchain_count": round(z4_killchain_count, 6),
                "yara_hit_count": round(yara_hit_count, 6),
                "string_sig_count": round(string_sig_count, 6),
                "event_class_risk": round(event_class_risk, 6),
                "uid_is_root": uid_is_root,
                "dst_port_risk": round(dst_port_risk, 6),
                "has_command_line": has_command_line,
                "cmdline_length_norm": round(cmdline_length_norm, 6),
                "prefilter_hit": prefilter_hit,
                "multi_layer_count": round(multi_layer_count, 6),
                "cmdline_renyi_h2": round(cmdline_renyi_h2, 6),
                "cmdline_compression": round(cmdline_compression, 6),
                "cmdline_min_entropy": round(cmdline_min_entropy, 6),
                "cmdline_entropy_gap": round(cmdline_entropy_gap, 6),
                "dns_entropy": round(dns_entropy, 6),
                "event_size_norm": round(event_size_norm, 6),
                "container_risk": round(container_risk, 6),
                "file_path_entropy": round(file_path_entropy, 6),
                "file_path_depth": round(file_path_depth, 6),
                "behavioral_alarm_count": round(behavioral_alarm_count, 6),
                "z1_z2_interaction": round(z1_z2_interaction, 6),
                "z1_z4_interaction": round(z1_z4_interaction, 6),
                "anomaly_behavioral": round(anomaly_behavioral, 6),
            }
        )

    target_positive_ratio = _clamp(0.23 + (0.80 - readiness_norm) * 0.18, 0.18, 0.34)
    sorted_scores = sorted(float(row.get("model_score", 0.0)) for row in raw_rows)
    cutoff_index = int((1.0 - target_positive_ratio) * max(len(sorted_scores) - 1, 0))
    cutoff_index = max(min(cutoff_index, max(len(sorted_scores) - 1, 0)), 0)
    score_cutoff = sorted_scores[cutoff_index] if sorted_scores else 0.5

    for row in raw_rows:
        seed_prefix = str(row.get("seed_prefix", ""))
        observed_at = row.get("observed_at", now)
        if not isinstance(observed_at, datetime):
            observed_at = now

        label = 1 if float(row.get("model_score", 0.0)) >= score_cutoff else 0
        if _rand01(seed_prefix + "|flip") < label_noise:
            label = 1 - label

        adjudicated = _rand01(seed_prefix + "|adjudicated") >= unresolved_ratio
        if adjudicated:
            delay_hours = int(_rand01(seed_prefix + "|delay") * 120)
            adjudicated_at = observed_at + timedelta(hours=delay_hours)
            adjudicated_count += 1
            if label == 1:
                positive_count += 1
            else:
                negative_count += 1
            encoded_label: int | None = label
            adjudicated_at_raw = _iso_utc(adjudicated_at)
        else:
            unresolved_count += 1
            encoded_label = None
            adjudicated_at_raw = ""

        feature_payload = {feature: row.get(feature, 0.0) for feature in feature_fields}
        rows.append(
            {
                "sample_id": row.get("sample_id"),
                "observed_at_utc": _iso_utc(observed_at),
                "adjudicated_at_utc": adjudicated_at_raw,
                "host_id": row.get("host_id"),
                "rule_id": row.get("rule_id"),
                "event_class": row.get("event_class"),
                "model_score": row.get("model_score"),
                "label": encoded_label,
                "label_source": "synthetic_ci",
                **feature_payload,
            }
        )

    synthetic_count_used = len(rows)
    dataset_mode = "synthetic_ci"

    rows = _dedupe_rows(rows, "synthetic")

    if external_rows:
        if external_first:
            rows, synthetic_count_used = _assemble_external_first_dataset(
                sample_count=sample_count,
                synthetic_rows=rows,
                external_rows=external_rows,
                max_synthetic_ratio=max_synthetic_ratio,
            )
            dataset_mode = "external_only" if synthetic_count_used == 0 else "hybrid_external_first"
        else:
            combined = _dedupe_rows([*external_rows, *rows], "combined")
            if len(combined) > sample_count:
                combined = combined[:sample_count]
            rows = combined
            synthetic_count_used = sum(1 for row in rows if str(row.get("label_source", "")).startswith("synthetic"))
            dataset_mode = "external_only" if synthetic_count_used == 0 else "hybrid_external"

    adjudicated_count = 0
    positive_count = 0
    negative_count = 0
    unresolved_count = 0
    for row in rows:
        label = _normalize_label(row.get("label"))
        if label is None:
            unresolved_count += 1
            row["label"] = None
            continue
        row["label"] = label
        adjudicated_count += 1
        if label == 1:
            positive_count += 1
        else:
            negative_count += 1

    with out_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    summary = {
        "suite": "signature_ml_build_training_corpus",
        "status": "pass",
        "dataset_mode": dataset_mode,
        "recorded_at_utc": _iso_utc(now),
        "version_seed": version_seed,
        "feature_contract": {
            "version": feature_contract.get("version"),
            "feature_count": feature_contract.get("feature_count"),
            "contract_sha256": feature_contract.get("contract_sha256"),
        },
        "measured": {
            "sample_count": len(rows),
            "adjudicated_count": adjudicated_count,
            "unresolved_count": unresolved_count,
            "positive_count": positive_count,
            "negative_count": negative_count,
            "adjudicated_ratio": round(adjudicated_count / max(len(rows), 1), 4),
            "positive_ratio": round(
                positive_count / max(adjudicated_count, 1),
                4,
            ),
            "target_positive_ratio": round(target_positive_ratio, 4),
            "score_cutoff": round(score_cutoff, 6),
            "window_days": window_days,
            "host_pool": host_pool,
            "rule_pool": rule_pool,
            "synthetic_used": synthetic_count_used,
            "external_total": external_stats.get("external_total", 0),
            "external_used": external_stats.get("external_used", 0),
            "external_invalid": external_stats.get("external_invalid", 0),
        },
        "inputs": {
            "manifest": str(args.manifest),
            "coverage": str(args.coverage),
            "readiness": str(args.readiness) if args.readiness else None,
            "attack_coverage": str(args.attack_coverage) if args.attack_coverage else None,
            "critical_gate": str(args.critical_gate) if args.critical_gate else None,
            "external_signals": str(args.external_signals) if args.external_signals else None,
            "external_first": external_first,
            "max_synthetic_ratio": max_synthetic_ratio,
            "max_external_per_host": max_external_per_host,
            "max_external_per_rule": max_external_per_rule,
        },
    }

    if args.output_summary:
        summary_path = Path(args.output_summary)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    if args.output_feature_contract:
        contract_path = Path(args.output_feature_contract)
        contract_path.parent.mkdir(parents=True, exist_ok=True)
        contract_path.write_text(json.dumps(feature_contract, indent=2) + "\n", encoding="utf-8")

    print("Signature ML training corpus snapshot:")
    print(f"- mode: {summary['dataset_mode']}")
    print(f"- sample count: {len(rows)}")
    print(f"- synthetic used: {synthetic_count_used}")
    print(f"- adjudicated count: {adjudicated_count}")
    print(f"- unresolved count: {unresolved_count}")
    print(f"- positive count: {positive_count}")
    print(f"- negative count: {negative_count}")
    print(f"- feature contract sha256: {feature_contract.get('contract_sha256')}")
    if external_stats.get("external_used", 0) > 0:
        print(
            f"- external signals: {external_stats.get('external_used', 0)} used "
            f"(total {external_stats.get('external_total', 0)}, invalid {external_stats.get('external_invalid', 0)})"
        )
    print(f"- output: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
