#!/usr/bin/env python3
import argparse
import json
import pathlib
import sys
from typing import Any


def load_json(root: pathlib.Path, relative: str) -> dict[str, Any]:
    path = root / relative
    if not path.exists():
        raise FileNotFoundError(f"missing metrics artifact: {relative}")
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Enforce optimization guardrail metric thresholds.")
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--output",
        default="artifacts/optimization-guardrail-summary/metrics.json",
        help="summary output path",
    )
    args = parser.parse_args()

    root = pathlib.Path(args.root)
    failures: list[str] = []

    try:
        det = load_json(root, "artifacts/detection-benchmark/metrics.json")
        det_regression = load_json(root, "artifacts/detection-benchmark/regression-report.json")
        tick = load_json(root, "artifacts/runtime-tick-slo/metrics.json")
        replay = load_json(root, "artifacts/replay-determinism/metrics.json")
        detection_quality = load_json(root, "artifacts/detection-quality-gate/metrics.json")
        drop = load_json(root, "artifacts/ebpf-drop-rate-pressure/metrics.json")
        rule_push = load_json(root, "artifacts/rule-push-slo/metrics.json")
        rule_push_regression = load_json(root, "artifacts/rule-push-slo/regression-report.json")
        ebpf_budget = load_json(root, "artifacts/ebpf-resource-budget/metrics.json")
        perf_gate = load_json(root, "artifacts/perf-profile-gate/metrics.json")
        release_opt = load_json(root, "artifacts/release-profile-opt/metrics.json")
        trend_report = load_json(root, "artifacts/detection-quality-gate/trend-drift-report.json")
        adversary_score = load_json(
            root, "artifacts/detection-quality-gate/adversary-emulation-score.json"
        )
    except Exception as err:
        print(str(err), file=sys.stderr)
        return 1

    if int(det.get("wall_clock_ms", 10**9)) > 60_000:
        failures.append(f"detection benchmark wall_clock_ms too high: {det.get('wall_clock_ms')}")

    det_regression_status = det_regression.get("status")
    if det_regression_status not in {"pass", "skipped_no_baseline"}:
        failures.append(
            "detection benchmark regression gate status invalid: "
            f"{det_regression_status}"
        )
    if int(tick.get("wall_clock_ms", 10**9)) > 60_000:
        failures.append(f"runtime tick SLO wall_clock_ms too high: {tick.get('wall_clock_ms')}")
    if int(replay.get("wall_clock_ms", 10**9)) > 60_000:
        failures.append(f"replay determinism wall_clock_ms too high: {replay.get('wall_clock_ms')}")

    dq = detection_quality.get("measured", {})
    if float(dq.get("precision", 0.0)) < 0.99:
        failures.append(f"detection quality precision below threshold: {dq.get('precision')} < 0.99")
    if float(dq.get("recall", 0.0)) < 0.99:
        failures.append(f"detection quality recall below threshold: {dq.get('recall')} < 0.99")
    if float(dq.get("false_alarm_upper_bound", 1e9)) > 0.20:
        failures.append(
            f"detection quality false_alarm_upper_bound too high: {dq.get('false_alarm_upper_bound')} > 0.20"
        )

    corpus = detection_quality.get("corpus", {})
    if int(corpus.get("scenario_count", 0)) < 12:
        failures.append(
            f"detection quality corpus scenario_count too low: {corpus.get('scenario_count')} < 12"
        )
    if int(corpus.get("total_events", 0)) < 60:
        failures.append(
            f"detection quality corpus total_events too low: {corpus.get('total_events')} < 60"
        )
    if int(corpus.get("malicious_events", 0)) < 5:
        failures.append(
            f"detection quality corpus malicious_events too low: {corpus.get('malicious_events')} < 5"
        )

    by_conf = dq.get("by_confidence_threshold", {})
    for label in ("definite", "very_high", "high"):
        class_metrics = by_conf.get(label)
        if not isinstance(class_metrics, dict):
            failures.append(f"missing detection quality by_confidence_threshold.{label} metrics")
            continue
        if float(class_metrics.get("precision", 0.0)) < 0.99:
            failures.append(
                f"detection quality {label} precision below threshold: {class_metrics.get('precision')} < 0.99"
            )
        if float(class_metrics.get("recall", 0.0)) < 0.99:
            failures.append(
                f"detection quality {label} recall below threshold: {class_metrics.get('recall')} < 0.99"
            )
        if float(class_metrics.get("false_alarm_upper_bound", 1e9)) > 0.20:
            failures.append(
                "detection quality "
                f"{label} false_alarm_upper_bound too high: {class_metrics.get('false_alarm_upper_bound')} > 0.20"
            )

    trend_path = root / "artifacts/detection-quality-gate/per-confidence-trend.ndjson"
    if not trend_path.exists():
        failures.append(
            "missing detection quality trend artifact: artifacts/detection-quality-gate/per-confidence-trend.ndjson"
        )
    else:
        lines = [line for line in trend_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            failures.append("detection quality trend artifact is empty")
        else:
            try:
                json.loads(lines[-1])
            except Exception as err:
                failures.append(f"detection quality trend artifact last line is invalid JSON: {err}")

    trend_status = trend_report.get("status")
    if trend_status not in {"ok", "insufficient_history"}:
        failures.append(f"detection quality trend drift status invalid: {trend_status}")

    adversary_status = adversary_score.get("status")
    if adversary_status != "pass":
        failures.append(f"adversary emulation score gate status invalid: {adversary_status}")

    adversary_thresholds = adversary_score.get("thresholds", {})
    adversary_scores = adversary_score.get("scores", {})
    adversary_final = float(adversary_scores.get("final_score", 0.0))
    adversary_focus = float(adversary_scores.get("focus_score", 0.0))
    adversary_min_final = float(adversary_thresholds.get("min_final_score", 92.0))
    adversary_min_focus = float(adversary_thresholds.get("min_focus_score", 95.0))

    if adversary_final < adversary_min_final:
        failures.append(
            "adversary emulation final score below threshold: "
            f"{adversary_final} < {adversary_min_final}"
        )
    if adversary_focus < adversary_min_focus:
        failures.append(
            "adversary emulation focus score below threshold: "
            f"{adversary_focus} < {adversary_min_focus}"
        )

    if int(drop.get("wall_clock_ms", 10**9)) > 60_000:
        failures.append(f"eBPF drop-rate pressure wall_clock_ms too high: {drop.get('wall_clock_ms')}")

    rp = rule_push.get("measured", {})
    if float(rp.get("transfer_seconds_at_link_rate", 1e9)) > 5.0:
        failures.append(
            f"rule push transfer exceeds SLO: {rp.get('transfer_seconds_at_link_rate')} > 5.0"
        )
    if float(rp.get("fleet_rollout_seconds", 1e9)) > 30.0:
        failures.append(f"rule push rollout exceeds SLO: {rp.get('fleet_rollout_seconds')} > 30.0")

    rule_push_regression_status = rule_push_regression.get("status")
    if rule_push_regression_status not in {"pass", "skipped_no_baseline"}:
        failures.append(
            "rule-push regression gate status invalid: "
            f"{rule_push_regression_status}"
        )

    eb = ebpf_budget.get("measured", {})
    if float(eb.get("binary_size_mb", 0.0)) <= 0.0:
        failures.append(f"binary size metric missing/invalid: {eb.get('binary_size_mb')}")
    if int(eb.get("release_build_wall_ms", 10**9)) > 120_000:
        failures.append(
            f"release build wall clock too high: {eb.get('release_build_wall_ms')} ms"
        )

    status = perf_gate.get("status")
    if status not in {"ok", "skipped"}:
        failures.append(f"perf profile gate status invalid: {status}")
    if status == "skipped" and perf_gate.get("reason") not in {
        "perf_not_available",
        "perf_unavailable_or_permission_denied",
    }:
        failures.append(f"perf profile gate skipped without accepted reason: {perf_gate.get('reason')}")

    if int(release_opt.get("baseline_release_build_ms", 10**9)) > 120_000:
        failures.append(
            f"release profile baseline build too high: {release_opt.get('baseline_release_build_ms')} ms"
        )

    summary = {
        "suite": "optimization_guardrail_thresholds",
        "status": "failed" if failures else "ok",
        "failures": failures,
        "artifacts": {
            "detection_benchmark": det,
            "detection_benchmark_regression": det_regression,
            "runtime_tick_slo": tick,
            "replay_determinism": replay,
            "detection_quality_gate": detection_quality,
            "ebpf_drop_rate_pressure": drop,
            "rule_push_slo": rule_push,
            "rule_push_regression": rule_push_regression,
            "ebpf_resource_budget": ebpf_budget,
            "perf_profile_gate": perf_gate,
            "release_profile_opt": release_opt,
            "detection_quality_trend_drift": trend_report,
            "adversary_emulation_score": adversary_score,
        },
    }

    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(f"wrote optimization guardrail threshold summary to {output_path}")

    if failures:
        print("optimization guardrail threshold failures:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("optimization guardrail thresholds passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
