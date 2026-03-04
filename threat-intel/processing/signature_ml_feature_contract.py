#!/usr/bin/env python3
"""Canonical feature contract for signature-ML processing pipeline."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

CONTRACT_VERSION = "v2"

FEATURES: tuple[str, ...] = (
    "z1_ioc_hit",
    "z2_temporal_count",
    "z3_anomaly_high",
    "z3_anomaly_med",
    "z4_killchain_count",
    "yara_hit_count",
    "string_sig_count",
    "event_class_risk",
    "uid_is_root",
    "dst_port_risk",
    "has_command_line",
    "cmdline_length_norm",
    "prefilter_hit",
    "multi_layer_count",
    "cmdline_renyi_h2",
    "cmdline_compression",
    "cmdline_min_entropy",
    "cmdline_entropy_gap",
    "dns_entropy",
    "event_size_norm",
    "container_risk",
    "file_path_entropy",
    "file_path_depth",
    "behavioral_alarm_count",
    "z1_z2_interaction",
    "z1_z4_interaction",
    "anomaly_behavioral",
    # Process tree / lineage
    "process_tree_depth_norm",
    "rare_parent_child_pair",
    "parent_cmdline_hash_risk",
    "parent_child_cmdline_distance",
    "sibling_spawn_burst_norm",
    # File mutation behavior
    "sensitive_path_write_velocity",
    "rename_churn_norm",
    "extension_entropy",
    "executable_write_ratio",
    "temp_to_system_write_ratio",
    # Network graph / beaconing
    "conn_fanout_norm",
    "unique_dst_ip_norm",
    "unique_dst_port_norm",
    "beacon_periodicity_score",
    "network_graph_centrality",
    # Credential access indicators
    "credential_access_indicator",
    "lsass_access_indicator",
    "sam_access_indicator",
    "token_theft_indicator",
    "lolbin_credential_chain",
    # Cross-domain interactions
    "network_credential_interaction",
    "tree_network_interaction",
    "file_behavior_interaction",
)


def _contract_payload() -> dict[str, Any]:
    return {
        "suite": "signature_ml_feature_contract",
        "version": CONTRACT_VERSION,
        "features": list(FEATURES),
    }


def contract_sha256() -> str:
    encoded = json.dumps(_contract_payload(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_feature_contract() -> dict[str, Any]:
    return {
        **_contract_payload(),
        "feature_count": len(FEATURES),
        "contract_sha256": contract_sha256(),
    }


def write_feature_contract(path: Path) -> Path:
    payload = load_feature_contract()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path
