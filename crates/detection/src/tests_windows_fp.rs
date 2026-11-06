use std::collections::{HashMap, VecDeque};

use crate::{AnomalyConfig, AnomalyEngine, EventClass, TelemetryEvent};

fn discovery_events() -> Vec<TelemetryEvent> {
    let fixtures: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("testdata/windows_discovery.json")).unwrap();
    fixtures
        .into_iter()
        .map(|fixture| serde_json::from_value(fixture["event"].clone()).unwrap())
        .collect()
}

#[test]
fn windows_fp_discovery_has_no_kl_alarm_without_baseline() {
    for event in discovery_events() {
        let mut engine = AnomalyEngine::default();
        for _ in 0..1000 {
            assert!(engine.observe(&event).is_none(), "{}", event.process);
        }
    }
}

#[test]
fn windows_fp_supplied_baseline_still_detects_distribution_shift() {
    let mut event = discovery_events().remove(1);
    let mut engine = AnomalyEngine::default();
    engine.set_baseline(
        event.process_key(),
        HashMap::from([(EventClass::ProcessExec, 1.0)]),
    );
    event.dst_ip = Some("203.0.113.9".into());
    event.dst_port = Some(4444);
    for _ in 0..127 {
        assert!(engine.observe(&event).is_none());
    }
    assert!(engine.observe(&event).unwrap().high);
}

#[test]
fn windows_fp_repeated_discovery_commands_do_not_blow_up_entropy_z() {
    let events = discovery_events();
    let entropy = crate::math::shannon_entropy_bits(events[1].command_line.as_ref().unwrap());
    // The observed SSDPSRV spike was 0.1999764859 bits over a constant baseline.
    let history = VecDeque::from(vec![entropy - 0.19997648594628412; 10]);
    let z = crate::math::robust_z(entropy, &history);
    assert!(z.is_finite() && z < AnomalyConfig::default().entropy_z_threshold);
    for mut event in events {
        let mut engine = AnomalyEngine::default();
        event.event_class = EventClass::ProcessExec;
        for _ in 0..10 {
            assert!(engine.observe(&event).is_none());
        }
        event.command_line.as_mut().unwrap().push('Z');
        assert!(engine.observe(&event).is_none());
    }
}

#[test]
fn windows_fp_warmed_encoded_command_still_alerts_with_calibrated_thresholds() {
    let config = AnomalyConfig::default();
    let mut engine = AnomalyEngine::new(config.clone());
    let mut event = discovery_events().remove(1);
    event.event_class = EventClass::ProcessExec;
    event.process = "powershell.exe".into();
    event.command_line =
        Some("powershell.exe -NoProfile -Command Write-Output aaaaaaaaaaaaaa".into());
    for _ in 0..10 {
        assert!(engine.observe(&event).is_none());
    }
    event.command_line = Some(format!(
        "powershell.exe -EncodedCommand {}",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".repeat(8)
    ));
    let decision = engine.observe(&event).expect("encoded command spike");
    assert!(decision.high);
    assert!(decision.entropy_z.unwrap() > config.entropy_z_threshold);
    assert!(decision.tau_high >= config.tau_floor_high);
    assert!(decision.tau_med >= config.tau_floor_med);
    assert_eq!(
        decision.tau_high,
        config
            .tau_floor_high
            .max(crate::tau_delta(11, 8, config.delta_high).unwrap())
    );
}

#[test]
fn windows_fp_discovery_network_metadata_is_not_ml_positive() {
    for event in discovery_events() {
        let features = crate::MlFeatures::extract(
            &event,
            &Default::default(),
            0,
            0,
            0,
            0,
            0,
            &Default::default(),
        );
        let score = crate::MlEngine::new().score(&features);
        assert!(!score.positive, "{} score={}", event.process, score.score);
    }
}

#[test]
fn windows_fp_network_ioc_attack_remains_ml_positive() {
    let mut event = discovery_events().remove(0);
    event.dst_ip = Some("203.0.113.9".into());
    event.dst_port = Some(4444);
    let signals = crate::DetectionSignals {
        z1_exact_ioc: true,
        network_ioc_hit: true,
        ..Default::default()
    };
    let features = crate::MlFeatures::extract(&event, &signals, 0, 0, 0, 0, 0, &Default::default());
    assert!(crate::MlEngine::new().score(&features).positive);
}
