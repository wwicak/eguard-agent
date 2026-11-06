use crate::types::EventClass;
use crate::util::set_of;

use super::predicate::{TemporalLink, TemporalPredicate};
use super::rule::{RuleLevel, TemporalRule, TemporalStage};

fn stage(predicate: TemporalPredicate, within_secs: u64) -> TemporalStage {
    TemporalStage { predicate, within_secs }
}

fn rule(name: &str, level: RuleLevel, stages: Vec<TemporalStage>) -> TemporalRule {
    TemporalRule { name: name.into(), level, stages, any_order: false }
}

pub(super) fn default_rules() -> Vec<TemporalRule> {
    use EventClass::{FileOpen, NetworkConnect};
    use RuleLevel::{High, Medium};
    use TemporalLink::*;
    let shells = set_of(["sh", "bash", "dash", "zsh", "ksh", "fish", "python", "python3", "perl", "ruby"]);
    let senders = set_of(["curl", "wget", "nc", "nc.openbsd", "nc.traditional", "ncat", "netcat", "socat", "python", "python3", "perl", "ruby", "php", "node", "openssl", "rclone", "ftp", "tftp", "powershell.exe", "pwsh.exe", "certutil.exe", "bitsadmin.exe", "curl.exe"]);
    let mut readers = senders.clone();
    readers.extend(set_of(["cat", "cp", "tar", "gzip", "zip", "xxd", "base64", "dd", "head", "tail"]));
    let persistence = TemporalPredicate {
        event_class: FileOpen,
        require_file_write: true,
        file_path_contains: Some(set_of(["/etc/cron", "/var/spool/cron/", "/etc/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/", "/.config/systemd/user/", "/etc/init.d/", "/etc/rc.local", "/etc/profile.d/", "/.bashrc", "/.bash_profile", "/.profile", "/.zshrc", "/.config/autostart/", "/library/launchagents/", "/library/launchdaemons/"])),
        process_not_any_of: Some(set_of(["dpkg", "rpm", "apt", "apt-get", "dnf", "yum", "zypper", "packagekitd", "snapd", "unattended-upgr", "systemd", "systemctl", "systemd-sysv-install", "deb-systemd-helper", "puppet", "chef-client", "salt-minion"])),
        file_path_not_contains: Some(set_of([".dpkg-new", ".dpkg-tmp", ".rpmnew", ".rpmsave", ".swp", ".swx"])),
        ..Default::default()
    };
    let mut activation_write = persistence.clone();
    activation_write.process_any_of = Some(set_of(["sh", "bash", "dash", "zsh", "python", "python3", "perl", "php", "curl", "wget", "tee", "cp", "mv", "crontab"]));
    activation_write.file_path_contains = Some(set_of(["/etc/cron", "/var/spool/cron/", "/etc/systemd/system/", "/.config/systemd/user/", "/etc/init.d/", "/etc/rc.local"]));

    let mut pipe = rule("phi_download_pipe_shell", Medium, vec![
        stage(TemporalPredicate {
            process_any_of: Some(set_of(["curl", "wget", "fetch"])),
            command_line_contains: Some(set_of(["://"])),
            command_line_not_contains: Some(set_of([" -o ", " --output ", " -p "])),
            ..Default::default()
        }, 10),
        stage(TemporalPredicate {
            process_any_of: Some(shells.clone()),
            command_line_exact_any_of: Some(set_of(["sh", "bash", "dash", "zsh", "ksh", "sh -s", "bash -s", "-", "python", "python3", "perl", "sudo sh", "sudo bash"])),
            link: Sibling,
            ..Default::default()
        }, 10),
    ]);
    // A pipeline is also the normal installer shape; it is not a high-grade attack by itself.
    pipe.any_order = true;

    vec![
        rule("phi_webshell", High, vec![
            stage(TemporalPredicate {
                process_any_of: Some(set_of(["sh", "bash", "dash", "zsh", "ksh", "cmd.exe", "powershell.exe", "pwsh.exe"])),
                parent_any_of: Some(set_of(["nginx", "apache2", "httpd", "caddy", "lighttpd", "w3wp.exe", "httpd.exe", "tomcat", "uwsgi", "gunicorn"])),
                parent_starts_with: Some(vec!["php-fpm".into(), "php-cgi".into()]),
                command_line_not_contains: Some(set_of(["sendmail -t", "sendmail -oi", "/usr/sbin/sendmail"])),
                ..Default::default()
            }, 30),
            stage(TemporalPredicate { event_class: NetworkConnect, link: SameProcessOrDescendant, dst_not_loopback: true, ..Default::default() }, 30),
        ]),
        rule("phi_unbrokered_root_shell", High, vec![
            stage(TemporalPredicate { uid_ne: Some(0), ..Default::default() }, 60),
            stage(TemporalPredicate {
                process_any_of: Some(shells.clone()), uid_eq: Some(0), link: SameProcessOrChild,
                parent_not_any_of: Some(set_of(["sudo", "sudo-rs", "su", "doas", "pkexec", "run0", "sshd", "sshd-session", "login", "systemd", "cron", "crond", "polkitd", "polkit-agent-helper-1", "gdm-session-worker", "lightdm", "sddm"])),
                ..Default::default()
            }, 20),
        ]),
        rule("phi_reverse_shell", High, vec![
            stage(TemporalPredicate {
                process_any_of: Some(set_of(["sh", "bash", "dash", "zsh", "ksh", "nc", "nc.openbsd", "nc.traditional", "ncat", "netcat", "socat", "python", "python3", "perl", "php", "ruby", "telnet"])),
                command_line_all_of: vec![
                    set_of(["/dev/tcp/", "/dev/udp/", " -e ", "nc -c", "ncat -c", " --exec ", "socat exec:", "socat tcp", "mkfifo", "socket.socket", "fsockopen", "tcpsocket", "io::socket::inet"]),
                    set_of([" -i", "0>&1", ">&", "<&", "exec", "dup2", "pty.spawn", "/bin/sh", "/bin/bash", "|sh", "| sh", "|bash", "| bash"]),
                ],
                ..Default::default()
            }, 60),
            stage(TemporalPredicate { event_class: NetworkConnect, link: SameProcessOrDescendantOrSibling, dst_not_loopback: true, ..Default::default() }, 10),
        ]),
        pipe,
        rule("phi_download_then_exec_file", Medium, vec![
            stage(TemporalPredicate {
                process_any_of: Some(set_of(["curl", "wget"])),
                command_line_contains: Some(set_of([" -o /tmp/", " -o /dev/shm/", " -o /var/tmp/", " -p /tmp/", "--output /tmp/"])),
                ..Default::default()
            }, 60),
            stage(TemporalPredicate {
                file_path_contains: Some(set_of(["/tmp/", "/dev/shm/", "/var/tmp/"])),
                link: SiblingOrChild, ..Default::default()
            }, 60),
        ]),
        rule("phi_interpreter_download_exec", High, vec![stage(TemporalPredicate {
            process_any_of: Some(set_of(["python", "python2", "python3", "perl", "ruby", "php", "node"])),
            command_line_all_of: vec![
                set_of([" -c ", " -e ", " -r "]),
                set_of(["urlopen", "urllib.request", "requests.get", "lwp::simple", "getstore", "open-uri", "net::http", "file_get_contents('http", "http.get("]),
                set_of(["exec(", "eval(", "system(", "subprocess", "os.system", "popen", "| sh", "|sh", "child_process"]),
            ],
            ..Default::default()
        }, 1)]),
        rule("phi_remote_exec_tool", High, vec![
            stage(TemporalPredicate {
                command_line_contains: Some(set_of(["wmiexec.py", "psexec.py", "smbexec.py", "atexec.py", "dcomexec.py", "crackmapexec ", "netexec ", "evil-winrm "])),
                ..Default::default()
            }, 120),
            stage(TemporalPredicate { event_class: NetworkConnect, dst_port_any_of: Some(crate::util::set_u16([135, 139, 445, 5985, 5986])), ..Default::default() }, 15),
        ]),
        rule("phi_private_credential_read", Medium, vec![stage(TemporalPredicate {
            event_class: FileOpen, require_credential_source: true,
            process_any_of: Some(set_of(["cat", "grep", "egrep", "awk", "sed", "strings", "xxd", "hexdump", "head", "tail", "less", "more", "cp", "tar", "bash", "sh", "dash", "zsh", "fish", "python", "python3", "perl", "ruby", "php", "sqlite3", "security", "plutil"])),
            ..Default::default()
        }, 1)]),
        rule("phi_ssh_unusual_key", Medium, vec![
            stage(TemporalPredicate { process_any_of: Some(set_of(["ssh", "scp", "sftp"])), command_line_contains: Some(set_of([" -i /tmp/", " -i /dev/shm/", " -i /var/tmp/", " -i /run/user/", "stricthostkeychecking=no"])), ..Default::default() }, 30),
            stage(TemporalPredicate { event_class: NetworkConnect, dst_port_any_of: Some(crate::util::set_u16([22])), ..Default::default() }, 30),
        ]),
        rule("phi_credential_exfil", High, vec![
            stage(TemporalPredicate { event_class: FileOpen, require_credential_source: true, process_any_of: Some(readers), ..Default::default() }, 120),
            stage(TemporalPredicate { event_class: NetworkConnect, process_any_of: Some(senders), link: SameProcessOrSibling, dst_not_loopback: true, ..Default::default() }, 120),
        ]),
        rule("phi_persistence_write", Medium, vec![stage(persistence, 1)]),
        rule("phi_persistence_install", High, vec![
            stage(activation_write, 120),
            stage(TemporalPredicate {
                process_any_of: Some(set_of(["systemctl", "crontab", "at", "update-rc.d", "chkconfig", "launchctl"])),
                command_line_contains: Some(set_of(["enable", "start", "load", "bootstrap", "crontab", " at ", "add"])),
                link: SameProcessOrDescendantOrSibling, ..Default::default()
            }, 120),
        ]),
        rule("phi_data_staging", High, vec![
            stage(TemporalPredicate {
                process_any_of: Some(set_of(["tar", "zip", "7z", "7za", "rar", "gzip", "xz", "zstd", "7z.exe", "rar.exe", "makecab.exe", "powershell.exe"])),
                command_line_all_of: vec![
                    set_of(["/tmp/", "/dev/shm/", "/var/tmp/", "\\temp\\", "\\appdata\\local\\temp", "compress-archive"]),
                    set_of(["/home/", "/root", "/etc", "/var/www", ".ssh", "documents", "\\users\\", "desktop"]),
                ],
                ..Default::default()
            }, 600),
            stage(TemporalPredicate {
                event_class: NetworkConnect,
                process_any_of: Some(set_of(["curl", "wget", "nc", "ncat", "socat", "scp", "sftp", "ftp", "rclone", "python", "python3", "perl", "curl.exe", "powershell.exe", "bitsadmin.exe"])),
                link: SameProcessOrDescendantOrSibling, dst_not_loopback: true, ..Default::default()
            }, 600),
        ]),
    ]
}
