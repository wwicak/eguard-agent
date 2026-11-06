#!/usr/bin/env python3
"""Synthetic A5 benign cases plus ordinary endpoint activity; no customer data."""
import json
import sys
from pathlib import Path


def build_events():
    fixtures = json.loads(Path(__file__).with_name("sigma_benign_cases.json").read_text())
    events = []
    def add(kind, process="synthetic", parent="test", command=None, path=None, **extra):
        events.append(dict(ts_unix=len(events) + 1, event_class=kind, pid=42, ppid=1, uid=1000,
            process=process, parent_process=parent, session_id=42, file_path=path, command_line=command,
            file_write=False, container_escape=False, container_privileged=False, **extra))
    for case in fixtures:
        for ev in case["events"]:
            kind = {"process_exec": "ProcessExec", "file_open": "FileOpen"}[ev["class"]]
            process = ev.get("process", "synthetic")
            path = ev.get("file_path")
            if kind == "ProcessExec" and not path:
                path = "/usr/bin/" + process
            add(kind, process, ev.get("parent", "test"), ev.get("cmdline"), path)
    # Balance observable event classes, rather than testing a process-only corpus.
    for kind in ["ProcessExec", "FileOpen", "NetworkConnect", "DnsQuery"]:
        count = sum(e["event_class"] == kind for e in events)
        for i in range(count, 125):
            if kind == "ProcessExec":
                process, command = [("git", "git status --short"), ("python3", "python3 app.py"), ("make", "make all"), ("bash", "bash build.sh")][i % 4]
                add(kind, process, "bash", command, "/usr/bin/" + process)
            elif kind == "FileOpen":
                add(kind, "python3", "bash", path=f"/home/synthetic/project/document-{i}.txt")
            elif kind == "NetworkConnect":
                add(kind, "curl", "bash", dst_ip="8.8.8.9", dst_domain="updates.example", dst_port=443)
            else:
                add(kind, "browser", "test", dst_domain=f"office-{i}.example")
    return events


if __name__ == "__main__":
    Path(sys.argv[1]).write_text(json.dumps(build_events()))
