use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use platform_linux::{EbpfEngine, EbpfError, EventType};

fn collect_elf_paths(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|err| format!("failed to read ebpf objects dir {}: {}", dir.display(), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("read dir entry: {}", err))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("o") {
            out.push(path);
        }
    }
    if out.is_empty() {
        return Err(format!("no ebpf object files found in {}", dir.display()));
    }
    out.sort();
    Ok(out)
}

fn parse_args() -> (PathBuf, Duration, usize) {
    let mut objects_dir: Option<PathBuf> = None;
    let mut duration = Duration::from_millis(2500);
    let mut min_exec = 1usize;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--objects-dir" => {
                if let Some(val) = args.next() {
                    objects_dir = Some(PathBuf::from(val));
                }
            }
            "--duration-ms" => {
                if let Some(val) = args.next() {
                    if let Ok(ms) = val.parse::<u64>() {
                        duration = Duration::from_millis(ms.max(250));
                    }
                }
            }
            "--min-process-exec" => {
                if let Some(val) = args.next() {
                    if let Ok(count) = val.parse::<usize>() {
                        min_exec = count;
                    }
                }
            }
            _ => {}
        }
    }

    let objects_dir = objects_dir
        .or_else(|| {
            std::env::var("EGUARD_EBPF_OBJECTS_DIR")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("zig-out/ebpf"));

    (objects_dir, duration, min_exec)
}

fn main() -> Result<(), EbpfError> {
    let (objects_dir, duration, min_exec) = parse_args();
    let paths = collect_elf_paths(&objects_dir).map_err(EbpfError::Backend)?;
    let ring_map = std::env::var("EGUARD_EBPF_RING_MAP").unwrap_or_else(|_| "events".to_string());

    let mut engine = EbpfEngine::from_elfs(&paths, &ring_map)?;

    // Generate a few events.
    let _ = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("echo ebpf_smoke_exec >/dev/null")
        .status();

    let _ = std::fs::create_dir_all("/tmp");
    let _ = std::fs::write("/tmp/ebpf_smoke.txt", "eguard-ebpf-smoke");
    let _ = std::fs::File::open("/tmp/ebpf_smoke.txt");

    if let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") {
        if let Ok(addr) = listener.local_addr() {
            std::thread::spawn(move || {
                let _ = listener.accept();
            });
            let _ = std::net::TcpStream::connect(addr);
        }
    }

    let mut exec_count = 0usize;
    let mut open_count = 0usize;
    let mut tcp_count = 0usize;
    let start = Instant::now();
    while start.elapsed() < duration {
        let events = engine.poll_once(Duration::from_millis(200))?;
        for event in events {
            match event.event_type {
                EventType::ProcessExec => exec_count += 1,
                EventType::FileOpen => open_count += 1,
                EventType::TcpConnect => tcp_count += 1,
                _ => {}
            }
        }
    }

    println!("ebpf_smoke counts: exec={exec_count} open={open_count} tcp={tcp_count}");

    if exec_count < min_exec {
        return Err(EbpfError::Backend(format!(
            "missing process_exec events (got {exec_count})"
        )));
    }
    if open_count == 0 {
        return Err(EbpfError::Backend("missing file_open events".to_string()));
    }
    if tcp_count == 0 {
        return Err(EbpfError::Backend("missing tcp_connect events".to_string()));
    }

    Ok(())
}
