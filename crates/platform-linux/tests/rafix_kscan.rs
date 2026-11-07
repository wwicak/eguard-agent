// RULEAUDIT2 lane A4 characterization of platform-linux scan_kernel_integrity
// against synthetic stock and attack fixture trees; precision regressions.

use std::fs;
use std::path::PathBuf;

use platform_linux::{scan_kernel_integrity, KernelIntegrityScanOptions};

fn root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("ra2-a4-kscan-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn opts(r: &PathBuf) -> KernelIntegrityScanOptions {
    KernelIntegrityScanOptions {
        proc_modules_path: r.join("proc_modules"),
        sys_module_path: r.join("sys_module"),
        kprobe_events_path: r.join("kprobe_events"),
        current_tracer_path: r.join("current_tracer"),
        ftrace_filter_path: r.join("set_ftrace_filter"),
        lsm_list_path: r.join("lsm"),
        bpffs_root: r.join("bpffs"),
    }
}

fn module(r: &PathBuf, name: &str, taint: Option<&str>, signer: Option<&str>) {
    let d = r.join("sys_module").join(name);
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("initstate"), "live\n").unwrap();
    if let Some(t) = taint {
        fs::write(d.join("taint"), format!("{t}\n")).unwrap();
    }
    if let Some(s) = signer {
        fs::write(d.join("signer"), format!("{s}\n")).unwrap();
    }
}

#[test]
fn rafix_kscan_stock_debian12_is_quiet() {
    let r = root("stock");
    // Loaded modules, real /sys/module/<m>/taint format is letters ("" or "OE"/"POE").
    fs::write(
        r.join("proc_modules"),
        "xt_mark 12288 1 - Live 0x0\nnvidia 56623104 0 - Live 0x0 (POE)\n",
    )
    .unwrap();
    module(&r, "xt_mark", Some(""), Some("Debian Secure Boot CA"));
    module(&r, "nvidia", Some("POE"), None);
    // Built-in subsystem: present in /sys/module, no initstate.
    fs::create_dir_all(r.join("sys_module").join("kernel")).unwrap();
    fs::write(r.join("kprobe_events"), "").unwrap();
    fs::write(r.join("current_tracer"), "nop\n").unwrap();
    // What the kernel returns for an EMPTY filter (kernel/trace/ftrace.c t_show PRINTALL).
    fs::write(
        r.join("set_ftrace_filter"),
        "#### all functions enabled ####\n",
    )
    .unwrap();
    // Debian 12 default (verified on this workstation: /sys/kernel/security/lsm).
    fs::write(
        r.join("lsm"),
        "lockdown,capability,landlock,yama,apparmor,tomoyo,bpf\n",
    )
    .unwrap();
    fs::create_dir_all(r.join("bpffs").join("snap")).unwrap(); // snapd (Ubuntu); seen in .35 corpus
    fs::create_dir_all(r.join("bpffs").join("tc")).unwrap(); // iproute2 / cilium

    module(&r, "loading_module", Some(""), None);
    fs::write(r.join("sys_module/loading_module/initstate"), "coming\n").unwrap();
    let rep = scan_kernel_integrity(&opts(&r)).unwrap();
    assert!(!rep
        .indicators
        .iter()
        .any(|s| s.starts_with("hidden_module_")));
    println!("A4|kscan|stock|{}", rep.command_line());
    assert_eq!(rep.ftrace_filter_count, 0);
    assert!(rep.lsm_list.iter().any(|s| s == "bpf"));
    assert!(!rep.indicators.iter().any(|s| s.starts_with("ftrace_")
        || s == "lsm_bpf_enabled"
        || s.starts_with("bpffs_pinned_object:")));
    let _ = fs::remove_dir_all(&r);
}

#[test]
fn rafix_kscan_attack_taint_and_probe_symbol() {
    let r = root("attack");
    // Unsigned out-of-tree LKM rootkit that did NOT hide itself.
    fs::write(
        r.join("proc_modules"),
        "diamorphine 16384 0 - Live 0x0 (OE)\n",
    )
    .unwrap();
    module(&r, "diamorphine", Some("OE"), None);
    // kprobe with fetch args: the hooked symbol is NOT the last token.
    fs::write(
        r.join("kprobe_events"),
        "p:kprobes/hk __x64_sys_getdents64 dirent=%si count=%dx\n",
    )
    .unwrap();
    fs::write(r.join("current_tracer"), "nop\n").unwrap();
    fs::write(
        r.join("set_ftrace_filter"),
        "#### all functions enabled ####\n",
    )
    .unwrap();
    fs::write(r.join("lsm"), "lockdown,capability,yama,apparmor\n").unwrap();
    fs::create_dir_all(r.join("bpffs")).unwrap();

    let rep = scan_kernel_integrity(&opts(&r)).unwrap();
    println!("A4|kscan|attack|{}", rep.command_line());
    let ind = &rep.indicators;
    assert!(
        ind.iter().any(|i| i == "unsigned_oot_module:diamorphine"),
        "{ind:?}"
    );
    assert!(
        ind.iter().any(|i| i == "kprobe_hook:__x64_sys_getdents64"),
        "{ind:?}"
    );
    assert_eq!(rep.kprobe_count, 1);
    assert!(!ind.iter().any(|i| i.starts_with("kprobe_hook_count:")));
    let _ = fs::remove_dir_all(&r);
}

#[test]
fn rafix_unresolved_exec_invocation_is_not_a_resolved_image() {
    use platform_linux::{enrich_event, EventType, RawEvent};
    let enriched = enrich_event(RawEvent {
        event_type: EventType::ProcessExec,
        pid: 999_999_999,
        payload: "path=/dev/fd/5;comm=runc".into(),
        ..Default::default()
    });
    assert_eq!(enriched.file_path.as_deref(), Some("/dev/fd/5"));
    assert!(
        enriched.process_exe.is_none(),
        "unresolved invocation must not impersonate a resolved image"
    );
}
