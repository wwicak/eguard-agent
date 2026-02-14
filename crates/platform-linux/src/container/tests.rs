use super::*;

#[test]
fn test_docker_cgroup() {
    let content = "0::/docker/abc123def456789012345678901234567890123456789012345678901234\n";
    let ctx = parse_container_from_cgroup(content).unwrap();
    assert_eq!(ctx.runtime, ContainerRuntime::Docker);
    assert_eq!(
        ctx.container_id,
        "abc123def456789012345678901234567890123456789012345678901234"
    );
    assert_eq!(ctx.container_id_short, "abc123def456");
}

#[test]
fn test_docker_systemd_scope() {
    let content = "0::/system.slice/docker-abc123def456789012345678901234567890123456789012345678901234.scope\n";
    let ctx = parse_container_from_cgroup(content).unwrap();
    assert_eq!(ctx.runtime, ContainerRuntime::Docker);
    assert_eq!(
        ctx.container_id,
        "abc123def456789012345678901234567890123456789012345678901234"
    );
}

#[test]
fn test_containerd_cgroup() {
    let content = "0::/system.slice/cri-containerd-abcdef123456789012345678901234567890123456789012345678901234.scope\n";
    let ctx = parse_container_from_cgroup(content).unwrap();
    assert_eq!(ctx.runtime, ContainerRuntime::Containerd);
}

#[test]
fn test_crio_cgroup() {
    let content = "0::/crio-abcdef123456789012345678901234567890123456789012345678901234.scope\n";
    let ctx = parse_container_from_cgroup(content).unwrap();
    assert_eq!(ctx.runtime, ContainerRuntime::CriO);
}

#[test]
fn test_podman_cgroup() {
    let content = "0::/machine.slice/libpod-abcdef123456789012345678901234567890123456789012345678901234.scope\n";
    let ctx = parse_container_from_cgroup(content).unwrap();
    assert_eq!(ctx.runtime, ContainerRuntime::Podman);
}

#[test]
fn test_lxc_cgroup() {
    let content = "0::/lxc/my-container\n";
    let ctx = parse_container_from_cgroup(content).unwrap();
    assert_eq!(ctx.runtime, ContainerRuntime::Lxc);
    assert_eq!(ctx.container_id, "my-container");
}

#[test]
fn test_kubernetes_cgroup() {
    let content = "0::/kubepods/burstable/pod12345678-1234-1234-1234-123456789012/abc123def456789012345678901234567890123456789012345678901234\n";
    let ctx = parse_container_from_cgroup(content).unwrap();
    assert_eq!(ctx.runtime, ContainerRuntime::Kubernetes);
    assert!(ctx.pod_uid.is_some());
}

#[test]
fn test_host_process() {
    let content = "0::/\n";
    assert!(parse_container_from_cgroup(content).is_none());
}

#[test]
fn test_host_systemd_slice() {
    let content = "0::/system.slice/sshd.service\n";
    assert!(parse_container_from_cgroup(content).is_none());
}

#[test]
fn test_is_hex_id() {
    assert!(is_hex_id("abc123def456"));
    assert!(is_hex_id(
        "abc123def456789012345678901234567890123456789012345678901234"
    ));
    assert!(!is_hex_id("short")); // too short
    assert!(!is_hex_id("not-hex-chars!!")); // non-hex
}

#[test]
fn test_container_labels_self() {
    // Our test process should be host
    let labels = container_labels(std::process::id());
    assert_eq!(
        labels.get("container_runtime").map(|s| s.as_str()),
        Some("host")
    );
}

#[test]
fn test_namespace_info_self() {
    let info = get_namespace_info(std::process::id());
    assert!(info.pid_ns.is_some());
    assert!(info.mnt_ns.is_some());
}
