//! Container runtime detection and cgroup-based container ID extraction.
//!
//! Parses `/proc/[pid]/cgroup` to identify container runtimes (Docker,
//! containerd, Podman, LXC, Kubernetes) and extract the container ID.
//! Also reads namespace information from `/proc/[pid]/ns/` to detect
//! namespace isolation boundaries.

use std::collections::HashMap;
use std::fs;

/// Detected container runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerRuntime {
    Docker,
    Containerd,
    CriO,
    Podman,
    Lxc,
    Kubernetes,
    Unknown,
    /// Process is running on the host (not in a container).
    Host,
}

impl ContainerRuntime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Containerd => "containerd",
            Self::CriO => "cri-o",
            Self::Podman => "podman",
            Self::Lxc => "lxc",
            Self::Kubernetes => "kubernetes",
            Self::Unknown => "unknown",
            Self::Host => "host",
        }
    }
}

/// Container context for a process.
#[derive(Debug, Clone)]
pub struct ContainerContext {
    /// Container runtime type.
    pub runtime: ContainerRuntime,
    /// Container ID (64-char hex for Docker/containerd, shorter for LXC).
    pub container_id: String,
    /// Short container ID (first 12 chars).
    pub container_id_short: String,
    /// Kubernetes pod UID (if applicable).
    pub pod_uid: Option<String>,
    /// Kubernetes namespace (parsed from cgroup path if available).
    pub k8s_namespace: Option<String>,
    /// The raw cgroup path that was matched.
    pub cgroup_path: String,
}

/// Namespace information for a process.
#[derive(Debug, Clone)]
pub struct NamespaceInfo {
    /// PID namespace inode (from /proc/[pid]/ns/pid).
    pub pid_ns: Option<u64>,
    /// Mount namespace inode.
    pub mnt_ns: Option<u64>,
    /// Network namespace inode.
    pub net_ns: Option<u64>,
    /// UTS namespace inode.
    pub uts_ns: Option<u64>,
    /// Whether this process is in the root PID namespace.
    pub is_host_pid_ns: bool,
}

/// Cached host PID namespace inode (read once from /proc/1/ns/pid).
static HOST_PID_NS: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();

fn get_host_pid_ns() -> Option<u64> {
    *HOST_PID_NS.get_or_init(|| read_ns_inode(1, "pid"))
}

/// Detect container context for a given PID.
pub fn detect_container(pid: u32) -> Option<ContainerContext> {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let content = fs::read_to_string(&cgroup_path).ok()?;
    parse_container_from_cgroup(&content)
}

/// Parse container info from cgroup file content.
fn parse_container_from_cgroup(content: &str) -> Option<ContainerContext> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // cgroup v2 format: "0::/path"
        // cgroup v1 format: "N:controller:/path"
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 3 {
            continue;
        }

        let cgroup_path = parts[2];

        // Skip root cgroup (host processes)
        if cgroup_path == "/" || cgroup_path.is_empty() {
            continue;
        }

        // Try to extract container info from the cgroup path
        if let Some(ctx) = parse_cgroup_path(cgroup_path) {
            return Some(ctx);
        }
    }

    None
}

/// Parse a single cgroup path to extract container context.
fn parse_cgroup_path(path: &str) -> Option<ContainerContext> {
    // Docker: /docker/<container_id>
    //         /system.slice/docker-<container_id>.scope
    if let Some(id) = extract_after_prefix(path, "/docker/") {
        return Some(build_context(ContainerRuntime::Docker, id, path));
    }
    if let Some(id) = extract_docker_scope(path) {
        return Some(build_context(ContainerRuntime::Docker, &id, path));
    }

    // containerd / CRI: /system.slice/containerd-<id>.scope
    //                    /.../cri-containerd-<id>.scope
    if let Some(id) = extract_containerd_id(path) {
        return Some(build_context(ContainerRuntime::Containerd, &id, path));
    }

    // CRI-O: /crio-<container_id>.scope
    if let Some(id) = extract_crio_id(path) {
        return Some(build_context(ContainerRuntime::CriO, &id, path));
    }

    // Kubernetes pods: /kubepods/burstable/pod<uid>/<container_id>
    //                  /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/<id>
    if let Some(ctx) = extract_kubernetes_context(path) {
        return Some(ctx);
    }

    // Podman: /libpod-<container_id>.scope
    //         /machine.slice/libpod-<id>.scope
    if let Some(id) = extract_podman_id(path) {
        return Some(build_context(ContainerRuntime::Podman, &id, path));
    }

    // LXC: /lxc/<container_name>
    //       /lxc.payload.<container_name>
    if let Some(id) = extract_lxc_id(path) {
        return Some(build_context(ContainerRuntime::Lxc, &id, path));
    }

    None
}

fn build_context(runtime: ContainerRuntime, id: &str, cgroup_path: &str) -> ContainerContext {
    let clean_id = id.trim_end_matches(".scope").to_string();
    let short = if clean_id.len() > 12 {
        clean_id[..12].to_string()
    } else {
        clean_id.clone()
    };

    ContainerContext {
        runtime,
        container_id: clean_id,
        container_id_short: short,
        pod_uid: None,
        k8s_namespace: None,
        cgroup_path: cgroup_path.to_string(),
    }
}

fn extract_after_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    let id = rest.split('/').next().unwrap_or(rest);
    if is_hex_id(id) {
        Some(id)
    } else {
        None
    }
}

fn extract_docker_scope(path: &str) -> Option<String> {
    // /system.slice/docker-<64hex>.scope
    for segment in path.split('/') {
        if let Some(rest) = segment.strip_prefix("docker-") {
            let id = rest.strip_suffix(".scope").unwrap_or(rest);
            if is_hex_id(id) {
                return Some(id.to_string());
            }
        }
    }
    None
}

fn extract_containerd_id(path: &str) -> Option<String> {
    for segment in path.split('/') {
        // cri-containerd-<id>.scope
        if let Some(rest) = segment.strip_prefix("cri-containerd-") {
            let id = rest.strip_suffix(".scope").unwrap_or(rest);
            if is_hex_id(id) {
                return Some(id.to_string());
            }
        }
        // containerd-<id>.scope
        if let Some(rest) = segment.strip_prefix("containerd-") {
            let id = rest.strip_suffix(".scope").unwrap_or(rest);
            if is_hex_id(id) {
                return Some(id.to_string());
            }
        }
    }
    None
}

fn extract_crio_id(path: &str) -> Option<String> {
    for segment in path.split('/') {
        if let Some(rest) = segment.strip_prefix("crio-") {
            let id = rest.strip_suffix(".scope").unwrap_or(rest);
            if is_hex_id(id) {
                return Some(id.to_string());
            }
        }
    }
    None
}

fn extract_podman_id(path: &str) -> Option<String> {
    for segment in path.split('/') {
        if let Some(rest) = segment.strip_prefix("libpod-") {
            let id = rest.strip_suffix(".scope").unwrap_or(rest);
            if is_hex_id(id) {
                return Some(id.to_string());
            }
        }
    }
    None
}

fn extract_lxc_id(path: &str) -> Option<String> {
    // /lxc/<name> or /lxc.payload.<name>
    if let Some(rest) = path.strip_prefix("/lxc/") {
        let name = rest.split('/').next().unwrap_or(rest);
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    for segment in path.split('/') {
        if let Some(name) = segment.strip_prefix("lxc.payload.") {
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

fn extract_kubernetes_context(path: &str) -> Option<ContainerContext> {
    // /kubepods/burstable/pod<uid>/<container_id>
    // /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/<runtime>-<id>.scope
    if !path.contains("kubepods") {
        return None;
    }

    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let mut pod_uid = None;
    let mut container_id = None;

    for (i, seg) in segments.iter().enumerate() {
        // Direct format: pod<uid>
        if let Some(uid) = seg.strip_prefix("pod") {
            if uid.len() >= 32 {
                pod_uid = Some(uid.to_string());
                // Next segment is the container ID
                if i + 1 < segments.len() && is_hex_id(segments[i + 1]) {
                    container_id = Some(segments[i + 1].to_string());
                }
            }
        }

        // Slice format: kubepods-burstable-pod<uid>.slice
        if seg.contains("-pod") && seg.ends_with(".slice") {
            if let Some(pos) = seg.find("-pod") {
                let after_pod = &seg[pos + 4..];
                let uid = after_pod.strip_suffix(".slice").unwrap_or(after_pod);
                // Remove dashes that systemd adds to UIDs
                let clean_uid = uid.replace('_', "-");
                if clean_uid.len() >= 32 {
                    pod_uid = Some(clean_uid);
                }
            }
        }

        // Container runtime scope: docker-<id>.scope, cri-containerd-<id>.scope, crio-<id>.scope
        if seg.ends_with(".scope") {
            for prefix in &["docker-", "cri-containerd-", "crio-", "containerd-"] {
                if let Some(rest) = seg.strip_prefix(prefix) {
                    let id = rest.strip_suffix(".scope").unwrap_or(rest);
                    if is_hex_id(id) {
                        container_id = Some(id.to_string());
                    }
                }
            }
        }
    }

    let cid = container_id?;
    let short = if cid.len() > 12 {
        cid[..12].to_string()
    } else {
        cid.clone()
    };

    Some(ContainerContext {
        runtime: ContainerRuntime::Kubernetes,
        container_id: cid,
        container_id_short: short,
        pod_uid,
        k8s_namespace: None, // Would need additional lookups
        cgroup_path: path.to_string(),
    })
}

/// Check if a string looks like a container ID (hex, 12-64 chars).
fn is_hex_id(s: &str) -> bool {
    let len = s.len();
    (12..=64).contains(&len) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Read namespace inode for a process.
fn read_ns_inode(pid: u32, ns_type: &str) -> Option<u64> {
    let link = format!("/proc/{}/ns/{}", pid, ns_type);
    let target = fs::read_link(&link).ok()?;
    let target_str = target.to_string_lossy();
    // Format: "ns_type:[inode]"
    let start = target_str.find('[')? + 1;
    let end = target_str.find(']')?;
    target_str[start..end].parse::<u64>().ok()
}

/// Get namespace information for a process.
pub fn get_namespace_info(pid: u32) -> NamespaceInfo {
    let pid_ns = read_ns_inode(pid, "pid");
    let mnt_ns = read_ns_inode(pid, "mnt");
    let net_ns = read_ns_inode(pid, "net");
    let uts_ns = read_ns_inode(pid, "uts");

    let host_pid_ns = get_host_pid_ns();
    let is_host_pid_ns = match (pid_ns, host_pid_ns) {
        (Some(p), Some(h)) => p == h,
        _ => false,
    };

    NamespaceInfo {
        pid_ns,
        mnt_ns,
        net_ns,
        uts_ns,
        is_host_pid_ns,
    }
}

/// Detect if a process has escaped its container namespace.
///
/// A container escape is indicated when:
/// - Process is in a different PID namespace than its parent
/// - Process has access to host PID namespace from within a container cgroup
pub fn detect_container_escape(pid: u32) -> bool {
    // If the process is in a container cgroup but has the host PID namespace,
    // that's a strong indicator of container escape.
    let container = detect_container(pid);
    if container.is_none() {
        return false; // Not in a container, can't escape
    }

    let ns_info = get_namespace_info(pid);
    if ns_info.is_host_pid_ns {
        // Process is in container cgroup but host PID namespace — escape!
        return true;
    }

    // Check if process can see PID 1's children (host namespace access)
    let proc1_ns = read_ns_inode(1, "pid");
    if let (Some(our_ns), Some(host_ns)) = (ns_info.pid_ns, proc1_ns) {
        if our_ns == host_ns {
            return true;
        }
    }

    false
}

/// Build a container label map suitable for telemetry enrichment.
pub fn container_labels(pid: u32) -> HashMap<String, String> {
    let mut labels = HashMap::new();

    match detect_container(pid) {
        Some(ctx) => {
            labels.insert("container_runtime".to_string(), ctx.runtime.as_str().to_string());
            labels.insert("container_id".to_string(), ctx.container_id_short.clone());
            labels.insert("container_id_full".to_string(), ctx.container_id);
            if let Some(pod_uid) = ctx.pod_uid {
                labels.insert("k8s_pod_uid".to_string(), pod_uid);
            }
            if let Some(ns) = ctx.k8s_namespace {
                labels.insert("k8s_namespace".to_string(), ns);
            }
        }
        None => {
            labels.insert("container_runtime".to_string(), "host".to_string());
        }
    }

    labels
}

#[cfg(test)]
mod tests;
