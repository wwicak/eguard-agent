use super::Adapter;
use std::{collections::HashMap, ffi::CStr, fs, path::Path};

pub fn physical(root: &Path, name: &str, depth: usize) -> bool {
    if depth > 8 || super::virtual_name(name) {
        return false;
    }
    let path = root.join(name);
    if path.join("device").exists() {
        return true;
    }
    let uevent = fs::read_to_string(path.join("uevent")).unwrap_or_default();
    if !path.join("bonding").exists()
        && !uevent.contains("DEVTYPE=vlan")
        && !uevent.contains("DEVTYPE=team")
    {
        return false;
    }
    // lower_* links are the kernel's topology evidence for stacked NICs.
    fs::read_dir(path).into_iter().flatten().flatten().any(|e| {
        e.file_name().to_string_lossy().starts_with("lower_")
            && fs::canonicalize(e.path())
                .ok()
                .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
                .is_some_and(|n| physical(root, &n, depth + 1))
    })
}

pub fn default_routes(v4: &str, v6: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in v4.lines().skip(1) {
        let p: Vec<_> = line.split_whitespace().collect();
        if p.len() > 7
            && p[1] == "00000000"
            && p[7] == "00000000"
            && u32::from_str_radix(p[3], 16).is_ok_and(|flags| flags & 1 != 0)
        {
            names.push(p[0].into());
        }
    }
    for line in v6.lines() {
        let p: Vec<_> = line.split_whitespace().collect();
        if p.len() >= 10
            && p[0] == "00000000000000000000000000000000"
            && p[1] == "00"
            && u32::from_str_radix(p[8], 16).is_ok_and(|flags| flags & 1 != 0 && flags & 0x200 == 0)
        {
            names.push(p[9].into());
        }
    }
    names
}

fn addresses() -> HashMap<String, Vec<String>> {
    let mut result: HashMap<String, Vec<String>> = HashMap::new();
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return result;
    }
    let mut ptr = head;
    while !ptr.is_null() {
        let a = unsafe { &*ptr };
        ptr = a.ifa_next;
        if a.ifa_name.is_null() || a.ifa_addr.is_null() {
            continue;
        }
        let ip = unsafe {
            match (*a.ifa_addr).sa_family as i32 {
                libc::AF_INET => {
                    let s = &*(a.ifa_addr as *const libc::sockaddr_in);
                    Some(std::net::Ipv4Addr::from(s.sin_addr.s_addr.to_ne_bytes()).to_string())
                }
                libc::AF_INET6 => {
                    let s = &*(a.ifa_addr as *const libc::sockaddr_in6);
                    Some(std::net::Ipv6Addr::from(s.sin6_addr.s6_addr).to_string())
                }
                _ => None,
            }
        };
        if let Some(ip) = ip {
            let name = unsafe { CStr::from_ptr(a.ifa_name) }
                .to_string_lossy()
                .into_owned();
            result.entry(name).or_default().push(ip);
        }
    }
    unsafe { libc::freeifaddrs(head) };
    result
}

pub fn snapshot() -> Vec<Adapter> {
    let root = Path::new("/sys/class/net");
    let routes = default_routes(
        &fs::read_to_string("/proc/net/route").unwrap_or_default(),
        &fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default(),
    );
    let mut ips = addresses();
    let mut out: Vec<_> = fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            Adapter {
                mac: fs::read_to_string(e.path().join("address"))
                    .unwrap_or_default()
                    .trim()
                    .into(),
                addresses: ips.remove(&name).unwrap_or_default(),
                default_route: routes.contains(&name),
                physical: physical(root, &name, 0),
                name,
            }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn topology() {
        let root = std::env::temp_dir().join(format!(
            "eguard-adapter-topology-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for n in [
            "eth0/device",
            "wlan0/device",
            "docker0",
            "veth0/device",
            "bond0/bonding",
            "eth0.10",
            "mystery",
        ] {
            fs::create_dir_all(root.join(n)).unwrap();
        }
        fs::write(root.join("eth0.10/uevent"), "DEVTYPE=vlan\n").unwrap();
        for n in ["bond0", "eth0.10", "mystery"] {
            std::os::unix::fs::symlink(root.join("eth0"), root.join(n).join("lower_eth0")).unwrap();
        }
        for n in ["eth0", "wlan0", "bond0", "eth0.10"] {
            assert!(physical(&root, n, 0), "{n}");
        }
        for n in ["docker0", "veth0", "mystery"] {
            assert!(!physical(&root, n, 0), "{n}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn routes() {
        assert_eq!(default_routes("Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 010200C0 0003 0 0 100 00000000", ""),vec!["eth0"]);
    }
}
