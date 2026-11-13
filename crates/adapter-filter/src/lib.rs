use std::net::IpAddr;

pub fn normalize_mac(raw: &str) -> Option<String> {
    let raw = raw.replace('-', ":");
    let parts: Vec<_> = raw.split(':').collect();
    if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
        return None;
    }
    let bytes: Vec<u8> = parts
        .iter()
        .map(|p| u8::from_str_radix(p, 16))
        .collect::<Result<_, _>>()
        .ok()?;
    if bytes[0] & 1 != 0 || bytes.iter().all(|b| *b == 0) {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

pub fn virtual_name(name: &str) -> bool {
    virtual_name_for_os(std::env::consts::OS, name)
}

pub fn virtual_name_for_os(os: &str, name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let prefixes: &[&str] = match os {
        "darwin" | "macos" => &[
            "lo", "awdl", "llw", "utun", "bridge", "p2p", "anpi", "ap", "stf", "gif", "vmenet",
            "feth", "ipsec", "ppp",
        ],
        "linux" => &[
            "lo",
            "veth",
            "docker",
            "br-",
            "virbr",
            "vnet",
            "tun",
            "tap",
            "tailscale",
            "wg",
            "zt",
            "flannel",
            "cni",
            "cali",
            "kube",
            "vxlan",
            "genev",
            "dummy",
            "ifb",
            "sit",
            "ip6tnl",
            "gre",
        ],
        _ => &[],
    };
    let terms = [
        "ibridge",
        "hyper-v",
        "vethernet",
        "vmware",
        "virtualbox",
        "vbox",
        "wsl",
        "tailscale",
        "wireguard",
        "tap-",
        "tap-windows",
        "wintun",
        "openvpn",
        "npcap loopback",
        "bluetooth pan",
        "personal area network",
        "microsoft wi-fi direct virtual",
        "kernel debug",
        "wan miniport",
        "teredo",
        "isatap",
        "loopback",
        "tunnel",
    ];
    prefixes.iter().any(|p| n.starts_with(p)) || terms.iter().any(|p| n.contains(p))
}

pub fn usable_ip(raw: &str) -> bool {
    let Ok(ip) = raw
        .split('/')
        .next()
        .unwrap_or("")
        .split('%')
        .next()
        .unwrap_or("")
        .parse::<IpAddr>()
    else {
        return false;
    };
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(v) => !v.is_link_local(),
            IpAddr::V6(v) => (v.segments()[0] & 0xffc0) != 0xfe80,
        }
}

#[derive(Clone, Debug, Default)]
pub struct Adapter {
    pub name: String,
    pub mac: String,
    pub addresses: Vec<String>,
    pub default_route: bool,
    pub physical: bool,
}

pub fn relevant(adapters: Vec<Adapter>) -> Vec<Adapter> {
    relevant_for_os(std::env::consts::OS, adapters)
}

pub fn relevant_for_os(os: &str, adapters: Vec<Adapter>) -> Vec<Adapter> {
    let mut out: Vec<Adapter> = Vec::new();
    for mut a in adapters {
        let Some(mac) = normalize_mac(&a.mac) else {
            continue;
        };
        if !a.physical || virtual_name_for_os(os, &a.name) || mac == "ac:de:48:00:11:22" {
            continue;
        }
        a.mac = mac;
        if !a.default_route && !a.addresses.iter().any(|ip| usable_ip(ip)) {
            continue;
        }
        if let Some(i) = out.iter().position(|old| old.mac == a.mac) {
            if a.default_route && !out[i].default_route {
                out[i] = a;
            }
        } else {
            out.push(a);
        }
    }
    out.sort_by_key(|a| !a.default_route);
    out
}

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bssb_and_cross_platform() {
        let names = [
            "en0", "en7", "en8", "bridge0", "awdl0", "llw0", "anpi0", "ap1", "vmenet0",
        ];
        let macs = [
            "14:7d:da:a4:0c:f4",
            "00:e0:99:00:1e:fd",
            "ac:de:48:00:11:22",
            "82:b9:7b:08:64:00",
            "82:b9:7b:08:64:01",
            "82:b9:7b:08:64:04",
            "82:b9:7b:08:64:05",
            "ba:9f:a7:e7:62:ae",
            "c2:dd:9a:ca:c8:3d",
        ];
        let input = names
            .iter()
            .zip(macs)
            .map(|(n, m)| Adapter {
                name: n.to_string(),
                mac: m.into(),
                physical: true,
                addresses: vec!["192.0.2.1".into()],
                ..Default::default()
            })
            .collect();
        assert_eq!(relevant_for_os("macos", input).len(), 2);
        for n in [
            "docker0",
            "veth12",
            "tailscale0",
            "wg0",
            "Hyper-V NIC",
            "vEthernet (WSL)",
            "VMware",
            "VirtualBox",
            "Bluetooth Device (Personal Area Network)",
        ] {
            assert!(virtual_name(n), "{n}");
        }
        assert!(!virtual_name_for_os(
            "windows",
            "Apple USB Ethernet Adapter"
        ));
        assert!(!virtual_name("eth0"));
        assert!(!virtual_name("wlan0"));
    }
    #[test]
    fn validation_and_default_dedup() {
        for m in [
            "00:00:00:00:00:00",
            "01:00:5e:00:00:01",
            "bad",
            "ff:ff:ff:ff:ff:ff",
        ] {
            assert!(normalize_mac(m).is_none());
        }
        assert!(normalize_mac("82:b9:7b:08:64:00").is_some());
        for ip in ["fe80::1", "169.254.1.1", "::", "127.0.0.1"] {
            assert!(!usable_ip(ip));
        }
        let a = Adapter {
            name: "eth0".into(),
            mac: "00:e0:99:00:1e:fd".into(),
            physical: true,
            addresses: vec!["192.0.2.1".into()],
            ..Default::default()
        };
        let mut b = a.clone();
        b.name = "bond0".into();
        b.addresses.clear();
        b.default_route = true;
        let out = relevant(vec![a, b]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "bond0");
    }
}
