"""Shared-host URLs and special-use addresses are not host-level threat IOCs."""
import ipaddress
from urllib.parse import urlsplit

# Paths, not these providers' shared hostnames, identify the malicious resource.
SHARED_HOST_SUFFIXES = frozenset({
    "docs.google.com", "drive.google.com", "sites.google.com", "forms.gle",
    "firebasestorage.googleapis.com", "storage.googleapis.com", "pastebin.com",
    "paste.ee", "tinyurl.com", "bit.ly", "dweb.link", "archive.org",
    "github.com", "raw.githubusercontent.com", "gist.githubusercontent.com",
    "discord.com", "discordapp.com", "api.telegram.org", "t.me",
})
SPECIAL_NETWORKS = tuple(map(ipaddress.ip_network, (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/3", "::/128", "::1/128", "::ffff:0:0/96",
    "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
    "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8",
)))


def is_shared_host(host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    if "." not in host:
        return False
    return any(host == suffix or host.endswith("." + suffix) for suffix in SHARED_HOST_SUFFIXES)


def domain_from_url(url: str) -> str | None:
    """Do not collapse shared-platform URLs into a malicious-host assertion."""
    try:
        parsed = urlsplit(url.strip())
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or "." not in host or is_shared_host(host):
            return None
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            return host
    except (ValueError, UnicodeError):
        return None


def is_public_indicator(value: str) -> bool:
    try:
        net = ipaddress.ip_network(value, strict=False)
        return net.is_global and not any(net.version == special.version and net.overlaps(special) for special in SPECIAL_NETWORKS)
    except ValueError:
        return False
