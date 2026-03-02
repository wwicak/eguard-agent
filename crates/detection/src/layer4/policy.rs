const DEFAULT_RANSOMWARE_WINDOW_SECS: i64 = 20;
const DEFAULT_RANSOMWARE_WRITE_THRESHOLD: u32 = 25;

const DEFAULT_RANSOMWARE_USER_PATH_PREFIXES: &[&str] = &[
    "/home/",
    "/users/",
    "/srv/",
    "/var/www/",
    "/mnt/",
    "/media/",
    "/volumes/",
    "\\\\",
];

const DEFAULT_RANSOMWARE_SYSTEM_PATH_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/tmp/",
    "/var/tmp/",
    "/var/run/",
    "/private/tmp/",
    "/private/var/",
    "/etc/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib64/",
    "/usr/",
    "/boot/",
    "/system/",
    "/library/",
    "c:\\windows",
    "c:/windows",
    "c:\\program files",
    "c:/program files",
    "c:\\program files (x86)",
    "c:/program files (x86)",
    "c:\\programdata",
    "c:/programdata",
    "c:\\temp",
    "c:/temp",
];

const DEFAULT_RANSOMWARE_TEMP_PATH_TOKENS: &[&str] = &[
    "/tmp/",
    "/temp/",
    "\\temp\\",
    "\\appdata\\",
    "/appdata/",
    "\\appdata\\local\\temp",
    "/appdata/local/temp",
];

pub(super) fn is_sensitive_credential_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();

    if lower.starts_with("/etc/shadow")
        || lower.starts_with("/etc/gshadow")
        || lower.starts_with("/etc/passwd")
        || lower.starts_with("/etc/sudoers")
        || lower.starts_with("/etc/master.passwd")
    {
        return true;
    }

    if lower.starts_with("/etc/ssh/ssh_host_") {
        return lower.ends_with("_key") && !lower.ends_with("_key.pub");
    }

    if lower.contains("/.ssh/") {
        let name = lower.rsplit('/').next().unwrap_or("");
        if matches!(
            name,
            "id_rsa"
                | "id_dsa"
                | "id_ecdsa"
                | "id_ed25519"
                | "authorized_keys"
                | "authorized_keys2"
        ) {
            return true;
        }
    }

    if lower.contains("/library/keychains")
        || lower.contains("/var/db/dslocal/")
        || lower.contains("/private/var/db/dslocal/")
    {
        return true;
    }

    if lower.contains("/windows/system32/config/sam")
        || lower.contains("/windows/system32/config/security")
        || lower.contains("/windows/system32/config/system")
        || lower.contains("/windows/system32/config/regback/sam")
        || lower.contains("/windows/ntds/ntds.dit")
        || lower.contains("/ntds/ntds.dit")
    {
        return true;
    }

    if lower.contains("credential") {
        return true;
    }

    false
}

#[derive(Debug, Clone)]
pub struct RansomwarePolicy {
    pub write_window_secs: i64,
    pub write_threshold: u32,
    pub adaptive_delta: f64,
    pub adaptive_min_samples: usize,
    pub adaptive_floor: u32,
    pub learned_root_min_hits: u32,
    pub learned_root_max: usize,
    pub user_path_prefixes: Vec<String>,
    pub system_path_prefixes: Vec<String>,
    pub temp_path_tokens: Vec<String>,
}

impl Default for RansomwarePolicy {
    fn default() -> Self {
        Self {
            write_window_secs: DEFAULT_RANSOMWARE_WINDOW_SECS,
            write_threshold: DEFAULT_RANSOMWARE_WRITE_THRESHOLD,
            adaptive_delta: 1e-6,
            adaptive_min_samples: 6,
            adaptive_floor: 5,
            learned_root_min_hits: 3,
            learned_root_max: 64,
            user_path_prefixes: DEFAULT_RANSOMWARE_USER_PATH_PREFIXES
                .iter()
                .map(|v| v.to_string())
                .collect(),
            system_path_prefixes: DEFAULT_RANSOMWARE_SYSTEM_PATH_PREFIXES
                .iter()
                .map(|v| v.to_string())
                .collect(),
            temp_path_tokens: DEFAULT_RANSOMWARE_TEMP_PATH_TOKENS
                .iter()
                .map(|v| v.to_string())
                .collect(),
        }
        .sanitized()
    }
}

impl RansomwarePolicy {
    pub fn sanitized(mut self) -> Self {
        if self.write_window_secs <= 0 {
            self.write_window_secs = DEFAULT_RANSOMWARE_WINDOW_SECS;
        }
        if self.write_threshold == 0 {
            self.write_threshold = DEFAULT_RANSOMWARE_WRITE_THRESHOLD;
        }
        if !(0.0..=1.0).contains(&self.adaptive_delta) {
            self.adaptive_delta = 1e-6;
        }
        if self.adaptive_min_samples == 0 {
            self.adaptive_min_samples = 6;
        }
        if self.adaptive_floor == 0 {
            self.adaptive_floor = 5;
        }
        if self.learned_root_min_hits == 0 {
            self.learned_root_min_hits = 3;
        }
        if self.learned_root_max == 0 {
            self.learned_root_max = 64;
        }
        self.user_path_prefixes = normalize_list(self.user_path_prefixes);
        self.system_path_prefixes = normalize_list(self.system_path_prefixes);
        self.temp_path_tokens = normalize_list(self.temp_path_tokens);
        if self.user_path_prefixes.is_empty() {
            self.user_path_prefixes = DEFAULT_RANSOMWARE_USER_PATH_PREFIXES
                .iter()
                .map(|v| v.to_string())
                .collect();
        }
        if self.system_path_prefixes.is_empty() {
            self.system_path_prefixes = DEFAULT_RANSOMWARE_SYSTEM_PATH_PREFIXES
                .iter()
                .map(|v| v.to_string())
                .collect();
        }
        if self.temp_path_tokens.is_empty() {
            self.temp_path_tokens = DEFAULT_RANSOMWARE_TEMP_PATH_TOKENS
                .iter()
                .map(|v| v.to_string())
                .collect();
        }
        self
    }

    pub(super) fn is_system_or_temp(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        if lower.is_empty() {
            return false;
        }

        if self
            .system_path_prefixes
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        {
            return true;
        }
        if self
            .temp_path_tokens
            .iter()
            .any(|token| lower.contains(token))
        {
            return true;
        }
        false
    }

    pub(super) fn is_candidate_path(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        if lower.is_empty() {
            return false;
        }

        if self.is_system_or_temp(&lower) {
            return false;
        }
        if self
            .user_path_prefixes
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        {
            return true;
        }

        let bytes = lower.as_bytes();
        if bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
            return true;
        }

        false
    }
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = values
        .into_iter()
        .filter_map(|v| {
            let trimmed = v.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_ascii_lowercase())
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

pub(super) fn path_root_prefix(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        let drive = &path[..2];
        let sep = if bytes[2] == b'\\' { '\\' } else { '/' };
        let rest = &path[3..];
        let components: Vec<&str> = rest.split(['/', '\\']).filter(|c| !c.is_empty()).collect();
        if components.is_empty() {
            return Some(format!("{drive}{sep}"));
        }
        let mut root = format!("{drive}{sep}{}", components[0]);
        if components.len() > 1 {
            root.push(sep);
            root.push_str(components[1]);
        }
        root.push(sep);
        return Some(root);
    }

    if let Some(rest) = path.strip_prefix("\\\\") {
        let components: Vec<&str> = rest.split('\\').filter(|c| !c.is_empty()).collect();
        if components.len() >= 2 {
            return Some(format!("\\\\{}\\{}\\", components[0], components[1]));
        }
        return None;
    }

    if path.starts_with('/') {
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        if components.is_empty() {
            return None;
        }
        let mut root = format!("/{}/", components[0]);
        if components.len() > 1 {
            root.push_str(components[1]);
            root.push('/');
        }
        return Some(root);
    }

    None
}
