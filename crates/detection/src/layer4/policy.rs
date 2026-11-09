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
        || lower.contains("/.aws/credentials")
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

    false
}

pub(crate) fn is_credential_source(path: &str) -> bool {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    if lower.ends_with(".pub") || matches!(name, "authorized_keys" | "authorized_keys2") {
        return false;
    }
    // Reuse the graph's credential-source policy, without treating public keys as secrets.
    is_sensitive_credential_path(&lower)
        || [
            "/.kube/config",
            "/.config/gcloud/credentials.db",
            "/application_default_credentials.json",
            "/.azure/accesstokens.json",
            "/.azure/msal_token_cache.json",
            "/login data",
            "/logins.json",
            "/key4.db",
            "/signons.sqlite",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
}

pub(super) fn is_expected_auth_stack_access(process: &str, path: &str) -> bool {
    let process = process_basename(process).to_ascii_lowercase();
    if !matches!(
        process.as_str(),
        "sudo"
            | "sudoedit"
            | "su"
            | "login"
            | "sshd"
            | "sshd-session"
            | "unix_chkpwd"
            | "chkpwd"
            | "passwd"
            | "chage"
            | "chfn"
            | "chsh"
            | "newusers"
            | "useradd"
            | "usermod"
            | "userdel"
            | "groupadd"
            | "groupmod"
            | "groupdel"
            | "polkitd"
            | "gdm-password"
            | "gdm-session-worker"
            | "systemd-homed"
            | "sssd"
            | "winbindd"
            | "opendirectoryd"
            | "mdmclient"
            | "profiles"
            | "mbsetupuser"
            | "securityd"
            | "configd"
            | "dscl"
            | "dseditgroup"
            | "sysadminctl"
            | "dsimport"
            | "system_installd"
            | "installd"
    ) {
        return false;
    }

    let lower = path.replace('\\', "/").to_ascii_lowercase();
    lower.starts_with("/etc/shadow")
        || lower.starts_with("/etc/gshadow")
        || lower.starts_with("/etc/master.passwd")
        || lower.starts_with("/etc/ssh/ssh_host_")
        || lower.contains("/var/db/dslocal/")
        || lower.contains("/private/var/db/dslocal/")
        || lower.contains("/windows/system32/config/sam")
        || lower.contains("/windows/system32/config/security")
        || lower.contains("/windows/system32/config/system")
}

fn process_basename(process: &str) -> &str {
    process.rsplit(['/', '\\']).next().unwrap_or(process).trim()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_systemprofile_is_not_credential_source(path: &str) {
        let nt_path = path.replacen("C:", r"\Device\HarddiskVolume3", 1);
        for path in [path.to_string(), nt_path] {
            for variant in [
                path.clone(),
                path.to_ascii_lowercase(),
                path.to_ascii_uppercase(),
            ] {
                assert!(!is_sensitive_credential_path(&variant), "{variant}");
                assert!(!is_credential_source(&variant), "{variant}");
            }
        }
    }

    #[test]
    fn agentfix28_cryptnet_systemprofile_is_not_credential_source() {
        assert_systemprofile_is_not_credential_source(
            r"C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\26C212D9399727259664BDFCA073966E_912C3CA51DE6018A7BE4CA7BC64AAFCD",
        );
    }

    #[test]
    fn agentfix28_office_systemprofile_is_not_credential_source() {
        assert_systemprofile_is_not_credential_source(
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Office\OTele\{BD5D4451-383D-47AE-8C81-6F717964EE12} (4) - 4720 - officeclicktorun.exe - OTele.dat",
        );
    }

    #[test]
    fn agentfix28_hive_files_and_known_siblings_remain_credential_sources() {
        for root in [
            r"C:\Windows\System32\config",
            r"\Device\HarddiskVolume3\Windows\System32\config",
        ] {
            for hive in ["SAM", "SECURITY", "SYSTEM", r"RegBack\SAM"] {
                for suffix in ["", ".LOG", ".LOG1", ".LOG2", ".sav", ".alt"] {
                    let path = format!(r"{root}\{hive}{suffix}");
                    for variant in [
                        path.clone(),
                        path.to_ascii_lowercase(),
                        path.replace('\\', "/"),
                    ] {
                        assert!(is_sensitive_credential_path(&variant), "{variant}");
                        assert!(is_credential_source(&variant), "{variant}");
                    }
                }
            }
        }
    }

    #[test]
    fn agentfix28_hive_prefix_lookalikes_are_not_credential_sources() {
        for name in [
            "samurai",
            "securitytools",
            "systemprofile",
            r"RegBack\samples",
            "SAM.LOG10",
            "SYSTEM.savx",
            "SECURITY.txt",
            r"SAM\child",
        ] {
            let path = format!(r"C:\Windows\System32\config\{name}");
            assert!(!is_sensitive_credential_path(&path), "{path}");
            assert!(!is_credential_source(&path), "{path}");
        }
    }

    #[test]
    fn expected_auth_stack_allows_macos_directory_services_access() {
        assert!(is_expected_auth_stack_access(
            "opendirectoryd",
            "/var/db/dslocal/nodes/Default/users/root.plist"
        ));
        assert!(is_expected_auth_stack_access(
            "/usr/libexec/opendirectoryd",
            "/private/var/db/dslocal/nodes/Default/groups/admin.plist"
        ));
        assert!(!is_expected_auth_stack_access("evil_dumper", "/etc/shadow"));
    }
}
