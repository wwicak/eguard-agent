use super::super::command_utils::extract_server_host;
use super::super::payloads::UpdatePayload;

const UPDATE_BASE_URL_ENV: &str = "EGUARD_AGENT_UPDATE_BASE_URL";
const UPDATE_DEFAULT_HTTPS_PORT_ENV: &str = "EGUARD_AGENT_UPDATE_HTTPS_PORT";
const UPDATE_ALLOW_HTTP_ENV: &str = "EGUARD_AGENT_UPDATE_ALLOW_HTTP";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpdatePackageKind {
    LinuxDeb,
    LinuxRpm,
    WindowsExe,
    WindowsMsi,
    MacosPkg,
}

impl UpdatePackageKind {
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    pub(super) fn as_linux_format(self) -> Option<&'static str> {
        match self {
            Self::LinuxDeb => Some("deb"),
            Self::LinuxRpm => Some("rpm"),
            _ => None,
        }
    }

    #[cfg(target_os = "windows")]
    pub(super) fn as_windows_kind(self) -> Option<&'static str> {
        match self {
            Self::WindowsExe => Some("exe"),
            Self::WindowsMsi => Some("msi"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct NormalizedUpdateRequest {
    version: String,
    package_url: String,
    checksum_sha256: String,
    package_kind: UpdatePackageKind,
}

impl NormalizedUpdateRequest {
    pub(super) fn version(&self) -> &str {
        &self.version
    }

    pub(super) fn package_url(&self) -> &str {
        &self.package_url
    }

    pub(super) fn checksum_sha256(&self) -> &str {
        &self.checksum_sha256
    }

    pub(super) fn package_kind(&self) -> UpdatePackageKind {
        self.package_kind
    }
}

pub(super) fn normalize_update_request(
    payload: UpdatePayload,
    server_addr: &str,
) -> Result<NormalizedUpdateRequest, String> {
    let version = payload.version.trim().to_string();
    if !is_safe_version_string(&version) {
        return Err("version is required and must be a safe token".to_string());
    }

    let checksum_sha256 = normalize_sha256_checksum(&payload.checksum_sha256)?;
    let package_url = resolve_update_url(payload.package_url.trim(), server_addr)?;

    let hinted_kind = parse_package_kind_hint(payload.package_format.trim())?;
    let url_kind = infer_package_kind_from_url(&package_url);
    if let (Some(hinted), Some(inferred)) = (hinted_kind, url_kind) {
        if hinted != inferred {
            return Err("package_format does not match package_url extension".to_string());
        }
    }

    let package_kind = hinted_kind
        .or(url_kind)
        .unwrap_or_else(default_package_kind_for_target);
    enforce_package_kind_for_target(package_kind)?;

    Ok(NormalizedUpdateRequest {
        version,
        package_url,
        checksum_sha256,
        package_kind,
    })
}

fn is_safe_version_string(raw: &str) -> bool {
    if raw.is_empty() || raw.len() > 64 {
        return false;
    }
    raw.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '+'))
}

fn normalize_sha256_checksum(raw: &str) -> Result<String, String> {
    let checksum = raw.trim().to_ascii_lowercase();
    if checksum.is_empty() {
        return Err("checksum_sha256 is required".to_string());
    }
    if checksum.len() != 64 || !checksum.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("checksum_sha256 must be a 64-char hex digest".to_string());
    }
    Ok(checksum)
}

fn resolve_update_url(raw_url: &str, server_addr: &str) -> Result<String, String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err("package_url is required".to_string());
    }

    if trimmed.starts_with("https://") {
        return Ok(trimmed.to_string());
    }

    if trimmed.starts_with("http://") {
        let allow_http = std::env::var(UPDATE_ALLOW_HTTP_ENV)
            .ok()
            .map(|value| {
                value == "1"
                    || value.eq_ignore_ascii_case("true")
                    || value.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        if !allow_http {
            return Err(format!(
                "http package_url is blocked; set {}=1 to allow",
                UPDATE_ALLOW_HTTP_ENV
            ));
        }
        return Ok(trimmed.to_string());
    }

    if !trimmed.starts_with('/') {
        return Err("package_url must be absolute (https://...) or /api-relative".to_string());
    }

    let base = resolve_update_base_url(server_addr)?;
    Ok(format!("{}{}", base.trim_end_matches('/'), trimmed))
}

fn resolve_update_base_url(server_addr: &str) -> Result<String, String> {
    if let Ok(raw) = std::env::var(UPDATE_BASE_URL_ENV) {
        let value = raw.trim();
        if value.starts_with("https://") || value.starts_with("http://") {
            return Ok(value.trim_end_matches('/').to_string());
        }
        if !value.is_empty() {
            return Err(format!("{} must include http(s)://", UPDATE_BASE_URL_ENV));
        }
    }

    let host = extract_server_host(server_addr);
    if host.trim().is_empty() {
        return Err("unable to derive update host from server_addr".to_string());
    }

    let host_token = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host
    };

    let port = std::env::var(UPDATE_DEFAULT_HTTPS_PORT_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1443".to_string());

    Ok(format!("https://{}:{}", host_token, port))
}

fn parse_package_kind_hint(raw: &str) -> Result<Option<UpdatePackageKind>, String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(None);
    }

    match normalized.as_str() {
        "deb" => Ok(Some(UpdatePackageKind::LinuxDeb)),
        "rpm" => Ok(Some(UpdatePackageKind::LinuxRpm)),
        "exe" => Ok(Some(UpdatePackageKind::WindowsExe)),
        "msi" => Ok(Some(UpdatePackageKind::WindowsMsi)),
        "pkg" => Ok(Some(UpdatePackageKind::MacosPkg)),
        _ => Err("unsupported package_format".to_string()),
    }
}

fn infer_package_kind_from_url(url: &str) -> Option<UpdatePackageKind> {
    let lower = url
        .split('?')
        .next()
        .unwrap_or(url)
        .trim()
        .to_ascii_lowercase();

    if lower.ends_with(".deb") {
        Some(UpdatePackageKind::LinuxDeb)
    } else if lower.ends_with(".rpm") {
        Some(UpdatePackageKind::LinuxRpm)
    } else if lower.ends_with(".exe") {
        Some(UpdatePackageKind::WindowsExe)
    } else if lower.ends_with(".msi") {
        Some(UpdatePackageKind::WindowsMsi)
    } else if lower.ends_with(".pkg") {
        Some(UpdatePackageKind::MacosPkg)
    } else {
        None
    }
}

fn default_package_kind_for_target() -> UpdatePackageKind {
    #[cfg(target_os = "windows")]
    {
        return UpdatePackageKind::WindowsExe;
    }
    #[cfg(target_os = "macos")]
    {
        return UpdatePackageKind::MacosPkg;
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        UpdatePackageKind::LinuxDeb
    }
}

fn enforce_package_kind_for_target(kind: UpdatePackageKind) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        if !matches!(
            kind,
            UpdatePackageKind::WindowsExe | UpdatePackageKind::WindowsMsi
        ) {
            return Err("windows agent accepts only .exe or .msi updates".to_string());
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        if kind != UpdatePackageKind::MacosPkg {
            return Err("macOS agent accepts only .pkg updates".to_string());
        }
        return Ok(());
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if !matches!(
            kind,
            UpdatePackageKind::LinuxDeb | UpdatePackageKind::LinuxRpm
        ) {
            return Err("linux agent accepts only .deb or .rpm updates".to_string());
        }
    }

    Ok(())
}
