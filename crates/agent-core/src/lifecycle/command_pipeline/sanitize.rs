use anyhow::Result;

pub(super) fn sanitize_profile_id(raw: &str) -> Result<String, &'static str> {
    let profile_id = raw.trim();
    if profile_id.is_empty() {
        return Err("profile_id required");
    }
    if profile_id.len() > 128 {
        return Err("profile_id too long");
    }
    if profile_id.contains("..") {
        return Err("path traversal segments are not allowed");
    }
    if profile_id.contains('/') || profile_id.contains('\\') {
        return Err("path separators are not allowed");
    }
    if !profile_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("profile_id contains unsupported characters");
    }

    Ok(profile_id.to_string())
}

#[cfg(any(test, not(any(target_os = "windows", target_os = "macos"))))]
pub(super) fn sanitize_apt_package_name(raw: &str) -> Result<String, &'static str> {
    let package_name = raw.trim();
    if package_name.is_empty() {
        return Err("package_name required");
    }
    if package_name.len() > 128 {
        return Err("package_name too long");
    }
    if package_name.starts_with('-') {
        return Err("package_name must not start with '-'");
    }
    if !package_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
    {
        return Err("package_name contains unsupported characters");
    }
    Ok(package_name.to_string())
}

#[cfg(any(test, not(any(target_os = "windows", target_os = "macos"))))]
pub(super) fn sanitize_apt_package_version(raw: &str) -> Result<String, &'static str> {
    let version = raw.trim();
    if version.is_empty() {
        return Ok(String::new());
    }
    if version.len() > 128 {
        return Err("version too long");
    }
    if version.starts_with('-') {
        return Err("version must not start with '-'");
    }
    if !version.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b':' | b'~' | b'_')
    }) {
        return Err("version contains unsupported characters");
    }
    Ok(version.to_string())
}

#[cfg(any(test, target_os = "windows"))]
pub(super) fn sanitize_windows_package_name(raw: &str) -> Result<String, &'static str> {
    let package_name = raw.trim();
    if package_name.is_empty() {
        return Err("package_name required");
    }
    if package_name.len() > 128 {
        return Err("package_name too long");
    }
    if package_name.starts_with('-') {
        return Err("package_name must not start with '-'");
    }
    if !package_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("package_name contains unsupported characters");
    }

    Ok(package_name.to_string())
}

#[cfg(any(test, target_os = "windows"))]
pub(super) fn sanitize_windows_package_version(raw: &str) -> Result<String, &'static str> {
    let version = raw.trim();
    if version.is_empty() {
        return Ok(String::new());
    }
    if version.len() > 128 {
        return Err("version too long");
    }
    if version.starts_with('-') {
        return Err("version must not start with '-'");
    }
    if !version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("version contains unsupported characters");
    }

    Ok(version.to_string())
}

#[cfg(any(test, target_os = "macos"))]
pub(super) fn sanitize_macos_package_name(raw: &str) -> Result<String, &'static str> {
    let package_name = raw.trim();
    if package_name.is_empty() {
        return Err("package_name required");
    }
    if package_name.len() > 128 {
        return Err("package_name too long");
    }
    if package_name.starts_with('-') {
        return Err("package_name must not start with '-'");
    }
    if !package_name.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b'@')
    }) {
        return Err("package_name contains unsupported characters");
    }

    Ok(package_name.to_string())
}

#[cfg(any(test, target_os = "macos"))]
pub(super) fn sanitize_macos_package_version(raw: &str) -> Result<String, &'static str> {
    let version = raw.trim();
    if version.is_empty() {
        return Ok(String::new());
    }
    if version.len() > 128 {
        return Err("version too long");
    }
    if version.starts_with('-') {
        return Err("version must not start with '-'");
    }
    if !version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("version contains unsupported characters");
    }

    Ok(version.to_string())
}
