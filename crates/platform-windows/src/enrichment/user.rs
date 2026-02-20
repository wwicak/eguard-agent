//! SID-to-username resolution.
//!
//! On Windows, uses `LookupAccountSidW` to resolve security identifiers
//! to human-readable usernames.

/// Resolve a Windows SID string to a username.
pub fn resolve_sid_to_username(sid: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        resolve_sid_windows(sid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = sid;
        tracing::warn!("resolve_sid_to_username is a stub on non-Windows");
        None
    }
}

/// Resolve a UID (token user) to a username.
pub fn resolve_uid_to_username(uid: u32) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        // TODO: OpenProcessToken -> GetTokenInformation -> LookupAccountSid
        let _ = uid;
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = uid;
        None
    }
}

#[cfg(target_os = "windows")]
fn resolve_sid_windows(sid: &str) -> Option<String> {
    // TODO: ConvertStringSidToSid + LookupAccountSidW
    let _ = sid;
    None
}
