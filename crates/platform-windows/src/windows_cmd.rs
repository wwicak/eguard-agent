//! Canonical Windows system command paths.
//!
//! Using absolute system paths avoids PATH-search hijacking when spawning
//! privileged subprocesses from the agent service.

#[cfg(target_os = "windows")]
pub(crate) const POWERSHELL_EXE: &str =
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
#[cfg(target_os = "windows")]
pub(crate) const NETSH_EXE: &str = r"C:\Windows\System32\netsh.exe";
#[cfg(target_os = "windows")]
pub(crate) const TASKKILL_EXE: &str = r"C:\Windows\System32\taskkill.exe";
#[cfg(target_os = "windows")]
pub(crate) const RUNDLL32_EXE: &str = r"C:\Windows\System32\rundll32.exe";
#[cfg(target_os = "windows")]
pub(crate) const SC_EXE: &str = r"C:\Windows\System32\sc.exe";
#[cfg(target_os = "windows")]
pub(crate) const REG_EXE: &str = r"C:\Windows\System32\reg.exe";
#[cfg(target_os = "windows")]
pub(crate) const ICACLS_EXE: &str = r"C:\Windows\System32\icacls.exe";
#[cfg(target_os = "windows")]
pub(crate) const EVENTCREATE_EXE: &str = r"C:\Windows\System32\eventcreate.exe";
