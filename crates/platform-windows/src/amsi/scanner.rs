//! AMSI content scanning pipeline.

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
        #[cfg(target_os = "windows")]
        {
            // TODO: AmsiInitialize
            Ok(Self { context_handle: 0 })
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!("AmsiScanner::new is a stub on non-Windows");
            Ok(Self { context_handle: 0 })
        }
    }

    /// Scan a buffer of content and return the verdict.
    pub fn scan_buffer(&self, content: &[u8], content_name: &str) -> Result<AmsiResult, super::AmsiError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: AmsiScanBuffer(self.context_handle, content, content_name, ...)
            let _ = (content, content_name);
            Ok(AmsiResult::NotDetected)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (self.context_handle, content, content_name);
            tracing::warn!("AmsiScanner::scan_buffer is a stub on non-Windows");
            Ok(AmsiResult::NotDetected)
        }
    }

    /// Scan a string and return the verdict.
    pub fn scan_string(&self, content: &str, content_name: &str) -> Result<AmsiResult, super::AmsiError> {
        self.scan_buffer(content.as_bytes(), content_name)
    }
}

impl Default for AmsiScanner {
    fn default() -> Self {
        Self { context_handle: 0 }
    }
}
