//! Deception Tokens -- Honeypot Canaries
//!
//! Only explicitly provisioned canaries are monitored. Ordinary user credential
//! paths and backup/indexing reads are not guaranteed attack evidence.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The kind of bait placed on the endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    /// Fake SSH keys, AWS credentials, `.env` files.
    CredentialFile,
    /// Fake sensitive documents (`passwords.xlsx`, etc.).
    DocumentFile,
    /// Fake database configs with honeypot connection strings.
    ConfigFile,
    /// Windows registry canary (not applicable on Linux).
    RegistryKey,
}

/// A single deployed canary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionToken {
    pub name: String,
    pub token_type: TokenType,
    /// File path or registry key being monitored.
    pub path: String,
    pub deployed: bool,
    pub triggered_count: u64,
}

/// Alert emitted when a canary is accessed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionAlert {
    pub token_name: String,
    pub token_type: TokenType,
    pub path: String,
    pub accessing_process: String,
    pub accessing_pid: u32,
    /// Reader-aware alert confidence; never autonomous response evidence.
    pub confidence: &'static str,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Manages a set of [`DeceptionToken`]s and checks file accesses against them.
pub struct DeceptionEngine {
    tokens: Vec<DeceptionToken>,
}

impl DeceptionEngine {
    /// Create an engine pre-loaded with [`default_tokens`].
    pub fn new() -> Self {
        Self {
            tokens: default_tokens(),
        }
    }

    /// Check whether `file_path` matches any deployed canary.
    ///
    /// Returns a [`DeceptionAlert`] on match and increments the trigger count.
    pub fn check_file_access(
        &mut self,
        file_path: &str,
        process_name: &str,
        pid: u32,
    ) -> Option<DeceptionAlert> {
        for token in &mut self.tokens {
            if !token.deployed {
                continue;
            }
            if file_path == token.path {
                token.triggered_count += 1;
                return Some(DeceptionAlert {
                    token_name: token.name.clone(),
                    token_type: token.token_type.clone(),
                    path: token.path.clone(),
                    accessing_process: process_name.to_owned(),
                    accessing_pid: pid,
                    confidence: if matches!(
                        crate::behavioral::basename(process_name).as_str(),
                        "msmpeng"
                            | "searchprotocolhost"
                            | "searchindexer"
                            | "clamd"
                            | "mds"
                            | "mdworker"
                            | "tracker-miner-fs"
                            | "tar"
                            | "rsync"
                            | "backup"
                    ) {
                        "low"
                    } else {
                        "high"
                    },
                });
            }
        }
        None
    }

    /// Return all monitored paths (useful for eBPF watch lists).
    pub fn token_paths(&self) -> Vec<&str> {
        self.tokens
            .iter()
            .filter(|t| t.deployed)
            .map(|t| t.path.as_str())
            .collect()
    }

    /// Register an additional canary at runtime.
    pub fn add_token(&mut self, token: DeceptionToken) {
        self.tokens.push(token);
    }

    /// `(deployed_count, total_triggers)` across all tokens.
    pub fn stats(&self) -> (usize, u64) {
        let deployed = self.tokens.iter().filter(|t| t.deployed).count();
        let triggers: u64 = self.tokens.iter().map(|t| t.triggered_count).sum();
        (deployed, triggers)
    }
}

impl Default for DeceptionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// No token is deployed merely by starting the detector. Enrollment must first
/// provision agent-owned decoys and then register their identities explicitly.
pub fn default_tokens() -> Vec<DeceptionToken> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_engine() -> DeceptionEngine {
        let mut engine = DeceptionEngine::new();
        for (name, path) in [
            ("ssh_canary", first_token_path()),
            ("aws_canary", second_token_path()),
        ] {
            engine.add_token(DeceptionToken {
                name: name.into(),
                token_type: TokenType::CredentialFile,
                path,
                deployed: true,
                triggered_count: 0,
            });
        }
        engine
    }
    fn first_token_path() -> String {
        "/var/lib/eguard-agent/decoy/synthetic-ssh".into()
    }
    fn second_token_path() -> String {
        "/var/lib/eguard-agent/decoy/synthetic-aws".into()
    }

    #[test]
    fn access_to_canary_triggers_alert() {
        let mut engine = fixture_engine();
        let path = first_token_path();
        let alert = engine.check_file_access(&path, "evil_proc", 1234);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.token_name, "ssh_canary");
        assert_eq!(alert.confidence, "high");
        assert_eq!(alert.accessing_process, "evil_proc");
        assert_eq!(alert.accessing_pid, 1234);
    }

    #[test]
    fn access_to_normal_path_returns_none() {
        let mut engine = fixture_engine();
        let alert = engine.check_file_access("/nonexistent/safe/path", "sshd", 500);
        assert!(alert.is_none());
    }

    #[test]
    fn multiple_accesses_increment_trigger_count() {
        let mut engine = fixture_engine();
        let path = second_token_path();
        engine.check_file_access(&path, "proc_a", 100);
        engine.check_file_access(&path, "proc_b", 200);
        engine.check_file_access(&path, "proc_c", 300);

        let aws_token = engine
            .tokens
            .iter()
            .find(|t| t.name == "aws_canary")
            .unwrap();
        assert_eq!(aws_token.triggered_count, 3);
    }

    #[test]
    fn custom_token_addition_works() {
        let mut engine = fixture_engine();
        let initial_count = engine.token_paths().len();

        engine.add_token(DeceptionToken {
            name: "custom_canary".into(),
            token_type: TokenType::RegistryKey,
            path: "/tmp/.secret_key".into(),
            deployed: true,
            triggered_count: 0,
        });

        assert_eq!(engine.token_paths().len(), initial_count + 1);

        let alert = engine.check_file_access("/tmp/.secret_key", "attacker", 9999);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().token_name, "custom_canary");
    }

    #[test]
    fn default_tokens_do_not_claim_deployment() {
        assert!(default_tokens().is_empty());
    }

    #[test]
    fn stats_reflect_state() {
        let mut engine = fixture_engine();
        let (deployed, triggers) = engine.stats();
        assert_eq!(deployed, 2);
        assert_eq!(triggers, 0);

        let path = first_token_path();
        engine.check_file_access(&path, "x", 1);
        engine.check_file_access(&path, "y", 2);
        let (_, triggers) = engine.stats();
        assert_eq!(triggers, 2);
    }

    #[test]
    fn undeployed_token_does_not_trigger() {
        let mut engine = fixture_engine();
        engine.add_token(DeceptionToken {
            name: "disabled_canary".into(),
            token_type: TokenType::DocumentFile,
            path: "/tmp/.disabled".into(),
            deployed: false,
            triggered_count: 0,
        });
        let alert = engine.check_file_access("/tmp/.disabled", "proc", 1);
        assert!(alert.is_none());
    }

    #[test]
    fn token_paths_excludes_undeployed() {
        let mut engine = fixture_engine();
        let before = engine.token_paths().len();
        engine.add_token(DeceptionToken {
            name: "off".into(),
            token_type: TokenType::ConfigFile,
            path: "/tmp/.off".into(),
            deployed: false,
            triggered_count: 0,
        });
        assert_eq!(engine.token_paths().len(), before);
    }
}
