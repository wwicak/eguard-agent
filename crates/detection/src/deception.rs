//! Deception Tokens -- Honeypot Canaries
//!
//! Deploy fake credentials, documents, and registry keys that trigger
//! instant Definite-confidence alerts when accessed by an attacker.
//! Zero false positive rate by construction -- no legitimate software
//! should ever access these canary files.

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
    /// Always `"definite"` -- guaranteed true positive.
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
                    confidence: "definite",
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

/// Pre-configured canary tokens that cover common attacker targets.
pub fn default_tokens() -> Vec<DeceptionToken> {
    vec![
        DeceptionToken {
            name: "ssh_canary".into(),
            token_type: TokenType::CredentialFile,
            path: "/root/.ssh/id_rsa_backup".into(),
            deployed: true,
            triggered_count: 0,
        },
        DeceptionToken {
            name: "aws_canary".into(),
            token_type: TokenType::CredentialFile,
            path: "/opt/.aws/credentials".into(),
            deployed: true,
            triggered_count: 0,
        },
        DeceptionToken {
            name: "password_canary".into(),
            token_type: TokenType::DocumentFile,
            path: "/usr/local/share/.passwords.csv".into(),
            deployed: true,
            triggered_count: 0,
        },
        DeceptionToken {
            name: "db_canary".into(),
            token_type: TokenType::ConfigFile,
            path: "/etc/eguard-agent/.db_credentials.conf".into(),
            deployed: true,
            triggered_count: 0,
        },
        DeceptionToken {
            name: "backup_key_canary".into(),
            token_type: TokenType::CredentialFile,
            path: "/var/backups/.encryption_key".into(),
            deployed: true,
            triggered_count: 0,
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_to_canary_triggers_alert() {
        let mut engine = DeceptionEngine::new();
        let alert = engine.check_file_access("/root/.ssh/id_rsa_backup", "evil_proc", 1234);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.token_name, "ssh_canary");
        assert_eq!(alert.confidence, "definite");
        assert_eq!(alert.accessing_process, "evil_proc");
        assert_eq!(alert.accessing_pid, 1234);
    }

    #[test]
    fn access_to_normal_path_returns_none() {
        let mut engine = DeceptionEngine::new();
        let alert = engine.check_file_access("/etc/passwd", "sshd", 500);
        assert!(alert.is_none());
    }

    #[test]
    fn multiple_accesses_increment_trigger_count() {
        let mut engine = DeceptionEngine::new();
        engine.check_file_access("/opt/.aws/credentials", "proc_a", 100);
        engine.check_file_access("/opt/.aws/credentials", "proc_b", 200);
        engine.check_file_access("/opt/.aws/credentials", "proc_c", 300);

        let aws_token = engine
            .tokens
            .iter()
            .find(|t| t.name == "aws_canary")
            .unwrap();
        assert_eq!(aws_token.triggered_count, 3);
    }

    #[test]
    fn custom_token_addition_works() {
        let mut engine = DeceptionEngine::new();
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
    fn default_tokens_cover_all_types() {
        let tokens = default_tokens();
        let types: Vec<_> = tokens.iter().map(|t| &t.token_type).collect();
        assert!(types.contains(&&TokenType::CredentialFile));
        assert!(types.contains(&&TokenType::DocumentFile));
        assert!(types.contains(&&TokenType::ConfigFile));
    }

    #[test]
    fn stats_reflect_state() {
        let mut engine = DeceptionEngine::new();
        let (deployed, triggers) = engine.stats();
        assert_eq!(deployed, 5); // all 5 defaults are deployed
        assert_eq!(triggers, 0);

        engine.check_file_access("/root/.ssh/id_rsa_backup", "x", 1);
        engine.check_file_access("/root/.ssh/id_rsa_backup", "y", 2);
        let (_, triggers) = engine.stats();
        assert_eq!(triggers, 2);
    }

    #[test]
    fn undeployed_token_does_not_trigger() {
        let mut engine = DeceptionEngine::new();
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
        let mut engine = DeceptionEngine::new();
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
