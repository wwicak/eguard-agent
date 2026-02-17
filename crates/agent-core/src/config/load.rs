use anyhow::Result;

use super::types::AgentConfig;

impl AgentConfig {
    pub fn load() -> Result<Self> {
        let mut cfg = Self::default();
        cfg.apply_file_config()?;
        cfg.apply_bootstrap_config()?;
        cfg.apply_env_overrides();
        Ok(cfg)
    }
}
