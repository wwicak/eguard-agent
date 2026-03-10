use anyhow::Result;

use super::types::AgentConfig;

impl AgentConfig {
    pub fn load() -> Result<Self> {
        let mut cfg = Self::default();
        let loaded = match cfg.apply_file_config() {
            Ok(loaded) => loaded,
            Err(err)
                if err
                    .to_string()
                    .contains("configured EGUARD_AGENT_CONFIG does not exist") =>
            {
                if cfg.recover_missing_agent_config()? {
                    cfg.apply_file_config()?
                } else {
                    return Err(err);
                }
            }
            Err(err) => return Err(err),
        };
        if !loaded && cfg.recover_missing_agent_config()? {
            let _ = cfg.apply_file_config()?;
        }
        cfg.apply_bootstrap_config()?;
        cfg.apply_env_overrides();
        Ok(cfg)
    }
}
