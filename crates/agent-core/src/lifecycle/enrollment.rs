use tracing::warn;

use grpc_client::EnrollmentEnvelope;

use super::AgentRuntime;

impl AgentRuntime {
    pub(super) async fn ensure_enrolled(&mut self) {
        if self.enrolled {
            return;
        }

        let enroll = self.build_enrollment_envelope();
        if let Err(err) = self.client.enroll(&enroll).await {
            warn!(error = %err, "enrollment failed");
            return;
        }

        self.enrolled = true;
        self.consume_bootstrap_config();
    }

    fn build_enrollment_envelope(&self) -> EnrollmentEnvelope {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| self.config.agent_id.clone());
        EnrollmentEnvelope {
            agent_id: self.config.agent_id.clone(),
            mac: self.config.mac.clone(),
            hostname,
            enrollment_token: self.config.enrollment_token.clone(),
            tenant_id: self.config.tenant_id.clone(),
        }
    }

    fn consume_bootstrap_config(&self) {
        let Some(path) = self.config.bootstrap_config_path.as_ref() else {
            return;
        };
        match std::fs::remove_file(path) {
            Ok(()) => tracing::info!(path = %path.display(), "consumed bootstrap config after enrollment"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                warn!(error = %err, path = %path.display(), "failed consuming bootstrap config")
            }
        }
    }
}
