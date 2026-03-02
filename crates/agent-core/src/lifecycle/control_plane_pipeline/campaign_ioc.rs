use anyhow::Result;
use grpc_client::IocSignalBatch;
use tracing::info;

use super::super::{AgentRuntime, IOC_SIGNAL_BUFFER_CAP};

impl AgentRuntime {
    /// Buffer an IOC signal from a detection hit for later batch upload.
    pub(in super::super) fn buffer_ioc_signal(
        &mut self,
        ioc_value: String,
        ioc_type: String,
        confidence: &str,
        now_unix: i64,
    ) {
        if self.ioc_signal_buffer.len() >= IOC_SIGNAL_BUFFER_CAP {
            // Drop oldest to make room — ring-buffer behavior.
            self.ioc_signal_buffer.remove(0);
        }

        // Coalesce: if the same IOC is already buffered, bump its event_count.
        if let Some(existing) = self
            .ioc_signal_buffer
            .iter_mut()
            .find(|s| s.ioc_value == ioc_value)
        {
            existing.event_count = existing.event_count.saturating_add(1);
            return;
        }

        self.ioc_signal_buffer.push(grpc_client::IocSignal {
            ioc_value,
            ioc_type,
            confidence: confidence.to_string(),
            first_seen_unix: now_unix,
            event_count: 1,
        });
    }

    pub(super) async fn upload_ioc_signals_if_due(&mut self, now_unix: i64) -> Result<()> {
        if !self.ioc_signal_upload_due(now_unix) {
            return Ok(());
        }
        self.last_ioc_signal_upload_unix = Some(now_unix);

        let signals = std::mem::take(&mut self.ioc_signal_buffer);
        if signals.is_empty() {
            return Ok(());
        }

        let batch = IocSignalBatch {
            agent_id: self.config.agent_id.clone(),
            signals,
        };

        self.client.send_ioc_signals(&batch).await?;
        info!(
            agent_id = %self.config.agent_id,
            signal_count = batch.signals.len(),
            "uploaded IOC signal batch for campaign correlation"
        );
        Ok(())
    }

    pub(super) async fn fetch_and_apply_campaigns_if_due(&mut self, now_unix: i64) -> Result<()> {
        if !self.campaign_fetch_due(now_unix) {
            return Ok(());
        }
        self.last_campaign_fetch_unix = Some(now_unix);

        let campaigns = self.client.fetch_campaigns(&self.config.agent_id).await?;
        if campaigns.is_empty() {
            self.active_campaign_iocs.clear();
            return Ok(());
        }

        let mut new_campaign_iocs = std::collections::HashSet::with_capacity(campaigns.len());
        for campaign in &campaigns {
            new_campaign_iocs.insert(campaign.ioc_value.clone());
        }

        info!(
            agent_id = %self.config.agent_id,
            active_campaigns = campaigns.len(),
            "fetched active campaign alerts"
        );
        self.active_campaign_iocs = new_campaign_iocs;
        Ok(())
    }

    /// Check if the given IOC values include any active campaign IOCs.
    /// If so, mark the detection as campaign-correlated.
    pub(in super::super) fn is_campaign_correlated(&self, ioc_values: &[String]) -> bool {
        ioc_values
            .iter()
            .any(|ioc| self.active_campaign_iocs.contains(ioc))
    }
}
