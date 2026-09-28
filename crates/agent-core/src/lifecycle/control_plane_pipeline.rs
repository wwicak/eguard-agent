mod baseline_sync;
mod campaign_ioc;
mod executor;
mod outbound_sends;
mod policy_sync;
mod rollout;
mod scheduler;

use std::time::Instant;

use anyhow::Result;

use super::{elapsed_micros, AgentRuntime, TickEvaluation};

impl AgentRuntime {
    pub(super) async fn run_connected_control_plane_stage(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) -> Result<()> {
        let control_started = Instant::now();
        self.enqueue_due_control_plane_tasks(now_unix, evaluation);
        let executed = self.execute_control_plane_task_budget(now_unix).await?;
        let oldest_age_secs = self.control_plane_queue_oldest_age_secs(now_unix);

        self.metrics.last_control_plane_sync_micros = elapsed_micros(control_started);
        self.metrics.last_control_plane_execute_count = executed;
        self.metrics.last_control_plane_queue_depth = self.pending_control_plane_tasks.len();
        self.metrics.max_control_plane_queue_depth = self
            .metrics
            .max_control_plane_queue_depth
            .max(self.pending_control_plane_tasks.len());
        self.metrics.last_control_plane_oldest_age_secs = oldest_age_secs;
        self.metrics.max_control_plane_oldest_age_secs = self
            .metrics
            .max_control_plane_oldest_age_secs
            .max(oldest_age_secs);

        Ok(())
    }
}
