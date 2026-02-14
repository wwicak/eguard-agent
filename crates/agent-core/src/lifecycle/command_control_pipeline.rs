use std::time::Instant;

use tracing::warn;

use super::{
    elapsed_micros, interval_due, AgentRuntime, PendingCommand, COMMAND_BACKLOG_CAPACITY,
    COMMAND_EXECUTION_BUDGET_PER_TICK, COMMAND_FETCH_INTERVAL_SECS, COMMAND_FETCH_LIMIT,
};

impl AgentRuntime {
    pub(super) async fn run_connected_command_stage(&mut self, now_unix: i64) {
        let command_sync_started = Instant::now();
        self.sync_pending_commands(now_unix).await;
        self.metrics.last_command_sync_micros = elapsed_micros(command_sync_started);
    }

    async fn sync_pending_commands(&mut self, now_unix: i64) {
        let fetched = self.fetch_command_backlog_batch(now_unix).await;
        let executed = self.execute_command_backlog_budget(now_unix).await;
        let oldest_age_secs = self.command_backlog_oldest_age_secs(now_unix);

        self.metrics.last_command_fetch_count = fetched;
        self.metrics.last_command_execute_count = executed;
        self.metrics.last_command_backlog_depth = self.pending_commands.len();
        self.metrics.max_command_backlog_depth = self
            .metrics
            .max_command_backlog_depth
            .max(self.pending_commands.len());
        self.metrics.last_command_backlog_oldest_age_secs = oldest_age_secs;
        self.metrics.max_command_backlog_oldest_age_secs = self
            .metrics
            .max_command_backlog_oldest_age_secs
            .max(oldest_age_secs);
    }

    async fn fetch_command_backlog_batch(&mut self, now_unix: i64) -> usize {
        if !self.pending_commands.is_empty() {
            return 0;
        }

        if !interval_due(
            self.last_command_fetch_attempt_unix,
            now_unix,
            COMMAND_FETCH_INTERVAL_SECS,
        ) {
            return 0;
        }
        self.last_command_fetch_attempt_unix = Some(now_unix);

        if self.pending_commands.len() >= COMMAND_BACKLOG_CAPACITY {
            warn!(
                backlog = self.pending_commands.len(),
                capacity = COMMAND_BACKLOG_CAPACITY,
                "command backlog reached capacity; deferring command fetch"
            );
            return 0;
        }

        let available_capacity = COMMAND_BACKLOG_CAPACITY - self.pending_commands.len();
        let fetch_limit = COMMAND_FETCH_LIMIT.min(available_capacity);
        if fetch_limit == 0 {
            return 0;
        }

        let completed_cursor = self.completed_command_cursor();
        match self
            .client
            .fetch_commands(&self.config.agent_id, &completed_cursor, fetch_limit)
            .await
        {
            Ok(commands) => {
                let fetched = commands.len();
                self.pending_commands
                    .extend(commands.into_iter().map(|envelope| PendingCommand {
                        envelope,
                        enqueued_at_unix: now_unix,
                    }));
                fetched
            }
            Err(err) => {
                warn!(error = %err, "command fetch failed");
                0
            }
        }
    }

    async fn execute_command_backlog_budget(&mut self, now_unix: i64) -> usize {
        let mut executed = 0usize;
        while executed < COMMAND_EXECUTION_BUDGET_PER_TICK {
            let Some(command) = self.pending_commands.pop_front() else {
                break;
            };

            self.handle_command(command.envelope, now_unix).await;
            executed = executed.saturating_add(1);
        }

        executed
    }

    fn command_backlog_oldest_age_secs(&self, now_unix: i64) -> u64 {
        let Some(oldest) = self.pending_commands.front() else {
            return 0;
        };

        now_unix.saturating_sub(oldest.enqueued_at_unix).max(0) as u64
    }
}
