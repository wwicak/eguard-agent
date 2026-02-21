use tracing::warn;

use super::{
    AgentRuntime, PendingResponseAction, TickEvaluation, RESPONSE_EXECUTION_BUDGET_PER_TICK,
    RESPONSE_QUEUE_CAPACITY,
};

impl AgentRuntime {
    pub(super) async fn run_connected_response_stage(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) {
        if std::env::var("EGUARD_DEBUG_EVENT_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            tracing::info!(
                pending_actions = self.pending_response_actions.len(),
                "debug response stage"
            );
        }

        self.maybe_apply_auto_isolation(now_unix, evaluation);
        self.enqueue_response_action_if_present(now_unix, evaluation);
        let executed = self.execute_response_backlog_budget(now_unix).await;
        let oldest_age_secs = self.response_queue_oldest_age_secs(now_unix);

        self.metrics.last_response_execute_count = executed;
        self.metrics.last_response_queue_depth = self.pending_response_actions.len();
        self.metrics.max_response_queue_depth = self
            .metrics
            .max_response_queue_depth
            .max(self.pending_response_actions.len());
        self.metrics.last_response_oldest_age_secs = oldest_age_secs;
        self.metrics.max_response_oldest_age_secs = self
            .metrics
            .max_response_oldest_age_secs
            .max(oldest_age_secs);
    }

    pub(super) fn maybe_apply_auto_isolation(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) {
        let Some(evaluation) = evaluation else {
            return;
        };

        if self.host_control.isolated {
            return;
        }

        let response_cfg = self.effective_response_config();
        let should_isolate = super::evaluate_auto_isolation(
            evaluation.confidence,
            now_unix,
            &response_cfg,
            &mut self.auto_isolation_state,
        );
        if !should_isolate {
            return;
        }

        let outcome = super::execute_server_command_with_state(
            super::ServerCommand::Isolate,
            now_unix,
            &mut self.host_control,
        );

        self.enqueue_response_report(super::ResponseEnvelope {
            agent_id: self.config.agent_id.clone(),
            action_type: "auto_isolate".to_string(),
            confidence: super::confidence_label(evaluation.confidence).to_string(),
            success: outcome.status == "completed",
            error_message: outcome.detail,
        });
    }

    fn enqueue_response_action_if_present(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) {
        let Some(evaluation) = evaluation else {
            return;
        };

        if matches!(
            evaluation.action,
            super::PlannedAction::AlertOnly | super::PlannedAction::None
        ) {
            return;
        }

        if self.pending_response_actions.len() >= RESPONSE_QUEUE_CAPACITY {
            warn!(
                queue_depth = self.pending_response_actions.len(),
                capacity = RESPONSE_QUEUE_CAPACITY,
                "response queue reached capacity; dropping oldest pending response"
            );
            self.pending_response_actions.pop_front();
        }

        self.pending_response_actions
            .push_back(PendingResponseAction {
                action: evaluation.action,
                confidence: evaluation.confidence,
                event: evaluation.detection_event.clone(),
                enqueued_at_unix: now_unix,
            });
    }

    async fn execute_response_backlog_budget(&mut self, now_unix: i64) -> usize {
        let mut executed = 0usize;

        while executed < RESPONSE_EXECUTION_BUDGET_PER_TICK {
            let Some(pending) = self.pending_response_actions.pop_front() else {
                break;
            };

            self.report_local_action_if_needed(
                pending.action,
                pending.confidence,
                &pending.event,
                now_unix,
            )
            .await;

            executed = executed.saturating_add(1);
        }

        executed
    }

    fn response_queue_oldest_age_secs(&self, now_unix: i64) -> u64 {
        let Some(item) = self.pending_response_actions.front() else {
            return 0;
        };

        now_unix.saturating_sub(item.enqueued_at_unix).max(0) as u64
    }
}
