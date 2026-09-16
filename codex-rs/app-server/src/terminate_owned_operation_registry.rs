use codex_app_server_protocol::CommandExecutionTerminateOwnedCompletedNotification;
use codex_app_server_protocol::CommandExecutionTerminateOwnedStatusResponse;
use codex_app_server_protocol::NativeProcessIdentity;
use codex_app_server_protocol::TerminateOwnedOperationState;
use codex_app_server_protocol::TerminateOwnedOutcome;
use codex_app_server_protocol::TerminateOwnedParams;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

pub(crate) const TERMINATE_OWNED_COMPLETION_VERSION: u32 = 1;
pub(crate) const TERMINATE_OWNED_TERMINAL_RETENTION_SECONDS: i64 = 15 * 60;
pub(crate) const TERMINATE_OWNED_OPERATION_CAPACITY: usize = 1024;

pub(crate) fn valid_termination_operation_id(operation_id: &str) -> bool {
    !operation_id.is_empty()
        && operation_id.len() <= 128
        && operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TerminateOwnedCorrelation {
    pub(crate) thread_id: String,
    pub(crate) turn_id: String,
    pub(crate) item_id: String,
    pub(crate) termination: TerminateOwnedParams,
}

#[derive(Clone)]
struct OperationRecord {
    correlation: TerminateOwnedCorrelation,
    created_at: i64,
    accepted_at: Option<i64>,
    initial_outcome: Option<TerminateOwnedOutcome>,
    completion: Option<CommandExecutionTerminateOwnedCompletedNotification>,
}

#[derive(Default)]
struct RegistryState {
    records: HashMap<String, OperationRecord>,
    terminal_order: VecDeque<String>,
    expired: HashMap<String, TerminateOwnedCorrelation>,
    expired_order: VecDeque<String>,
}

#[derive(Clone)]
pub(crate) struct TerminateOwnedOperationRegistry {
    state: Arc<Mutex<RegistryState>>,
    capacity: usize,
    retention_seconds: i64,
}

pub(crate) enum ReserveResult {
    Reserved,
    Duplicate(Box<CommandExecutionTerminateOwnedStatusResponse>),
    Conflict,
    Full,
}

impl TerminateOwnedOperationRegistry {
    pub(crate) fn new() -> Self {
        Self::with_limits(
            TERMINATE_OWNED_OPERATION_CAPACITY,
            TERMINATE_OWNED_TERMINAL_RETENTION_SECONDS,
        )
    }

    fn with_limits(capacity: usize, retention_seconds: i64) -> Self {
        Self {
            state: Arc::new(Mutex::new(RegistryState::default())),
            capacity,
            retention_seconds,
        }
    }

    pub(crate) async fn reserve(
        &self,
        operation_id: &str,
        correlation: TerminateOwnedCorrelation,
        now: i64,
    ) -> ReserveResult {
        let mut state = self.state.lock().await;
        self.purge_expired(&mut state, now);
        if let Some(record) = state.records.get(operation_id) {
            return if record.correlation == correlation {
                ReserveResult::Duplicate(Box::new(status_response(operation_id, record)))
            } else {
                ReserveResult::Conflict
            };
        }
        if state.expired.contains_key(operation_id) {
            return ReserveResult::Conflict;
        }
        while state.records.len() >= self.capacity {
            let Some(oldest) = state.terminal_order.pop_front() else {
                return ReserveResult::Full;
            };
            self.expire_record(&mut state, &oldest);
        }
        state.records.insert(
            operation_id.to_string(),
            OperationRecord {
                correlation,
                created_at: now,
                accepted_at: None,
                initial_outcome: None,
                completion: None,
            },
        );
        ReserveResult::Reserved
    }

    pub(crate) async fn accept(
        &self,
        operation_id: &str,
        outcome: TerminateOwnedOutcome,
        now: i64,
    ) {
        if let Some(record) = self.state.lock().await.records.get_mut(operation_id) {
            record.accepted_at = Some(now);
            record.initial_outcome = Some(outcome);
        }
    }

    pub(crate) async fn refuse(&self, operation_id: &str) {
        self.state.lock().await.records.remove(operation_id);
    }

    #[allow(dead_code)] // Native B will publish authoritative terminal evidence through this path.
    pub(crate) async fn complete(
        &self,
        operation_id: &str,
        completion: CommandExecutionTerminateOwnedCompletedNotification,
    ) -> bool {
        let mut state = self.state.lock().await;
        let Some(record) = state.records.get_mut(operation_id) else {
            return false;
        };
        if record.completion.is_none() {
            record.completion = Some(completion);
            state.terminal_order.push_back(operation_id.to_string());
        }
        true
    }

    #[cfg(test)]
    pub(crate) async fn status(
        &self,
        operation_id: &str,
        correlation: &TerminateOwnedCorrelation,
        now: i64,
    ) -> Option<CommandExecutionTerminateOwnedStatusResponse> {
        let mut state = self.state.lock().await;
        self.purge_expired(&mut state, now);
        if let Some(record) = state.records.get(operation_id) {
            return (record.correlation == *correlation)
                .then(|| status_response(operation_id, record));
        }
        state.expired.get(operation_id).and_then(|stored| {
            (stored == correlation).then(|| CommandExecutionTerminateOwnedStatusResponse {
                state: TerminateOwnedOperationState::Expired,
                operation_id: operation_id.to_string(),
                created_at: None,
                accepted_at: None,
                initial_outcome: None,
                completion: None,
            })
        })
    }

    pub(crate) async fn status_by_identity(
        &self,
        operation_id: &str,
        thread_id: &str,
        turn_id: &str,
        item_id: &str,
        process_identity: &NativeProcessIdentity,
        now: i64,
    ) -> Option<CommandExecutionTerminateOwnedStatusResponse> {
        let mut state = self.state.lock().await;
        self.purge_expired(&mut state, now);
        if let Some(record) = state.records.get(operation_id) {
            let correlation = &record.correlation;
            return (correlation.thread_id == thread_id
                && correlation.turn_id == turn_id
                && correlation.item_id == item_id
                && correlation.termination.expected_identity == *process_identity)
                .then(|| status_response(operation_id, record));
        }
        state.expired.get(operation_id).and_then(|correlation| {
            (correlation.thread_id == thread_id
                && correlation.turn_id == turn_id
                && correlation.item_id == item_id
                && correlation.termination.expected_identity == *process_identity)
                .then(|| CommandExecutionTerminateOwnedStatusResponse {
                    state: TerminateOwnedOperationState::Expired,
                    operation_id: operation_id.to_string(),
                    created_at: None,
                    accepted_at: None,
                    initial_outcome: None,
                    completion: None,
                })
        })
    }

    fn purge_expired(&self, state: &mut RegistryState, now: i64) {
        while let Some(operation_id) = state.terminal_order.front().cloned() {
            let Some(record) = state.records.get(&operation_id) else {
                state.terminal_order.pop_front();
                continue;
            };
            let Some(completion) = record.completion.as_ref() else {
                state.terminal_order.pop_front();
                continue;
            };
            if now - completion.completed_at < self.retention_seconds {
                break;
            }
            state.terminal_order.pop_front();
            self.expire_record(state, &operation_id);
        }
    }

    fn expire_record(&self, state: &mut RegistryState, operation_id: &str) {
        if let Some(record) = state.records.remove(operation_id) {
            state
                .expired
                .insert(operation_id.to_string(), record.correlation);
            state.expired_order.push_back(operation_id.to_string());
            while state.expired.len() > self.capacity {
                if let Some(oldest) = state.expired_order.pop_front() {
                    state.expired.remove(&oldest);
                }
            }
        }
    }
}

fn status_response(
    operation_id: &str,
    record: &OperationRecord,
) -> CommandExecutionTerminateOwnedStatusResponse {
    CommandExecutionTerminateOwnedStatusResponse {
        state: if record.completion.is_some() {
            TerminateOwnedOperationState::Terminal
        } else {
            TerminateOwnedOperationState::InProgress
        },
        operation_id: operation_id.to_string(),
        created_at: Some(record.created_at),
        accepted_at: record.accepted_at,
        initial_outcome: record.initial_outcome,
        completion: record.completion.clone(),
    }
}

#[cfg(test)]
#[path = "terminate_owned_operation_registry_tests.rs"]
mod tests;
