pub use codex_exec_server_protocol::NativeProcessIdentity;
pub use codex_exec_server_protocol::ProcessOwnershipToken;
pub use codex_exec_server_protocol::TerminateOwnedOutcome;
pub use codex_exec_server_protocol::TerminateOwnedParams;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use ts_rs::TS;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct CommandExecutionOwnershipEvidenceNotification {
    pub thread_id: String,
    pub turn_id: String,
    pub item_id: String,
    pub termination: TerminateOwnedParams,
}

impl std::fmt::Debug for CommandExecutionOwnershipEvidenceNotification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandExecutionOwnershipEvidenceNotification")
            .field("thread_id", &self.thread_id)
            .field("turn_id", &self.turn_id)
            .field("item_id", &self.item_id)
            .field("termination", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct CommandExecutionTerminateOwnedParams {
    pub thread_id: String,
    pub turn_id: String,
    pub item_id: String,
    pub termination: TerminateOwnedParams,
    #[ts(optional = nullable)]
    pub operation_id: Option<String>,
}

impl std::fmt::Debug for CommandExecutionTerminateOwnedParams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandExecutionTerminateOwnedParams")
            .field("thread_id", &self.thread_id)
            .field("turn_id", &self.turn_id)
            .field("item_id", &self.item_id)
            .field("termination", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase", export_to = "v2/")]
pub enum TerminateOwnedAckPhase {
    Accepted,
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct CommandExecutionTerminateOwnedResponse {
    pub outcome: TerminateOwnedOutcome,
    pub operation_id: Option<String>,
    pub phase: Option<TerminateOwnedAckPhase>,
    pub reason: Option<String>,
    pub completion_version: Option<u32>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct CommandExecutionTerminateOwnedStatusParams {
    pub operation_id: String,
    pub thread_id: String,
    pub turn_id: String,
    pub item_id: String,
    pub process_identity: NativeProcessIdentity,
}

impl std::fmt::Debug for CommandExecutionTerminateOwnedStatusParams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandExecutionTerminateOwnedStatusParams")
            .field("operation_id", &self.operation_id)
            .field("thread_id", &self.thread_id)
            .field("turn_id", &self.turn_id)
            .field("item_id", &self.item_id)
            .field("process_identity", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase", export_to = "v2/")]
pub enum TerminateOwnedOperationState {
    InProgress,
    Terminal,
    Unknown,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase", export_to = "v2/")]
pub enum TerminateOwnedTreeContainmentMode {
    JobObjectContained,
    RootOnlyFallback,
    Uncontained,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[schemars(rename = "CommandExecutionTerminateOwnedCompletionPayload")]
#[ts(export_to = "v2/")]
pub struct CommandExecutionTerminateOwnedCompletedNotification {
    pub operation_id: String,
    pub thread_id: String,
    pub turn_id: String,
    pub item_id: String,
    pub process_identity: NativeProcessIdentity,
    pub root_exit_confirmed: bool,
    pub tree_containment_mode: TerminateOwnedTreeContainmentMode,
    pub tree_exit_confirmed: bool,
    pub stdout_closed: bool,
    pub stderr_closed: bool,
    pub drain_complete: bool,
    pub drain_reason: Option<String>,
    pub output_truncated: bool,
    pub exit_code: Option<i32>,
    pub exit_reason: Option<String>,
    pub tool_finalized: bool,
    pub completed_at: i64,
}

impl std::fmt::Debug for CommandExecutionTerminateOwnedCompletedNotification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandExecutionTerminateOwnedCompletedNotification")
            .field("operation_id", &self.operation_id)
            .field("thread_id", &self.thread_id)
            .field("turn_id", &self.turn_id)
            .field("item_id", &self.item_id)
            .field("process_identity", &"[REDACTED]")
            .field("root_exit_confirmed", &self.root_exit_confirmed)
            .field("tree_exit_confirmed", &self.tree_exit_confirmed)
            .field("drain_complete", &self.drain_complete)
            .field("tool_finalized", &self.tool_finalized)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct CommandExecutionTerminateOwnedStatusResponse {
    pub state: TerminateOwnedOperationState,
    pub operation_id: String,
    pub created_at: Option<i64>,
    pub accepted_at: Option<i64>,
    pub initial_outcome: Option<TerminateOwnedOutcome>,
    pub completion: Option<CommandExecutionTerminateOwnedCompletedNotification>,
}

impl std::fmt::Debug for CommandExecutionTerminateOwnedStatusResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandExecutionTerminateOwnedStatusResponse")
            .field("state", &self.state)
            .field("operation_id", &self.operation_id)
            .field("created_at", &self.created_at)
            .field("accepted_at", &self.accepted_at)
            .field("initial_outcome", &self.initial_outcome)
            .field("completion", &self.completion)
            .finish()
    }
}

#[cfg(test)]
#[path = "command_execution_ownership_tests.rs"]
mod tests;
