use super::*;
use codex_app_server_protocol::NativeProcessIdentity;
use codex_app_server_protocol::ProcessOwnershipToken;
use codex_app_server_protocol::TerminateOwnedTreeContainmentMode;
use pretty_assertions::assert_eq;

#[test]
fn operation_id_validation_accepts_opaque_ascii_identifier() {
    assert!(valid_termination_operation_id(
        "018f7f82-9b31-7cde-a456-426614174000"
    ));
}

#[test]
fn operation_id_validation_rejects_missing_malformed_and_oversized_values() {
    assert!(!valid_termination_operation_id(""));
    assert!(!valid_termination_operation_id("contains whitespace"));
    assert!(!valid_termination_operation_id(&"x".repeat(129)));
}

fn identity(pid: u32) -> NativeProcessIdentity {
    NativeProcessIdentity {
        os_pid: pid,
        creation_time: Some(10),
        executable_identity: Some("test-executable".to_string()),
        parent_pid: Some(1),
        parent_creation_time: Some(2),
        platform: "test".to_string(),
    }
}

fn correlation(item_id: &str, pid: u32) -> TerminateOwnedCorrelation {
    TerminateOwnedCorrelation {
        thread_id: "thread-1".to_string(),
        turn_id: "turn-1".to_string(),
        item_id: item_id.to_string(),
        termination: TerminateOwnedParams {
            process_id: pid.to_string().into(),
            ownership_token: ProcessOwnershipToken::from_opaque(format!("token-{pid}")),
            expected_identity: identity(pid),
        },
    }
}

fn completion(
    operation_id: &str,
    item_id: &str,
    pid: u32,
    at: i64,
) -> CommandExecutionTerminateOwnedCompletedNotification {
    CommandExecutionTerminateOwnedCompletedNotification {
        operation_id: operation_id.to_string(),
        thread_id: "thread-1".to_string(),
        turn_id: "turn-1".to_string(),
        item_id: item_id.to_string(),
        process_identity: identity(pid),
        root_exit_confirmed: false,
        tree_containment_mode: TerminateOwnedTreeContainmentMode::Unknown,
        tree_exit_confirmed: false,
        stdout_closed: false,
        stderr_closed: false,
        drain_complete: false,
        drain_reason: Some("native_a_unconfirmed".to_string()),
        output_truncated: false,
        exit_code: None,
        exit_reason: None,
        tool_finalized: false,
        completed_at: at,
    }
}

#[tokio::test]
async fn reserve_then_accept_is_visible_as_in_progress() {
    let registry = TerminateOwnedOperationRegistry::with_limits(4, 100);
    let correlation = correlation("item-1", 42);
    assert!(matches!(
        registry.reserve("op-1", correlation.clone(), 10).await,
        ReserveResult::Reserved
    ));
    registry
        .accept("op-1", TerminateOwnedOutcome::Terminated, 11)
        .await;
    let status = registry.status("op-1", &correlation, 12).await.unwrap();
    assert_eq!(status.state, TerminateOwnedOperationState::InProgress);
    assert_eq!(status.accepted_at, Some(11));
}

#[tokio::test]
async fn duplicate_exact_correlation_is_idempotent_but_different_correlation_conflicts() {
    let registry = TerminateOwnedOperationRegistry::with_limits(4, 100);
    let first = correlation("item-1", 42);
    assert!(matches!(
        registry.reserve("op-1", first.clone(), 10).await,
        ReserveResult::Reserved
    ));
    assert!(matches!(
        registry.reserve("op-1", first, 11).await,
        ReserveResult::Duplicate(_)
    ));
    assert!(matches!(
        registry
            .reserve("op-1", correlation("item-2", 43), 11)
            .await,
        ReserveResult::Conflict
    ));
}

#[tokio::test]
async fn refusal_removes_reserved_operation() {
    let registry = TerminateOwnedOperationRegistry::with_limits(4, 100);
    let correlation = correlation("item-1", 42);
    assert!(matches!(
        registry.reserve("op-1", correlation.clone(), 10).await,
        ReserveResult::Reserved
    ));
    registry.refuse("op-1").await;
    assert!(registry.status("op-1", &correlation, 11).await.is_none());
}

#[tokio::test]
async fn terminal_record_is_queryable_and_expires_with_injected_time() {
    let registry = TerminateOwnedOperationRegistry::with_limits(4, 10);
    let correlation = correlation("item-1", 42);
    assert!(matches!(
        registry.reserve("op-1", correlation.clone(), 10).await,
        ReserveResult::Reserved
    ));
    registry
        .complete("op-1", completion("op-1", "item-1", 42, 20))
        .await;
    assert_eq!(
        registry
            .status("op-1", &correlation, 29)
            .await
            .unwrap()
            .state,
        TerminateOwnedOperationState::Terminal
    );
    assert_eq!(
        registry
            .status("op-1", &correlation, 30)
            .await
            .unwrap()
            .state,
        TerminateOwnedOperationState::Expired
    );
}

#[tokio::test]
async fn capacity_evicts_terminal_records_only() {
    let registry = TerminateOwnedOperationRegistry::with_limits(2, 100);
    let first = correlation("item-1", 41);
    let second = correlation("item-2", 42);
    let third = correlation("item-3", 43);
    assert!(matches!(
        registry.reserve("op-1", first.clone(), 1).await,
        ReserveResult::Reserved
    ));
    registry
        .complete("op-1", completion("op-1", "item-1", 41, 2))
        .await;
    assert!(matches!(
        registry.reserve("op-2", second.clone(), 2).await,
        ReserveResult::Reserved
    ));
    assert!(matches!(
        registry.reserve("op-3", third, 3).await,
        ReserveResult::Reserved
    ));
    assert_eq!(
        registry.status("op-1", &first, 3).await.unwrap().state,
        TerminateOwnedOperationState::Expired
    );
    assert_eq!(
        registry.status("op-2", &second, 3).await.unwrap().state,
        TerminateOwnedOperationState::InProgress
    );
}

#[tokio::test]
async fn all_in_flight_registry_rejects_new_operation_without_eviction() {
    let registry = TerminateOwnedOperationRegistry::with_limits(1, 100);
    let first = correlation("item-1", 41);
    assert!(matches!(
        registry.reserve("op-1", first.clone(), 1).await,
        ReserveResult::Reserved
    ));
    assert!(matches!(
        registry.reserve("op-2", correlation("item-2", 42), 2).await,
        ReserveResult::Full
    ));
    assert_eq!(
        registry.status("op-1", &first, 2).await.unwrap().state,
        TerminateOwnedOperationState::InProgress
    );
}

#[tokio::test]
async fn independent_operations_do_not_contaminate_each_other() {
    let registry = TerminateOwnedOperationRegistry::with_limits(4, 100);
    let first = correlation("item-1", 41);
    let second = correlation("item-2", 42);
    registry.reserve("op-1", first.clone(), 1).await;
    registry.reserve("op-2", second.clone(), 1).await;
    registry
        .complete("op-1", completion("op-1", "item-1", 41, 2))
        .await;
    assert_eq!(
        registry.status("op-1", &first, 2).await.unwrap().state,
        TerminateOwnedOperationState::Terminal
    );
    assert_eq!(
        registry.status("op-2", &second, 2).await.unwrap().state,
        TerminateOwnedOperationState::InProgress
    );
}

#[tokio::test]
async fn new_registry_reports_old_operation_as_unknown() {
    let old = TerminateOwnedOperationRegistry::with_limits(4, 100);
    let correlation = correlation("item-1", 42);
    old.reserve("op-1", correlation.clone(), 1).await;
    let restarted = TerminateOwnedOperationRegistry::with_limits(4, 100);
    assert!(restarted.status("op-1", &correlation, 2).await.is_none());
}
