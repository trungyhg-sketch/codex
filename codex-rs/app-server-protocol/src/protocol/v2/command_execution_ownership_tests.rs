use super::*;
use crate::ClientRequest;
use crate::ServerNotification;
use pretty_assertions::assert_eq;
use serde_json::json;

fn termination_params() -> TerminateOwnedParams {
    TerminateOwnedParams {
        process_id: "42".into(),
        ownership_token: ProcessOwnershipToken::from_opaque("private-token-marker".to_string()),
        expected_identity: NativeProcessIdentity {
            os_pid: 42,
            creation_time: Some(1234),
            executable_identity: Some("private-executable-marker".to_string()),
            parent_pid: Some(7),
            parent_creation_time: Some(5678),
            platform: "test".to_string(),
        },
    }
}

#[test]
fn ownership_evidence_notification_round_trips_without_debug_disclosure() {
    let notification = ServerNotification::CommandExecutionOwnershipEvidence(
        CommandExecutionOwnershipEvidenceNotification {
            thread_id: "thread-1".to_string(),
            turn_id: "turn-1".to_string(),
            item_id: "item-1".to_string(),
            termination: termination_params(),
        },
    );
    let encoded = serde_json::to_value(&notification).unwrap();
    let decoded: ServerNotification = serde_json::from_value(encoded.clone()).unwrap();

    let ServerNotification::CommandExecutionOwnershipEvidence(decoded) = decoded else {
        panic!("expected ownership evidence notification");
    };
    let ServerNotification::CommandExecutionOwnershipEvidence(expected) = &notification else {
        unreachable!("constructed as ownership evidence notification");
    };
    assert_eq!(&decoded, expected);
    assert_eq!(
        encoded["method"],
        json!("item/commandExecution/ownershipEvidence")
    );
    let debug = format!("{notification:?}");
    assert!(!debug.contains("private-token-marker"));
    assert!(!debug.contains("private-executable-marker"));
}

#[test]
fn terminate_owned_request_and_response_use_canonical_stage2b_types() {
    let params = CommandExecutionTerminateOwnedParams {
        thread_id: "thread-1".to_string(),
        turn_id: "turn-1".to_string(),
        item_id: "item-1".to_string(),
        termination: termination_params(),
        operation_id: None,
    };
    let encoded = json!({
        "id": 1,
        "method": "item/commandExecution/terminateOwned",
        "params": serde_json::to_value(&params).unwrap(),
    });
    let decoded: ClientRequest = serde_json::from_value(encoded.clone()).unwrap();

    assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
    assert_eq!(
        encoded["method"],
        json!("item/commandExecution/terminateOwned")
    );
    let debug = format!("{params:?}");
    assert!(!debug.contains("private-token-marker"));
    assert!(!debug.contains("private-executable-marker"));

    let response = CommandExecutionTerminateOwnedResponse {
        outcome: TerminateOwnedOutcome::IdentityMismatch,
        operation_id: None,
        phase: None,
        reason: None,
        completion_version: None,
    };
    assert_eq!(
        serde_json::from_value::<CommandExecutionTerminateOwnedResponse>(
            serde_json::to_value(&response).unwrap()
        )
        .unwrap(),
        response
    );
}

#[test]
fn completion_v1_request_and_status_query_round_trip() {
    let request = ClientRequest::CommandExecutionTerminateOwned {
        request_id: crate::RequestId::Integer(1),
        params: CommandExecutionTerminateOwnedParams {
            thread_id: "thread-1".to_string(),
            turn_id: "turn-1".to_string(),
            item_id: "item-1".to_string(),
            termination: termination_params(),
            operation_id: Some("operation-1".to_string()),
        },
    };
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["params"]["operationId"], json!("operation-1"));
    assert_eq!(
        serde_json::from_value::<ClientRequest>(value).unwrap(),
        request
    );

    let status = ClientRequest::CommandExecutionTerminateOwnedStatus {
        request_id: crate::RequestId::Integer(2),
        params: CommandExecutionTerminateOwnedStatusParams {
            operation_id: "operation-1".to_string(),
            thread_id: "thread-1".to_string(),
            turn_id: "turn-1".to_string(),
            item_id: "item-1".to_string(),
            process_identity: termination_params().expected_identity,
        },
    };
    let value = serde_json::to_value(&status).unwrap();
    assert_eq!(
        value["method"],
        json!("item/commandExecution/terminateOwned/status")
    );
    assert_eq!(
        serde_json::from_value::<ClientRequest>(value).unwrap(),
        status
    );
}

#[test]
fn native_a_completion_schema_never_claims_exit_or_drain() {
    let completion = CommandExecutionTerminateOwnedCompletedNotification {
        operation_id: "operation-1".to_string(),
        thread_id: "thread-1".to_string(),
        turn_id: "turn-1".to_string(),
        item_id: "item-1".to_string(),
        process_identity: termination_params().expected_identity,
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
        completed_at: 123,
    };
    let notification =
        ServerNotification::CommandExecutionTerminateOwnedCompleted(completion.clone());
    let value = serde_json::to_value(&notification).unwrap();
    assert_eq!(
        value["method"],
        json!("item/commandExecution/terminateOwned/completed")
    );
    let decoded = serde_json::from_value::<ServerNotification>(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), value);
    assert!(!completion.root_exit_confirmed);
    assert!(!completion.tree_exit_confirmed);
    assert!(!completion.drain_complete);
    assert!(!completion.tool_finalized);
}
