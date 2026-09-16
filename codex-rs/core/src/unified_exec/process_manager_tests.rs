use super::*;
use crate::unified_exec::clamp_yield_time;
use codex_network_proxy::ManagedNetworkSandboxContext;
use pretty_assertions::assert_eq;
use tokio::sync::Notify;
use tokio::time::Duration;
use tokio::time::Instant;

#[test]
fn command_signature_is_deterministic_sensitive_to_material_changes_and_redacted() {
    let cwd = PathUri::parse("file:///tmp/work").unwrap();
    let command = vec!["sh".to_string(), "-c".to_string(), "echo safe".to_string()];
    let same = command.clone();
    let changed = vec![
        "sh".to_string(),
        "-c".to_string(),
        "echo changed".to_string(),
    ];

    let first = safe_command_signature(&command, &cwd).unwrap();
    assert_eq!(first, safe_command_signature(&same, &cwd).unwrap());
    assert_ne!(first, safe_command_signature(&changed, &cwd).unwrap());
    assert_eq!(format!("{first:?}"), "SafeCommandSignature([REDACTED])");
}

#[test]
fn command_signature_excludes_environment_and_never_retains_raw_command() {
    let cwd = PathUri::parse("file:///tmp/work").unwrap();
    let secret = "sensitive-value-marker";
    let signature = safe_command_signature(&["tool".to_string(), secret.to_string()], &cwd)
        .expect("non-empty command should produce a digest");

    assert!(!format!("{signature:?}").contains(secret));
    assert!(safe_command_signature(&[], &cwd).is_none());
}

#[test]
fn native_identity_state_is_fail_closed_for_missing_and_partial_metadata() {
    assert_eq!(
        native_identity_state(None),
        NativeIdentityState::Unavailable
    );
    let ownership = codex_exec_server::NativeProcessOwnership {
        ownership_token: codex_exec_server::ProcessOwnershipToken::from_opaque("opaque".into()),
        identity: Some(codex_exec_server::NativeProcessIdentity {
            os_pid: 123,
            creation_time: None,
            executable_identity: None,
            parent_pid: None,
            parent_creation_time: None,
            platform: "driver".to_string(),
        }),
    };
    assert_eq!(
        native_identity_state(Some(&ownership)),
        NativeIdentityState::Partial
    );
}

#[cfg(unix)]
fn ownership_test_entry(
    process: Arc<UnifiedExecProcess>,
    process_id: i32,
    token: &str,
    identity: Option<codex_exec_server::NativeProcessIdentity>,
) -> ProcessEntry {
    let now = Instant::now();
    let native_process_ownership = Some(codex_exec_server::NativeProcessOwnership {
        ownership_token: codex_exec_server::ProcessOwnershipToken::from_opaque(token.to_string()),
        identity,
    });
    ProcessEntry {
        process,
        ownership: ProcessOwnershipEvidence {
            identity_state: native_identity_state(native_process_ownership.as_ref()),
            native_process_ownership,
            command_signature: safe_command_signature(
                &["safe-tool".to_string(), "safe-argument".to_string()],
                &PathUri::parse("file:///tmp").unwrap(),
            ),
            spawned_at: now,
        },
        ownership_termination: OwnershipTerminationState::Active,
        plugin_metrics_sidecar: None,
        call_id: format!("call-{process_id}"),
        turn_id: "turn".to_string(),
        process_id,
        cwd: PathUri::parse("file:///tmp").unwrap(),
        initial_exec_command_active: Arc::new(AtomicBool::new(true)),
        hook_command: String::new(),
        tty: false,
        network_approval: None,
        session: std::sync::Weak::new(),
        last_used: now,
    }
}

#[cfg(unix)]
#[tokio::test]
async fn process_store_preserves_concurrent_distinct_ownership_entries() {
    let process = Arc::new(
        crate::unified_exec::process_tests::remote_process(
            codex_exec_server::WriteStatus::Accepted,
            None,
            codex_sandboxing::SandboxType::None,
        )
        .await,
    );
    let store = Arc::new(tokio::sync::Mutex::new(ProcessStore::default()));
    let first_store = Arc::clone(&store);
    let first_process = Arc::clone(&process);
    let first = tokio::spawn(async move {
        first_store.lock().await.processes.insert(
            1001,
            ownership_test_entry(first_process, 1001, "ownership-token-first", None),
        );
    });
    let second_store = Arc::clone(&store);
    let second_process = Arc::clone(&process);
    let second = tokio::spawn(async move {
        second_store.lock().await.processes.insert(
            1002,
            ownership_test_entry(second_process, 1002, "ownership-token-second", None),
        );
    });
    first.await.unwrap();
    second.await.unwrap();

    let store = store.lock().await;
    let first = store.processes.get(&1001).unwrap();
    let second = store.processes.get(&1002).unwrap();
    let first_token = first
        .ownership
        .native_process_ownership
        .as_ref()
        .unwrap()
        .ownership_token
        .as_str();
    let second_token = second
        .ownership
        .native_process_ownership
        .as_ref()
        .unwrap()
        .ownership_token
        .as_str();

    assert_eq!(first_token, "ownership-token-first");
    assert_eq!(second_token, "ownership-token-second");
    assert_ne!(first_token, second_token);
    assert_eq!(
        first.ownership.identity_state,
        NativeIdentityState::Unavailable
    );
    assert_eq!(
        second.ownership.identity_state,
        NativeIdentityState::Unavailable
    );
}

#[cfg(unix)]
#[tokio::test]
async fn owned_termination_snapshot_uses_current_correlated_entry() {
    let manager = UnifiedExecProcessManager::default();
    let process = Arc::new(
        crate::unified_exec::process_tests::remote_process(
            codex_exec_server::WriteStatus::Accepted,
            None,
            codex_sandboxing::SandboxType::None,
        )
        .await,
    );
    let identity = complete_test_identity(4321);
    manager.process_store.lock().await.processes.insert(
        901,
        ownership_test_entry(process, 901, "snapshot-token", Some(identity.clone())),
    );

    let snapshot = manager
        .owned_termination_params("901", "turn", "call-901")
        .await
        .expect("complete current evidence should be available");
    assert_eq!(snapshot.process_id.as_str(), "901");
    assert_eq!(snapshot.expected_identity, identity);
    assert_eq!(snapshot.ownership_token.as_str(), "snapshot-token");
}

#[cfg(unix)]
#[tokio::test]
async fn owned_termination_snapshot_fails_closed_for_missing_or_partial_identity() {
    let manager = UnifiedExecProcessManager::default();
    let process = Arc::new(
        crate::unified_exec::process_tests::remote_process(
            codex_exec_server::WriteStatus::Accepted,
            None,
            codex_sandboxing::SandboxType::None,
        )
        .await,
    );
    manager.process_store.lock().await.processes.insert(
        902,
        ownership_test_entry(Arc::clone(&process), 902, "missing", None),
    );
    manager.process_store.lock().await.processes.insert(
        903,
        ownership_test_entry(
            process,
            903,
            "partial",
            Some(codex_exec_server::NativeProcessIdentity {
                os_pid: 4321,
                creation_time: None,
                executable_identity: None,
                parent_pid: None,
                parent_creation_time: None,
                platform: "linux".to_string(),
            }),
        ),
    );

    assert_eq!(
        manager
            .owned_termination_params("902", "turn", "call-902")
            .await,
        None
    );
    assert_eq!(
        manager
            .owned_termination_params("903", "turn", "call-903")
            .await,
        None
    );
    assert_eq!(
        manager
            .owned_termination_params("999", "turn", "call-999")
            .await,
        None
    );
}

#[cfg(unix)]
#[tokio::test]
async fn owned_termination_snapshot_rejects_stale_correlation_after_replacement() {
    let manager = UnifiedExecProcessManager::default();
    let process = Arc::new(
        crate::unified_exec::process_tests::remote_process(
            codex_exec_server::WriteStatus::Accepted,
            None,
            codex_sandboxing::SandboxType::None,
        )
        .await,
    );
    let mut replacement = ownership_test_entry(
        process,
        904,
        "replacement-token",
        Some(complete_test_identity(9876)),
    );
    replacement.call_id = "replacement-call".to_string();
    replacement.turn_id = "replacement-turn".to_string();
    manager
        .process_store
        .lock()
        .await
        .processes
        .insert(904, replacement);

    assert_eq!(
        manager
            .owned_termination_params("904", "turn", "call-904")
            .await,
        None
    );
}

#[cfg(unix)]
#[tokio::test]
async fn process_entry_ownership_is_stable_across_lifecycle_and_replacement() {
    let process = Arc::new(
        crate::unified_exec::process_tests::remote_process(
            codex_exec_server::WriteStatus::Accepted,
            None,
            codex_sandboxing::SandboxType::None,
        )
        .await,
    );
    let mut store = ProcessStore::default();
    store.processes.insert(
        2001,
        ownership_test_entry(Arc::clone(&process), 2001, "ownership-token-original", None),
    );
    let original_token = store.processes[&2001]
        .ownership
        .native_process_ownership
        .as_ref()
        .unwrap()
        .ownership_token
        .as_str()
        .to_string();

    process.terminate_confirmed().await.unwrap();
    assert_eq!(
        store.processes[&2001]
            .ownership
            .native_process_ownership
            .as_ref()
            .unwrap()
            .ownership_token
            .as_str(),
        original_token
    );

    let replacement = ownership_test_entry(
        Arc::clone(&process),
        2001,
        "ownership-token-replacement",
        None,
    );
    let removed = store.processes.insert(2001, replacement).unwrap();
    assert_eq!(
        removed
            .ownership
            .native_process_ownership
            .as_ref()
            .unwrap()
            .ownership_token
            .as_str(),
        original_token
    );
    assert_eq!(
        store.processes[&2001]
            .ownership
            .native_process_ownership
            .as_ref()
            .unwrap()
            .ownership_token
            .as_str(),
        "ownership-token-replacement"
    );
    assert_ne!(
        store.processes[&2001]
            .ownership
            .native_process_ownership
            .as_ref()
            .unwrap()
            .ownership_token
            .as_str(),
        original_token
    );
}

#[cfg(unix)]
fn complete_test_identity(pid: u32) -> codex_exec_server::NativeProcessIdentity {
    codex_exec_server::NativeProcessIdentity {
        os_pid: pid,
        creation_time: Some(42),
        executable_identity: Some("/safe/test-executable".to_string()),
        parent_pid: Some(1),
        parent_creation_time: Some(1),
        platform: "linux".to_string(),
    }
}

#[cfg(unix)]
fn owned_params(
    process_id: i32,
    token: &str,
    identity: codex_exec_server::NativeProcessIdentity,
) -> codex_exec_server_protocol::TerminateOwnedParams {
    codex_exec_server_protocol::TerminateOwnedParams {
        process_id: process_id.to_string().into(),
        ownership_token: codex_exec_server::ProcessOwnershipToken::from_opaque(token.to_string()),
        expected_identity: identity,
    }
}

#[cfg(unix)]
#[tokio::test]
async fn owned_termination_is_idempotent_and_never_uses_legacy_remote_terminate() {
    use std::sync::atomic::Ordering;

    let process_id = 3001;
    let token = "owned-token";
    let identity = complete_test_identity(301);
    let (process, control) = crate::unified_exec::process_tests::owned_remote_process(
        process_id,
        token,
        identity.clone(),
        false,
        codex_exec_server_protocol::TerminateOwnedOutcome::Terminated,
    )
    .await;
    let manager = UnifiedExecProcessManager::default();
    manager.process_store.lock().await.processes.insert(
        process_id,
        ownership_test_entry(Arc::new(process), process_id, token, Some(identity.clone())),
    );
    let params = owned_params(process_id, token, identity);

    assert_eq!(
        manager.terminate_owned_process(params.clone()).await,
        codex_exec_server_protocol::TerminateOwnedOutcome::Terminated
    );
    assert_eq!(
        manager.terminate_owned_process(params).await,
        codex_exec_server_protocol::TerminateOwnedOutcome::Terminated
    );
    assert_eq!(control.owned_calls.load(Ordering::SeqCst), 1);
    assert_eq!(control.legacy_calls.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn concurrent_duplicate_owned_termination_invokes_underlying_once() {
    use std::sync::atomic::Ordering;

    let process_id = 3005;
    let token = "concurrent-token";
    let identity = complete_test_identity(306);
    let (process, control) = crate::unified_exec::process_tests::owned_remote_process(
        process_id,
        token,
        identity.clone(),
        true,
        codex_exec_server_protocol::TerminateOwnedOutcome::Terminated,
    )
    .await;
    let manager = Arc::new(UnifiedExecProcessManager::default());
    manager.process_store.lock().await.processes.insert(
        process_id,
        ownership_test_entry(Arc::new(process), process_id, token, Some(identity.clone())),
    );
    let params = owned_params(process_id, token, identity);
    let entered = control.entered.notified();
    let first_manager = Arc::clone(&manager);
    let first_params = params.clone();
    let first =
        tokio::spawn(async move { first_manager.terminate_owned_process(first_params).await });
    entered.await;
    let second_manager = Arc::clone(&manager);
    let second = tokio::spawn(async move { second_manager.terminate_owned_process(params).await });
    control.release.notify_one();

    assert_eq!(
        first.await.unwrap(),
        codex_exec_server_protocol::TerminateOwnedOutcome::Terminated
    );
    assert_eq!(
        second.await.unwrap(),
        codex_exec_server_protocol::TerminateOwnedOutcome::Terminated
    );
    assert_eq!(control.owned_calls.load(Ordering::SeqCst), 1);
    assert_eq!(control.legacy_calls.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn owned_termination_rejects_wrong_stale_and_unavailable_evidence() {
    use std::sync::atomic::Ordering;

    let process_id = 3002;
    let identity = complete_test_identity(302);
    let (process, control) = crate::unified_exec::process_tests::owned_remote_process(
        process_id,
        "current-token",
        identity.clone(),
        false,
        codex_exec_server_protocol::TerminateOwnedOutcome::Terminated,
    )
    .await;
    let manager = UnifiedExecProcessManager::default();
    manager.process_store.lock().await.processes.insert(
        process_id,
        ownership_test_entry(
            Arc::new(process),
            process_id,
            "current-token",
            Some(identity.clone()),
        ),
    );

    assert_eq!(
        manager
            .terminate_owned_process(owned_params(process_id, "old-token", identity.clone()))
            .await,
        codex_exec_server_protocol::TerminateOwnedOutcome::OwnershipMismatch
    );
    let mut stale = identity.clone();
    stale.creation_time = Some(41);
    assert_eq!(
        manager
            .terminate_owned_process(owned_params(process_id, "current-token", stale))
            .await,
        codex_exec_server_protocol::TerminateOwnedOutcome::StaleEvidence
    );
    manager
        .process_store
        .lock()
        .await
        .processes
        .get_mut(&process_id)
        .unwrap()
        .ownership
        .identity_state = NativeIdentityState::Unavailable;
    assert_eq!(
        manager
            .terminate_owned_process(owned_params(process_id, "current-token", identity.clone()))
            .await,
        codex_exec_server_protocol::TerminateOwnedOutcome::IdentityUnavailable
    );
    manager
        .process_store
        .lock()
        .await
        .processes
        .get_mut(&process_id)
        .unwrap()
        .ownership
        .identity_state = NativeIdentityState::Partial;
    assert_eq!(
        manager
            .terminate_owned_process(owned_params(process_id, "current-token", identity.clone()))
            .await,
        codex_exec_server_protocol::TerminateOwnedOutcome::PartialIdentity
    );
    manager
        .process_store
        .lock()
        .await
        .processes
        .get_mut(&process_id)
        .unwrap()
        .ownership
        .native_process_ownership = None;
    assert_eq!(
        manager
            .terminate_owned_process(owned_params(process_id, "current-token", identity))
            .await,
        codex_exec_server_protocol::TerminateOwnedOutcome::Unsupported
    );
    assert_eq!(control.owned_calls.load(Ordering::SeqCst), 0);
    assert_eq!(control.legacy_calls.load(Ordering::SeqCst), 0);

    let restarted = UnifiedExecProcessManager::default();
    assert_eq!(
        restarted
            .terminate_owned_process(owned_params(
                process_id,
                "current-token",
                complete_test_identity(302),
            ))
            .await,
        codex_exec_server_protocol::TerminateOwnedOutcome::ProcessNotFound
    );
}

#[cfg(unix)]
#[tokio::test]
async fn exited_during_owned_termination_is_stable_and_idempotent() {
    use std::sync::atomic::Ordering;

    let process_id = 3006;
    let token = "exited-token";
    let identity = complete_test_identity(307);
    let (process, control) = crate::unified_exec::process_tests::owned_remote_process(
        process_id,
        token,
        identity.clone(),
        false,
        codex_exec_server_protocol::TerminateOwnedOutcome::AlreadyExited,
    )
    .await;
    let manager = UnifiedExecProcessManager::default();
    manager.process_store.lock().await.processes.insert(
        process_id,
        ownership_test_entry(Arc::new(process), process_id, token, Some(identity.clone())),
    );
    let params = owned_params(process_id, token, identity);

    assert_eq!(
        manager.terminate_owned_process(params.clone()).await,
        codex_exec_server_protocol::TerminateOwnedOutcome::AlreadyExited
    );
    assert_eq!(
        manager.terminate_owned_process(params).await,
        codex_exec_server_protocol::TerminateOwnedOutcome::AlreadyExited
    );
    assert_eq!(control.owned_calls.load(Ordering::SeqCst), 1);
    assert_eq!(control.legacy_calls.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn concurrent_owned_termination_releases_store_and_protects_replacement() {
    use std::sync::atomic::Ordering;

    let process_id = 3003;
    let token = "original-token";
    let identity = complete_test_identity(303);
    let (process, control) = crate::unified_exec::process_tests::owned_remote_process(
        process_id,
        token,
        identity.clone(),
        true,
        codex_exec_server_protocol::TerminateOwnedOutcome::Terminated,
    )
    .await;
    let manager = Arc::new(UnifiedExecProcessManager::default());
    manager.process_store.lock().await.processes.insert(
        process_id,
        ownership_test_entry(Arc::new(process), process_id, token, Some(identity.clone())),
    );
    let params = owned_params(process_id, token, identity.clone());
    let entered = control.entered.notified();
    let first_manager = Arc::clone(&manager);
    let first_params = params.clone();
    let first =
        tokio::spawn(async move { first_manager.terminate_owned_process(first_params).await });
    entered.await;

    // Acquiring and mutating ProcessStore while the mocked RPC is blocked proves
    // the store mutex is not held across the termination await.
    manager.release_process_id(process_id).await;
    assert!(
        manager
            .process_store
            .lock()
            .await
            .processes
            .contains_key(&process_id)
    );

    let (replacement, _) = crate::unified_exec::process_tests::owned_remote_process(
        process_id,
        "replacement-token",
        complete_test_identity(304),
        false,
        codex_exec_server_protocol::TerminateOwnedOutcome::Terminated,
    )
    .await;
    manager.process_store.lock().await.processes.insert(
        process_id,
        ownership_test_entry(
            Arc::new(replacement),
            process_id,
            "replacement-token",
            Some(complete_test_identity(304)),
        ),
    );
    control.release.notify_one();

    assert_eq!(
        first.await.unwrap(),
        codex_exec_server_protocol::TerminateOwnedOutcome::Terminated
    );
    let store = manager.process_store.lock().await;
    let replacement = store.processes.get(&process_id).unwrap();
    assert_eq!(
        replacement.ownership_termination,
        OwnershipTerminationState::Active
    );
    assert_eq!(
        replacement
            .ownership
            .native_process_ownership
            .as_ref()
            .unwrap()
            .ownership_token
            .as_str(),
        "replacement-token"
    );
    drop(store);
    assert_eq!(
        manager.terminate_owned_process(params).await,
        codex_exec_server_protocol::TerminateOwnedOutcome::OwnershipMismatch
    );
    assert_eq!(control.owned_calls.load(Ordering::SeqCst), 1);
    assert_eq!(control.legacy_calls.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn pruning_skips_an_entry_while_owned_termination_is_in_flight() {
    let process_id = 3004;
    let identity = complete_test_identity(305);
    let process = Arc::new(
        crate::unified_exec::process_tests::remote_process(
            codex_exec_server::WriteStatus::Accepted,
            None,
            codex_sandboxing::SandboxType::None,
        )
        .await,
    );
    let mut store = ProcessStore::default();
    for id in 3004..(3004 + MAX_UNIFIED_EXEC_PROCESSES as i32) {
        store.processes.insert(
            id,
            ownership_test_entry(
                Arc::clone(&process),
                id,
                &format!("token-{id}"),
                Some(identity.clone()),
            ),
        );
    }
    store.processes.get_mut(&process_id).unwrap().last_used =
        Instant::now() - Duration::from_secs(60);
    store
        .processes
        .get_mut(&process_id)
        .unwrap()
        .ownership_termination = OwnershipTerminationState::Terminating;

    let pruned = UnifiedExecProcessManager::prune_processes_if_needed(&mut store);
    assert_ne!(pruned.map(|entry| entry.process_id), Some(process_id));
    assert!(store.processes.contains_key(&process_id));
}

#[test]
fn unified_exec_env_injects_defaults() {
    let env = apply_unified_exec_env(HashMap::new());
    let expected = HashMap::from([
        ("NO_COLOR".to_string(), "1".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("LC_CTYPE".to_string(), "C.UTF-8".to_string()),
        ("LC_ALL".to_string(), "C.UTF-8".to_string()),
        ("COLORTERM".to_string(), String::new()),
        ("PAGER".to_string(), "cat".to_string()),
        ("GIT_PAGER".to_string(), "cat".to_string()),
        ("GH_PAGER".to_string(), "cat".to_string()),
        ("CODEX_CI".to_string(), "1".to_string()),
    ]);

    assert_eq!(env, expected);
}

#[test]
fn unified_exec_env_overrides_existing_values() {
    let mut base = HashMap::new();
    base.insert("NO_COLOR".to_string(), "0".to_string());
    base.insert("PATH".to_string(), "/usr/bin".to_string());

    let env = apply_unified_exec_env(base);

    assert_eq!(env.get("NO_COLOR"), Some(&"1".to_string()));
    assert_eq!(env.get("PATH"), Some(&"/usr/bin".to_string()));
}

#[test]
fn env_overlay_for_exec_server_keeps_runtime_changes_only() {
    let local_policy_env = HashMap::from([
        ("HOME".to_string(), "/client-home".to_string()),
        ("PATH".to_string(), "/client-path".to_string()),
        ("SHELL_SET".to_string(), "policy".to_string()),
        (
            CODEX_PERMISSION_PROFILE_ENV_VAR.to_string(),
            "current-profile".to_string(),
        ),
        (
            codex_apply_patch::CODEX_APPLY_PATCH_PRESERVE_LINE_ENDINGS_ENV_VAR.to_string(),
            "1".to_string(),
        ),
    ]);
    let request_env = HashMap::from([
        ("HOME".to_string(), "/client-home".to_string()),
        ("PATH".to_string(), "/sandbox-path".to_string()),
        ("OpenAI_Federation_Rule_Id".to_string(), "rule".to_string()),
        ("SHELL_SET".to_string(), "policy".to_string()),
        ("CODEX_THREAD_ID".to_string(), "thread-1".to_string()),
        (
            CODEX_PERMISSION_PROFILE_ENV_VAR.to_string(),
            "current-profile".to_string(),
        ),
        (
            codex_apply_patch::CODEX_APPLY_PATCH_PRESERVE_LINE_ENDINGS_ENV_VAR.to_string(),
            "1".to_string(),
        ),
        (
            "CODEX_SANDBOX_NETWORK_DISABLED".to_string(),
            "1".to_string(),
        ),
    ]);

    assert_eq!(
        env_overlay_for_exec_server(&request_env, &local_policy_env),
        HashMap::from([
            ("PATH".to_string(), "/sandbox-path".to_string()),
            ("CODEX_THREAD_ID".to_string(), "thread-1".to_string()),
            (
                CODEX_PERMISSION_PROFILE_ENV_VAR.to_string(),
                "current-profile".to_string(),
            ),
            (
                codex_apply_patch::CODEX_APPLY_PATCH_PRESERVE_LINE_ENDINGS_ENV_VAR.to_string(),
                "1".to_string(),
            ),
            (
                "CODEX_SANDBOX_NETWORK_DISABLED".to_string(),
                "1".to_string()
            ),
        ])
    );
}

#[test]
fn exec_env_policy_excludes_non_inheritable_and_runtime_variables() {
    let policy = ShellEnvironmentPolicy {
        r#set: HashMap::from([
            (
                "codex_permission_profile".to_string(),
                "stale-profile".to_string(),
            ),
            (
                "openai_identity_token_file".to_string(),
                "/run/identity-token".to_string(),
            ),
            (
                "codex_apply_patch_preserve_line_endings".to_string(),
                "1".to_string(),
            ),
            (
                "codex_plugin_metrics_output".to_string(),
                "/stale/sidecar".to_string(),
            ),
            ("KEEP".to_string(), "value".to_string()),
        ]),
        ..Default::default()
    };

    assert_eq!(
        exec_env_policy_from_shell_policy(&policy),
        codex_exec_server::ExecEnvPolicy {
            inherit: policy.inherit,
            ignore_default_excludes: policy.ignore_default_excludes,
            exclude: vec![
                CODEX_PERMISSION_PROFILE_ENV_VAR.to_string(),
                codex_apply_patch::CODEX_APPLY_PATCH_PRESERVE_LINE_ENDINGS_ENV_VAR.to_string(),
                PLUGIN_METRICS_OUTPUT_ENV_VAR.to_string(),
            ],
            r#set: HashMap::from([("KEEP".to_string(), "value".to_string())]),
            include_only: Vec::new(),
        }
    );
}

#[test]
fn exec_server_params_use_path_uri_and_env_policy_overlay_contract() {
    let cwd: codex_utils_absolute_path::AbsolutePathBuf = std::env::current_dir()
        .expect("current dir")
        .try_into()
        .expect("absolute path");
    let permission_profile = codex_protocol::models::PermissionProfile::Disabled;
    let managed_network = ManagedNetworkSandboxContext {
        loopback_ports: vec![43123],
        allow_local_binding: false,
    };
    let mut request = ExecRequest {
        command: vec!["bash".to_string(), "-lc".to_string(), "true".to_string()],
        cwd: cwd.clone().into(),
        env: HashMap::from([
            ("HOME".to_string(), "/client-home".to_string()),
            ("PATH".to_string(), "/sandbox-path".to_string()),
            ("CODEX_THREAD_ID".to_string(), "thread-1".to_string()),
            (
                "HTTP_PROXY".to_string(),
                "http://127.0.0.1:43123".to_string(),
            ),
            ("CODEX_NETWORK_PROXY_ACTIVE".to_string(), "1".to_string()),
            (
                "SSL_CERT_FILE".to_string(),
                "/client/custom-ca.pem".to_string(),
            ),
        ]),
        exec_server_env_config: Some(ExecServerEnvConfig {
            policy: codex_exec_server::ExecEnvPolicy {
                inherit: codex_protocol::config_types::ShellEnvironmentPolicyInherit::Core,
                ignore_default_excludes: false,
                exclude: Vec::new(),
                r#set: HashMap::new(),
                include_only: Vec::new(),
            },
            local_policy_env: HashMap::from([
                ("HOME".to_string(), "/client-home".to_string()),
                ("PATH".to_string(), "/client-path".to_string()),
                (
                    "HTTP_PROXY".to_string(),
                    "http://127.0.0.1:43123".to_string(),
                ),
                ("CODEX_NETWORK_PROXY_ACTIVE".to_string(), "1".to_string()),
                (
                    "SSL_CERT_FILE".to_string(),
                    "/client/custom-ca.pem".to_string(),
                ),
            ]),
        }),
        exec_server_shell_snapshot: None,
        network: None,
        network_environment_id: None,
        expiration: crate::exec::ExecExpiration::DefaultTimeout,
        capture_policy: crate::exec::ExecCapturePolicy::ShellTool,
        sandbox: codex_sandboxing::SandboxType::None,
        windows_sandbox_policy_cwd: cwd.clone().into(),
        windows_sandbox_workspace_roots: vec![cwd],
        windows_sandbox_level: codex_protocol::config_types::WindowsSandboxLevel::Disabled,
        windows_sandbox_private_desktop: false,
        permission_profile: permission_profile.clone(),
        windows_sandbox_filesystem_overrides: None,
        arg0: None,
        exec_server_sandbox: None,
        exec_server_enforce_managed_network: true,
        exec_server_managed_network: Some(managed_network.clone()),
        exec_server_network_proxy: None,
    };

    let proxy_settings_mode = codex_sandboxing::WindowsSandboxProxySettingsMode::Preserve;
    let params_for_request = |request: &ExecRequest| {
        exec_server_params_for_request(
            /*process_id*/ 123,
            request,
            proxy_settings_mode,
            /*tty*/ true,
        )
    };
    let params = params_for_request(&request);

    assert_eq!(params.process_id.as_str(), "123");
    assert_eq!(params.cwd, request.cwd);
    assert!(params.enforce_managed_network);
    assert_eq!(params.managed_network, Some(managed_network));
    assert!(params.env_policy.is_some());
    assert_eq!(
        params.env,
        HashMap::from([
            ("PATH".to_string(), "/sandbox-path".to_string()),
            ("CODEX_THREAD_ID".to_string(), "thread-1".to_string()),
            (
                "HTTP_PROXY".to_string(),
                "http://127.0.0.1:43123".to_string(),
            ),
            ("CODEX_NETWORK_PROXY_ACTIVE".to_string(), "1".to_string(),),
        ])
    );
    request.exec_server_shell_snapshot = Some(codex_exec_server::ShellSnapshotRequest {
        scope_id: "attachment-1".to_string(),
        shell: codex_exec_server::ShellInfo {
            name: "bash".to_string(),
            path: "/bin/bash".to_string(),
        },
    });
    let mut snapshot_env = params.env;
    snapshot_env.remove("PATH");
    assert_eq!(params_for_request(&request).env, snapshot_env);
    request.exec_server_shell_snapshot = None;

    request.exec_server_sandbox = Some(
        codex_exec_server::FileSystemSandboxContext::from_permission_profile(permission_profile),
    );
    let first = params_for_request(&request);
    let second = params_for_request(&request);
    assert_eq!(
        first
            .sandbox
            .as_ref()
            .and_then(|sandbox| sandbox.windows_sandbox_proxy_settings_mode),
        Some(codex_sandboxing::WindowsSandboxProxySettingsMode::Preserve)
    );
    assert!(first.process_id.as_str().starts_with("123-"));
    assert!(second.process_id.as_str().starts_with("123-"));
    assert_ne!(first.process_id, second.process_id);
}

#[cfg(windows)]
#[test]
fn initial_exec_yield_time_uses_windows_floor() {
    let above_max_yield_time_ms = crate::unified_exec::MAX_YIELD_TIME_MS + 1;

    assert_eq!(
        clamp_yield_time(/*yield_time_ms*/ 1_000),
        crate::unified_exec::WINDOWS_INITIAL_EXEC_YIELD_TIME_FLOOR_MS
    );
    assert_eq!(
        clamp_yield_time(/*yield_time_ms*/ 2_000),
        crate::unified_exec::WINDOWS_INITIAL_EXEC_YIELD_TIME_FLOOR_MS
    );
    assert_eq!(
        clamp_yield_time(/*yield_time_ms*/ 5_000),
        crate::unified_exec::WINDOWS_INITIAL_EXEC_YIELD_TIME_FLOOR_MS
    );
    assert_eq!(clamp_yield_time(/*yield_time_ms*/ 10_000), 10_000);
    assert_eq!(
        clamp_yield_time(/*yield_time_ms*/ above_max_yield_time_ms),
        crate::unified_exec::MAX_YIELD_TIME_MS
    );
}

#[cfg(not(windows))]
#[test]
fn initial_exec_yield_time_has_no_platform_floor() {
    assert_eq!(clamp_yield_time(/*yield_time_ms*/ 1_000), 1_000);
    assert_eq!(
        clamp_yield_time(/*yield_time_ms*/ 1),
        crate::unified_exec::MIN_YIELD_TIME_MS
    );
}

#[tokio::test]
async fn output_collection_stays_bounded_across_repeated_drains() {
    let chunks: [&[u8]; 4] = [b"01234567", b"89ABCDEF", b"ghijklmnopq", b"rs"];
    let output_buffer = Arc::new(tokio::sync::Mutex::new(HeadTailBuffer::<10>::default()));
    let output_notify = Arc::new(Notify::new());
    let output_closed = Arc::new(AtomicBool::new(false));
    let output_closed_notify = Arc::new(Notify::new());
    let cancellation_token = CancellationToken::new();
    let output = OutputHandles {
        output_buffer: Arc::clone(&output_buffer),
        output_notify: Arc::clone(&output_notify),
        output_closed: Arc::clone(&output_closed),
        output_closed_notify: Arc::clone(&output_closed_notify),
        cancellation_token: cancellation_token.clone(),
    };

    let collect = UnifiedExecProcessManager::collect_output_until_deadline(
        &output,
        /*pause_state*/ None,
        Instant::now() + Duration::from_secs(5),
    );
    let produce = async {
        for chunk in chunks {
            output_buffer.lock().await.push_chunk(chunk);
            output_notify.notify_one();
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if output_buffer.lock().await.retained_bytes() == 0 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("collector should drain each chunk");
        }

        output_closed.store(true, Ordering::Release);
        cancellation_token.cancel();
        output_closed_notify.notify_waiters();
        output_notify.notify_waiters();
    };

    let (collected, ()) = tokio::join!(collect, produce);
    let mut expected = HeadTailBuffer::<10>::default();
    for chunk in chunks {
        expected.push_chunk(chunk);
    }
    assert_eq!(collected, expected);
}

#[tokio::test]
async fn output_collection_preserves_omissions_from_drained_buffer() {
    let mut buffered_output = HeadTailBuffer::<10>::default();
    buffered_output.push_chunk(&[b'a'; 10]);
    buffered_output.push_chunk(b"overflow");
    let mut expected = HeadTailBuffer::<10>::default();
    expected.push_chunk(&[b'a'; 10]);
    expected.push_chunk(b"overflow");
    let output_buffer = Arc::new(tokio::sync::Mutex::new(buffered_output));
    let output_notify = Arc::new(Notify::new());
    let output_closed = Arc::new(AtomicBool::new(true));
    let output_closed_notify = Arc::new(Notify::new());
    let cancellation_token = CancellationToken::new();
    cancellation_token.cancel();
    let output = OutputHandles {
        output_buffer,
        output_notify,
        output_closed,
        output_closed_notify,
        cancellation_token,
    };

    let collected = UnifiedExecProcessManager::collect_output_until_deadline(
        &output,
        /*pause_state*/ None,
        Instant::now() + Duration::from_secs(1),
    )
    .await;

    assert_eq!(collected, expected);
}

#[tokio::test]
async fn network_denial_fallback_message_names_sandbox_network_proxy() {
    let message = network_denial_message_for_session(/*session*/ None, /*deferred*/ None).await;

    assert_eq!(
        message,
        "Network access was denied by the Codex sandbox network proxy."
    );
}

#[tokio::test]
async fn late_network_denial_grace_observes_cancellation_after_exit() {
    let cancellation = CancellationToken::new();
    let cancellation_for_task = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        cancellation_for_task.cancel();
    });

    assert!(wait_for_late_network_denial(Some(cancellation)).await);
}

#[tokio::test]
async fn failed_initial_end_for_unstored_process_uses_fallback_output() {
    let (session, turn, rx_event) = crate::session::tests::make_session_and_context_with_rx().await;
    let context = UnifiedExecContext::new(
        Arc::clone(&session),
        crate::session::step_context::StepContext::for_test(Arc::clone(&turn)),
        tokio_util::sync::CancellationToken::new(),
        "call-unified-denied".to_string(),
    );
    let request = ExecCommandRequest {
        command: vec![
            "sh".to_string(),
            "-lc".to_string(),
            "echo before".to_string(),
        ],
        shell_type: crate::shell::ShellType::Sh,
        hook_command: "echo before".to_string(),
        process_id: 123,
        yield_time_ms: 1000,
        max_output_tokens: None,
        #[allow(deprecated)]
        cwd: turn.cwd.clone().into(),
        #[allow(deprecated)]
        sandbox_cwd: turn.cwd.clone().into(),
        turn_environment: turn
            .environments
            .primary()
            .cloned()
            .expect("primary environment"),
        shell_mode: codex_tools::UnifiedExecShellMode::Direct,
        network: None,
        tty: true,
        sandbox_permissions: crate::sandboxing::SandboxPermissions::UseDefault,
        additional_permissions: None,
        additional_permissions_preapproved: false,
        justification: None,
        prefix_rule: None,
    };

    let transcript = Arc::new(tokio::sync::Mutex::new(HeadTailBuffer::default()));
    transcript.lock().await.push_chunk(b"PARTIAL_TRANSCRIPT");

    emit_failed_initial_exec_end_if_unstored(
        /*process_started_alive*/ false,
        &context,
        &request,
        #[allow(deprecated)]
        turn.cwd.clone().into(),
        /*plugin_attribution*/ None,
        transcript,
        "PRE_DENIAL_MARKER".to_string(),
        "Network access denied".to_string(),
        Duration::from_millis(7),
    )
    .await;

    let event = tokio::time::timeout(Duration::from_secs(1), rx_event.recv())
        .await
        .expect("timed out waiting for failed command execution item")
        .expect("event channel closed");
    let codex_protocol::protocol::EventMsg::ItemCompleted(completed_event) = event.msg else {
        panic!("expected ItemCompleted event");
    };
    let codex_protocol::items::TurnItem::CommandExecution(item) = completed_event.item else {
        panic!("expected CommandExecution item");
    };
    assert_eq!(item.id, "call-unified-denied");
    assert_eq!(
        item.status,
        codex_protocol::items::CommandExecutionStatus::Failed
    );
    assert_eq!(item.exit_code, Some(-1));
    assert_eq!(item.process_id.as_deref(), Some("123"));
    assert_eq!(
        item.aggregated_output.as_deref(),
        Some("PRE_DENIAL_MARKER\nNetwork access denied")
    );
}

#[test]
fn pruning_prefers_exited_processes_outside_recently_used() {
    let now = Instant::now();
    let meta = vec![
        (1, now - Duration::from_secs(40), false),
        (2, now - Duration::from_secs(30), true),
        (3, now - Duration::from_secs(20), false),
        (4, now - Duration::from_secs(19), false),
        (5, now - Duration::from_secs(18), false),
        (6, now - Duration::from_secs(17), false),
        (7, now - Duration::from_secs(16), false),
        (8, now - Duration::from_secs(15), false),
        (9, now - Duration::from_secs(14), false),
        (10, now - Duration::from_secs(13), false),
    ];

    let candidate = UnifiedExecProcessManager::process_id_to_prune_from_meta(&meta);

    assert_eq!(candidate, Some(2));
}

#[test]
fn pruning_falls_back_to_lru_when_no_exited() {
    let now = Instant::now();
    let meta = vec![
        (1, now - Duration::from_secs(40), false),
        (2, now - Duration::from_secs(30), false),
        (3, now - Duration::from_secs(20), false),
        (4, now - Duration::from_secs(19), false),
        (5, now - Duration::from_secs(18), false),
        (6, now - Duration::from_secs(17), false),
        (7, now - Duration::from_secs(16), false),
        (8, now - Duration::from_secs(15), false),
        (9, now - Duration::from_secs(14), false),
        (10, now - Duration::from_secs(13), false),
    ];

    let candidate = UnifiedExecProcessManager::process_id_to_prune_from_meta(&meta);

    assert_eq!(candidate, Some(1));
}

#[test]
fn pruning_protects_recent_processes_even_if_exited() {
    let now = Instant::now();
    let meta = vec![
        (1, now - Duration::from_secs(40), false),
        (2, now - Duration::from_secs(30), false),
        (3, now - Duration::from_secs(20), true),
        (4, now - Duration::from_secs(19), false),
        (5, now - Duration::from_secs(18), false),
        (6, now - Duration::from_secs(17), false),
        (7, now - Duration::from_secs(16), false),
        (8, now - Duration::from_secs(15), false),
        (9, now - Duration::from_secs(14), false),
        (10, now - Duration::from_secs(13), true),
    ];

    let candidate = UnifiedExecProcessManager::process_id_to_prune_from_meta(&meta);

    // (10) is exited but among the last 8; we should drop the LRU outside that set.
    assert_eq!(candidate, Some(1));
}

#[cfg(unix)]
#[tokio::test]
async fn pruning_does_not_evict_live_process_while_exited_process_is_finalizing() {
    let exited_process = Arc::new(
        crate::unified_exec::process_tests::remote_process(
            codex_exec_server::WriteStatus::Accepted,
            /*terminate_error*/ None,
            codex_sandboxing::SandboxType::None,
        )
        .await,
    );
    exited_process
        .terminate_confirmed()
        .await
        .expect("exited process should terminate");
    let live_process = Arc::new(
        crate::unified_exec::process_tests::remote_process(
            codex_exec_server::WriteStatus::Accepted,
            /*terminate_error*/ None,
            codex_sandboxing::SandboxType::None,
        )
        .await,
    );
    let _interaction_guard = exited_process.interaction_lock().lock_owned().await;
    let now = Instant::now();
    let cwd = PathUri::parse("file:///tmp").expect("test cwd should be valid");
    let mut store = ProcessStore::default();
    let max_process_id =
        i32::try_from(MAX_UNIFIED_EXEC_PROCESSES).expect("process cap should fit in i32");

    for process_id in 1..=max_process_id {
        let is_exited = process_id == 1;
        store.processes.insert(
            process_id,
            ProcessEntry {
                process: if is_exited {
                    Arc::clone(&exited_process)
                } else {
                    Arc::clone(&live_process)
                },
                ownership: ProcessOwnershipEvidence {
                    native_process_ownership: None,
                    command_signature: None,
                    identity_state: NativeIdentityState::Unavailable,
                    spawned_at: now,
                },
                ownership_termination: OwnershipTerminationState::Active,
                plugin_metrics_sidecar: None,
                call_id: format!("call-{process_id}"),
                turn_id: "turn".to_string(),
                process_id,
                cwd: cwd.clone(),
                initial_exec_command_active: Arc::new(AtomicBool::new(false)),
                hook_command: format!("command-{process_id}"),
                tty: false,
                network_approval: None,
                session: std::sync::Weak::new(),
                last_used: if is_exited {
                    now - Duration::from_secs(1)
                } else {
                    now
                },
            },
        );
    }

    let pruned = UnifiedExecProcessManager::prune_processes_if_needed(&mut store);

    assert_eq!(
        (pruned.map(|entry| entry.process_id), store.processes.len()),
        (None, MAX_UNIFIED_EXEC_PROCESSES)
    );
}
