use super::NativeProcessIdentity;
use super::NativeProcessIdentityValidationResult;

#[test]
fn identity_type_does_not_contain_command_data() {
    let identity = NativeProcessIdentity {
        os_pid: 7,
        creation_time: None,
        executable_identity: None,
        parent_pid: None,
        parent_creation_time: None,
        platform: std::env::consts::OS,
    };

    assert_eq!(identity.os_pid, 7);
    assert_eq!(identity.platform, std::env::consts::OS);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_stat_parser_rejects_malformed_input_and_handles_spaces_in_name() {
    assert!(super::parse_linux_stat("malformed").is_none());
    let mut fields = vec!["S".to_string(), "7".to_string()];
    fields.extend((5..=22).map(|value| value.to_string()));
    let stat = format!("123 (name with ) spaces) {}", fields.join(" "));
    assert_eq!(super::parse_linux_stat(&stat), Some((7, 22)));
}

#[test]
fn partial_identity_never_matches() {
    let identity = NativeProcessIdentity {
        os_pid: 42,
        creation_time: None,
        executable_identity: None,
        parent_pid: None,
        parent_creation_time: None,
        platform: std::env::consts::OS,
    };
    assert_eq!(
        super::compare_native_process_identity(&identity, &identity),
        NativeProcessIdentityValidationResult::PartialIdentity
    );
}

#[cfg(windows)]
#[test]
fn invalid_process_handle_fails_closed_without_fabricating_handle_fields() {
    let identity = super::capture_native_process_identity(std::process::id(), std::ptr::null_mut());

    assert_eq!(identity.creation_time, None);
    assert_eq!(identity.executable_identity, None);
}
