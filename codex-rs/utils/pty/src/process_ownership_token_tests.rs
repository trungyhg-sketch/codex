use super::ProcessOwnershipToken;

#[test]
fn tokens_are_unique_and_debug_is_redacted() {
    let first = ProcessOwnershipToken::new();
    let second = ProcessOwnershipToken::new();

    assert_ne!(first, second);
    assert_eq!(format!("{first:?}"), "ProcessOwnershipToken([REDACTED])");
    assert!(uuid::Uuid::parse_str(first.as_str()).is_ok());
}
