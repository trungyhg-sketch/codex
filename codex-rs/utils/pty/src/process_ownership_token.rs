use std::fmt;

/// Opaque evidence that a native process was created by this owner instance.
#[derive(Clone, PartialEq, Eq)]
pub struct ProcessOwnershipToken(String);

impl ProcessOwnershipToken {
    pub(crate) fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProcessOwnershipToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProcessOwnershipToken([REDACTED])")
    }
}

#[cfg(test)]
#[path = "process_ownership_token_tests.rs"]
mod tests;
