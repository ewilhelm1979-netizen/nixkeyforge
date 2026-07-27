#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![doc = "Typed, dry-run-first system adapters for NixKeyforge."]

pub mod apply;
pub mod backup;
pub mod command;
pub mod fido;
pub mod fs;
pub mod luks;
pub mod nixos;
pub mod pam;
pub mod ssh;

use sha2::{Digest, Sha256};
use std::fmt;

/// The physical authenticator's intended role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatorRole {
    Primary,
    Backup,
}

/// A stable, non-secret identifier suitable for diagnostics.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RedactedId(String);

impl RedactedId {
    pub fn from_sensitive(value: &[u8]) -> Self {
        let digest = Sha256::digest(value);
        Self(format!(
            "sha256:{}",
            digest[..8]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
    }

    pub fn expose_redacted(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RedactedId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("RedactedId").field(&self.0).finish()
    }
}

impl fmt::Display for RedactedId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_identifier_never_contains_input() {
        let id = RedactedId::from_sensitive(b"private-credential-material");
        assert!(!format!("{id:?}").contains("private-credential"));
        assert!(id.expose_redacted().starts_with("sha256:"));
    }
}
