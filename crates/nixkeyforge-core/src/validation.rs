use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use thiserror::Error;

const DIGEST_PREFIX: &str = "sha256:";
const DIGEST_HEX_LEN: usize = 64;

/// Errors caused by untrusted domain input or a policy violation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds the maximum length of {max}")]
    TooLong { field: &'static str, max: usize },
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    #[error("{field} has an invalid format")]
    InvalidFormat { field: &'static str },
    #[error("unsafe archive path: {reason}")]
    UnsafeArchivePath { reason: &'static str },
    #[error("duplicate archive path")]
    DuplicateArchivePath,
    #[error("policy violation: {0}")]
    PolicyViolation(&'static str),
}

fn validate_text(field: &'static str, value: &str, max_len: usize) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty { field });
    }
    if value.len() > max_len {
        return Err(ValidationError::TooLong {
            field,
            max: max_len,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::ControlCharacter { field });
    }
    Ok(())
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(DIGEST_HEX_LEN);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn parse_digest(field: &'static str, value: &str) -> Result<[u8; 32], ValidationError> {
    let hex = value
        .strip_prefix(DIGEST_PREFIX)
        .ok_or(ValidationError::InvalidFormat { field })?;
    if hex.len() != DIGEST_HEX_LEN {
        return Err(ValidationError::InvalidFormat { field });
    }

    let mut bytes = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(pair[0]).ok_or(ValidationError::InvalidFormat { field })?;
        let low = hex_value(pair[1]).ok_or(ValidationError::InvalidFormat { field })?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

/// A SHA-256 digest rendered in a single canonical lowercase representation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    #[must_use]
    pub fn of_bytes(value: &[u8]) -> Self {
        Self(Sha256::digest(value).into())
    }

    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{DIGEST_PREFIX}{}", hex_encode(&self.0))
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_digest("SHA-256 digest", &value)
            .map(Self)
            .map_err(de::Error::custom)
    }
}

/// An irreversible, domain-separated identifier safe for diagnostics and JSON.
///
/// The original value is never retained. The domain separator prevents the same
/// raw value used for two identifier kinds from producing the same digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RedactedIdentifier([u8; 32]);

impl RedactedIdentifier {
    pub fn new(domain: &'static str, sensitive_value: &[u8]) -> Result<Self, ValidationError> {
        validate_text("identifier domain", domain, 64)?;
        if sensitive_value.is_empty() {
            return Err(ValidationError::Empty {
                field: "identifier value",
            });
        }

        let mut hasher = Sha256::new();
        hasher.update(b"nixkeyforge-redacted-id-v1\0");
        hasher.update(domain.as_bytes());
        hasher.update([0]);
        hasher.update(sensitive_value);
        Ok(Self(hasher.finalize().into()))
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.0)
    }
}

impl fmt::Display for RedactedIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "redacted:{DIGEST_PREFIX}{}", hex_encode(&self.0))
    }
}

impl fmt::Debug for RedactedIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RedactedIdentifier")
            .field(&self.to_string())
            .finish()
    }
}

impl Serialize for RedactedIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RedactedIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let digest = value
            .strip_prefix("redacted:")
            .ok_or_else(|| de::Error::custom("redacted identifier has an invalid format"))?;
        parse_digest("redacted identifier", digest)
            .map(Self)
            .map_err(de::Error::custom)
    }
}

/// A normalized relative path that is safe to use as an archive member name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ArchivePath(String);

impl ArchivePath {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_text("archive path", &value, 1024)?;

        if value.starts_with('/') {
            return Err(ValidationError::UnsafeArchivePath {
                reason: "absolute paths are forbidden",
            });
        }
        if value.contains('\\') {
            return Err(ValidationError::UnsafeArchivePath {
                reason: "backslash path separators are forbidden",
            });
        }
        if value.as_bytes().get(1) == Some(&b':')
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
        {
            return Err(ValidationError::UnsafeArchivePath {
                reason: "drive-qualified paths are forbidden",
            });
        }

        for component in value.split('/') {
            if component.is_empty() {
                return Err(ValidationError::UnsafeArchivePath {
                    reason: "empty path components are forbidden",
                });
            }
            if matches!(component, "." | "..") {
                return Err(ValidationError::UnsafeArchivePath {
                    reason: "dot path components are forbidden",
                });
            }
        }
        Ok(Self(value))
    }

    pub(crate) fn trusted(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn starts_with(&self, prefix: &Self) -> bool {
        self == prefix
            || self
                .0
                .strip_prefix(&prefix.0)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
}

impl fmt::Display for ArchivePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Debug for ArchivePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<'de> Deserialize<'de> for ArchivePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A bounded semantic tool version such as `0.1.0`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct VersionString(String);

impl VersionString {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_text("tool version", &value, 64)?;
        let valid = value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'+')
        });
        if !valid {
            return Err(ValidationError::InvalidFormat {
                field: "tool version",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for VersionString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn redacted_identifier_never_formats_the_source() {
        let secret = b"credential-handle-super-secret";
        let identifier = RedactedIdentifier::new("pam-credential", secret).unwrap();
        for output in [
            format!("{identifier}"),
            format!("{identifier:?}"),
            serde_json::to_string(&identifier).unwrap(),
        ] {
            assert!(!output.contains("credential-handle-super-secret"));
            assert!(output.contains("redacted:sha256:"));
        }
    }

    #[test]
    fn identifier_hashes_are_domain_separated() {
        let pam = RedactedIdentifier::new("pam", b"same").unwrap();
        let luks = RedactedIdentifier::new("luks", b"same").unwrap();
        assert_ne!(pam, luks);
    }

    #[test]
    fn rejects_noncanonical_digest_deserialization() {
        let uppercase = format!("\"sha256:{}\"", "A".repeat(64));
        assert!(serde_json::from_str::<Sha256Digest>(&uppercase).is_err());
        assert!(serde_json::from_str::<Sha256Digest>("\"1234\"").is_err());
    }

    #[test]
    fn archive_path_rejects_traversal_and_absolute_forms() {
        for path in [
            "../../etc/shadow",
            "/etc/shadow",
            "C:\\Windows\\secret",
            "safe/../shadow",
            "safe//file",
            "./manifest.json",
        ] {
            assert!(ArchivePath::new(path).is_err(), "{path}");
        }
    }
}
