use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    ArchivePath, AuthenticatorRole, RedactedIdentifier, Sha256Digest, ValidationError,
    VersionString,
};

pub const BACKUP_SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_PATH: &str = "manifest.json";

/// Fixed format discriminator for an NKFB package.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupFormat {
    #[serde(rename = "nixkeyforge-backup")]
    NixKeyforgeBackup,
}

/// The two deliberately distinct backup profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackupClass {
    PortableConfiguration,
    SensitiveMachineRecovery,
}

/// All component identifiers understood by manifest schema version 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BackupComponent {
    #[serde(rename = "configuration")]
    Configuration,
    #[serde(rename = "generated-nix")]
    GeneratedNixModules,
    #[serde(rename = "redacted-system-information")]
    RedactedSystemInformation,
    #[serde(rename = "pam-credential-metadata")]
    PamCredentialMetadata,
    #[serde(rename = "authenticator-roles")]
    AuthenticatorRoles,
    #[serde(rename = "public-ssh-key")]
    PublicSshKeys,
    #[serde(rename = "checksums")]
    Checksums,
    #[serde(rename = "verification-status")]
    VerificationStatus,
    #[serde(rename = "luks2-header")]
    Luks2Header,
    #[serde(rename = "recovery-material")]
    RecoveryMaterial,
    #[serde(rename = "ssh-private-key")]
    SshPrivateKeys,
    #[serde(rename = "ssh-host-key")]
    SshHostKeys,
    #[serde(rename = "pam-mapping")]
    PamMapping,
}

impl BackupComponent {
    #[must_use]
    pub const fn is_sensitive(self) -> bool {
        matches!(
            self,
            Self::Luks2Header
                | Self::RecoveryMaterial
                | Self::SshPrivateKeys
                | Self::SshHostKeys
                | Self::PamMapping
        )
    }

    fn archive_prefix(self) -> ArchivePath {
        let suffix = match self {
            Self::Configuration => "configuration",
            Self::GeneratedNixModules => "generated-nix",
            Self::RedactedSystemInformation => "redacted-system-information",
            Self::PamCredentialMetadata => "pam-credential-metadata",
            Self::AuthenticatorRoles => "authenticator-roles",
            Self::PublicSshKeys => "public-ssh-key",
            Self::Checksums => "checksums",
            Self::VerificationStatus => "verification-status",
            Self::Luks2Header => "luks2-header",
            Self::RecoveryMaterial => "recovery-material",
            Self::SshPrivateKeys => "ssh-private-key",
            Self::SshHostKeys => "ssh-host-key",
            Self::PamMapping => "pam-mapping",
        };
        ArchivePath::trusted(format!("components/{suffix}"))
    }
}

/// Encryption context is envelope metadata, not part of `manifest.json`.
///
/// It contains neither an Age recipient nor any secret passphrase, only
/// redacted recipient fingerprints or the fact that interactive mode was used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "method")]
pub enum EncryptionMethod {
    None,
    AgeRecipients {
        recipient_ids: Vec<RedactedIdentifier>,
    },
    InteractivePassphrase,
}

impl EncryptionMethod {
    #[must_use]
    pub const fn is_authenticated_encryption(&self) -> bool {
        !matches!(self, Self::None)
    }

    fn validate(&self) -> Result<(), ValidationError> {
        if let Self::AgeRecipients { recipient_ids } = self {
            if recipient_ids.is_empty() {
                return Err(ValidationError::PolicyViolation(
                    "Age encryption requires at least one recipient",
                ));
            }
            if recipient_ids.iter().collect::<BTreeSet<_>>().len() != recipient_ids.len() {
                return Err(ValidationError::PolicyViolation(
                    "duplicate Age recipients are forbidden",
                ));
            }
        }
        Ok(())
    }
}

/// Archive entry types presented by an archive reader before extraction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArchiveEntryKind {
    RegularFile,
    Directory,
    Symlink,
    Hardlink,
    DeviceNode,
    Fifo,
    Socket,
    SparseFile,
    ExtendedHeader,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveMember {
    pub path: ArchivePath,
    pub kind: ArchiveEntryKind,
}

/// Validates archive structure before any extraction is attempted.
pub fn validate_archive_members(members: &[ArchiveMember]) -> Result<(), ValidationError> {
    let mut paths = BTreeSet::new();
    let mut manifests = 0_usize;
    for member in members {
        if !paths.insert(&member.path) {
            return Err(ValidationError::DuplicateArchivePath);
        }
        if member.path.as_str() == MANIFEST_PATH {
            manifests += 1;
        }
        if member.kind != ArchiveEntryKind::RegularFile {
            return Err(ValidationError::PolicyViolation(
                "only regular files are allowed in an NKFB version 1 archive",
            ));
        }
    }
    if manifests != 1 {
        return Err(ValidationError::PolicyViolation(
            "an archive must contain exactly one manifest",
        ));
    }
    Ok(())
}

/// Exact LUKS UUID used to prevent restoring recovery data to another volume.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LuksUuid(String);

impl LuksUuid {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.len() != 36 {
            return Err(ValidationError::InvalidFormat { field: "LUKS UUID" });
        }
        for (index, byte) in value.bytes().enumerate() {
            let valid = if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            };
            if !valid {
                return Err(ValidationError::InvalidFormat { field: "LUKS UUID" });
            }
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the exact UUID for identity comparison and typed command
    /// construction. Callers must not place it in diagnostics.
    pub fn expose_for_identity_check(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LuksUuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match RedactedIdentifier::new("luks-uuid", self.0.as_bytes()) {
            Ok(redacted) => redacted.fmt(formatter),
            Err(_) => formatter.write_str("<redacted-luks-uuid>"),
        }
    }
}

impl fmt::Debug for LuksUuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LuksUuid")
            .field(&self.to_string())
            .finish()
    }
}

impl Serialize for LuksUuid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for LuksUuid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LuksVolumeRole {
    Root,
    Home,
    Swap,
    Data,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LuksVolumeIdentity {
    pub uuid: LuksUuid,
    pub role: LuksVolumeRole,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupHost {
    pub redacted_id: RedactedIdentifier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManifestVerification {
    ManualTestPending,
    Verified,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestAuthenticator {
    pub role: AuthenticatorRole,
    pub redacted_id: RedactedIdentifier,
    pub verification: ManifestVerification,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupMediaType {
    #[serde(rename = "application/json")]
    Json,
    #[serde(rename = "text/x-nix")]
    Nix,
    #[serde(rename = "text/plain")]
    PlainText,
    #[serde(rename = "application/vnd.openssh.public-key")]
    OpenSshPublicKey,
    #[serde(rename = "application/octet-stream")]
    OctetStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupFileMode {
    #[serde(rename = "0600")]
    OwnerReadWrite,
    #[serde(rename = "0644")]
    ReadOnlyPublic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackupSensitivity {
    Configuration,
    Metadata,
    Public,
    Sensitive,
}

/// One checksummed regular component file declared by the manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupEntry {
    pub component: BackupComponent,
    pub path: ArchivePath,
    pub media_type: BackupMediaType,
    pub length: u64,
    pub sha256: Sha256Digest,
    pub mode: BackupFileMode,
    pub sensitivity: BackupSensitivity,
}

impl BackupEntry {
    pub fn verify_content(&self, content: &[u8]) -> Result<(), ValidationError> {
        let actual_size = u64::try_from(content.len()).map_err(|_| {
            ValidationError::PolicyViolation("backup entry size cannot be represented")
        })?;
        if actual_size != self.length {
            return Err(ValidationError::PolicyViolation(
                "backup entry length does not match the manifest",
            ));
        }
        if Sha256Digest::of_bytes(content) != self.sha256 {
            return Err(ValidationError::PolicyViolation(
                "backup entry checksum does not match the manifest",
            ));
        }
        Ok(())
    }

    fn validate_metadata(&self) -> Result<(), ValidationError> {
        if !self.path.starts_with(&self.component.archive_prefix()) {
            return Err(ValidationError::PolicyViolation(
                "backup entry path does not match its component",
            ));
        }
        let expected_sensitivity = match self.component {
            BackupComponent::Configuration | BackupComponent::GeneratedNixModules => {
                BackupSensitivity::Configuration
            }
            BackupComponent::RedactedSystemInformation
            | BackupComponent::PamCredentialMetadata
            | BackupComponent::AuthenticatorRoles
            | BackupComponent::Checksums
            | BackupComponent::VerificationStatus => BackupSensitivity::Metadata,
            BackupComponent::PublicSshKeys => BackupSensitivity::Public,
            BackupComponent::Luks2Header
            | BackupComponent::RecoveryMaterial
            | BackupComponent::SshPrivateKeys
            | BackupComponent::SshHostKeys
            | BackupComponent::PamMapping => BackupSensitivity::Sensitive,
        };
        if self.sensitivity != expected_sensitivity {
            return Err(ValidationError::PolicyViolation(
                "backup entry sensitivity does not match its component",
            ));
        }
        if self.sensitivity == BackupSensitivity::Sensitive
            && self.mode != BackupFileMode::OwnerReadWrite
        {
            return Err(ValidationError::PolicyViolation(
                "sensitive backup entries must use mode 0600",
            ));
        }
        Ok(())
    }
}

/// Canonical public `manifest.json` schema for NKFB version 1.
///
/// Field declaration order is also the producer's canonical JSON field order.
/// The Age envelope and its recipients are intentionally not stored here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub format: BackupFormat,
    pub schema_version: u32,
    pub tool_version: VersionString,
    /// UTC RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
    pub created_at: String,
    pub profile: BackupClass,
    pub host: BackupHost,
    pub luks_volumes: Vec<LuksVolumeIdentity>,
    pub authenticators: Vec<ManifestAuthenticator>,
    pub entries: Vec<BackupEntry>,
}

impl fmt::Debug for BackupManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupManifest")
            .field("format", &self.format)
            .field("schema_version", &self.schema_version)
            .field("tool_version", &self.tool_version)
            .field("created_at", &self.created_at)
            .field("profile", &self.profile)
            .field("host", &self.host)
            .field("luks_volumes", &self.luks_volumes)
            .field("authenticators", &self.authenticators)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl BackupManifest {
    pub fn validate(
        &self,
        policy: &BackupPolicy,
        encryption: &EncryptionMethod,
    ) -> Result<(), ValidationError> {
        policy.validate()?;
        encryption.validate()?;
        if self.format != BackupFormat::NixKeyforgeBackup {
            return Err(ValidationError::PolicyViolation(
                "unsupported backup format",
            ));
        }
        if self.schema_version != BACKUP_SCHEMA_VERSION {
            return Err(ValidationError::PolicyViolation(
                "unsupported backup schema version",
            ));
        }
        if self.profile != policy.profile {
            return Err(ValidationError::PolicyViolation(
                "manifest backup profile does not match policy",
            ));
        }
        validate_timestamp(&self.created_at)?;
        if policy.encryption_required && !encryption.is_authenticated_encryption() {
            return Err(ValidationError::PolicyViolation(
                "every NKFB profile requires authenticated encryption",
            ));
        }
        if self.entries.is_empty() {
            return Err(ValidationError::PolicyViolation(
                "a backup manifest must contain at least one entry",
            ));
        }

        let mut authenticator_roles = BTreeSet::new();
        for authenticator in &self.authenticators {
            if !authenticator_roles.insert(authenticator.role) {
                return Err(ValidationError::PolicyViolation(
                    "duplicate authenticator roles are forbidden",
                ));
            }
        }
        if self.luks_volumes.iter().collect::<BTreeSet<_>>().len() != self.luks_volumes.len() {
            return Err(ValidationError::PolicyViolation(
                "duplicate LUKS volume identities are forbidden",
            ));
        }

        let mut paths = BTreeSet::new();
        let mut total_size = 0_u64;
        let mut previous_path: Option<&ArchivePath> = None;
        for entry in &self.entries {
            entry.validate_metadata()?;
            if !paths.insert(&entry.path) {
                return Err(ValidationError::DuplicateArchivePath);
            }
            if previous_path.is_some_and(|previous| previous >= &entry.path) {
                return Err(ValidationError::PolicyViolation(
                    "manifest entries must be sorted lexicographically by path",
                ));
            }
            previous_path = Some(&entry.path);
            if !policy.allowed_components.contains(&entry.component) {
                return Err(ValidationError::PolicyViolation(
                    "backup component is not allowed by policy",
                ));
            }
            if entry.length > policy.max_entry_size {
                return Err(ValidationError::PolicyViolation(
                    "backup entry exceeds the configured size limit",
                ));
            }
            total_size =
                total_size
                    .checked_add(entry.length)
                    .ok_or(ValidationError::PolicyViolation(
                        "backup total size overflow",
                    ))?;
            if !policy
                .restore_prefix_allowlist
                .iter()
                .any(|prefix| entry.path.starts_with(prefix))
            {
                return Err(ValidationError::PolicyViolation(
                    "backup entry is outside the restore allowlist",
                ));
            }
        }
        if total_size > policy.max_total_size {
            return Err(ValidationError::PolicyViolation(
                "backup exceeds the configured total size limit",
            ));
        }

        let has_luks_header = self
            .entries
            .iter()
            .any(|entry| entry.component == BackupComponent::Luks2Header);
        if has_luks_header && self.luks_volumes.len() != 1 {
            return Err(ValidationError::PolicyViolation(
                "a LUKS2 header requires exactly one declared volume identity",
            ));
        }
        if let Some(expected) = &policy.expected_luks_volumes {
            let actual: BTreeSet<_> = self.luks_volumes.iter().cloned().collect();
            if &actual != expected {
                return Err(ValidationError::PolicyViolation(
                    "backup LUKS identities do not match the expected target",
                ));
            }
        }
        Ok(())
    }
}

fn validate_timestamp(value: &str) -> Result<(), ValidationError> {
    if value.len() != 20
        || !value.is_ascii()
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
        || !value.ends_with('Z')
    {
        return Err(ValidationError::InvalidFormat {
            field: "backup creation timestamp",
        });
    }
    for (index, byte) in value.bytes().enumerate() {
        if !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit() {
            return Err(ValidationError::InvalidFormat {
                field: "backup creation timestamp",
            });
        }
    }
    let number = |start: usize, end: usize| -> u32 {
        value.as_bytes()[start..end]
            .iter()
            .fold(0, |result, byte| result * 10 + u32::from(byte - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let hour = number(11, 13);
    let minute = number(14, 16);
    let second = number(17, 19);
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 0,
    };
    if day == 0 || day > days_in_month || hour > 23 || minute > 59 || second > 60 {
        return Err(ValidationError::InvalidFormat {
            field: "backup creation timestamp",
        });
    }
    Ok(())
}

/// Profile, encryption, size, target identity, and extraction allowlist policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPolicy {
    pub profile: BackupClass,
    pub encryption_required: bool,
    pub allowed_components: BTreeSet<BackupComponent>,
    pub restore_prefix_allowlist: Vec<ArchivePath>,
    pub max_entry_size: u64,
    pub max_total_size: u64,
    pub expected_luks_volumes: Option<BTreeSet<LuksVolumeIdentity>>,
}

impl BackupPolicy {
    #[must_use]
    pub fn portable() -> Self {
        Self {
            profile: BackupClass::PortableConfiguration,
            encryption_required: true,
            allowed_components: [
                BackupComponent::Configuration,
                BackupComponent::GeneratedNixModules,
                BackupComponent::RedactedSystemInformation,
                BackupComponent::PamCredentialMetadata,
                BackupComponent::AuthenticatorRoles,
                BackupComponent::PublicSshKeys,
                BackupComponent::Checksums,
                BackupComponent::VerificationStatus,
            ]
            .into_iter()
            .collect(),
            restore_prefix_allowlist: vec![ArchivePath::trusted("components")],
            max_entry_size: 64 * 1024 * 1024,
            max_total_size: 256 * 1024 * 1024,
            expected_luks_volumes: None,
        }
    }

    #[must_use]
    pub fn sensitive_machine_recovery() -> Self {
        Self {
            profile: BackupClass::SensitiveMachineRecovery,
            encryption_required: true,
            allowed_components: [
                BackupComponent::Configuration,
                BackupComponent::GeneratedNixModules,
                BackupComponent::RedactedSystemInformation,
                BackupComponent::PamCredentialMetadata,
                BackupComponent::AuthenticatorRoles,
                BackupComponent::PublicSshKeys,
                BackupComponent::Checksums,
                BackupComponent::VerificationStatus,
                BackupComponent::Luks2Header,
                BackupComponent::RecoveryMaterial,
                BackupComponent::SshPrivateKeys,
                BackupComponent::SshHostKeys,
                BackupComponent::PamMapping,
            ]
            .into_iter()
            .collect(),
            restore_prefix_allowlist: vec![ArchivePath::trusted("components")],
            max_entry_size: 1024 * 1024 * 1024,
            max_total_size: 4 * 1024 * 1024 * 1024,
            expected_luks_volumes: None,
        }
    }

    #[must_use]
    pub fn with_expected_luks_volume(mut self, expected: LuksVolumeIdentity) -> Self {
        self.expected_luks_volumes = Some([expected].into_iter().collect());
        self
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if !self.encryption_required {
            return Err(ValidationError::PolicyViolation(
                "every NKFB profile must require authenticated encryption",
            ));
        }
        if self.profile == BackupClass::PortableConfiguration
            && self
                .allowed_components
                .iter()
                .any(|component| component.is_sensitive())
        {
            return Err(ValidationError::PolicyViolation(
                "portable backup policy cannot allow sensitive components",
            ));
        }
        if self.restore_prefix_allowlist.is_empty() {
            return Err(ValidationError::PolicyViolation(
                "restore prefix allowlist must not be empty",
            ));
        }
        if self
            .restore_prefix_allowlist
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != self.restore_prefix_allowlist.len()
        {
            return Err(ValidationError::PolicyViolation(
                "duplicate restore allowlist prefixes are forbidden",
            ));
        }
        if self.max_entry_size == 0
            || self.max_total_size == 0
            || self.max_entry_size > self.max_total_size
        {
            return Err(ValidationError::PolicyViolation(
                "backup size limits are invalid",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn id(domain: &'static str, value: &str) -> RedactedIdentifier {
        RedactedIdentifier::new(domain, value.as_bytes()).unwrap()
    }

    fn encryption() -> EncryptionMethod {
        EncryptionMethod::AgeRecipients {
            recipient_ids: vec![id("age-recipient", "age1synthetic")],
        }
    }

    fn entry(path: &str, component: BackupComponent) -> BackupEntry {
        BackupEntry {
            component,
            path: ArchivePath::new(path).unwrap(),
            media_type: BackupMediaType::Json,
            length: u64::try_from(path.len()).unwrap(),
            sha256: Sha256Digest::of_bytes(path.as_bytes()),
            mode: BackupFileMode::OwnerReadWrite,
            sensitivity: match component {
                BackupComponent::Configuration | BackupComponent::GeneratedNixModules => {
                    BackupSensitivity::Configuration
                }
                BackupComponent::RedactedSystemInformation
                | BackupComponent::PamCredentialMetadata
                | BackupComponent::AuthenticatorRoles
                | BackupComponent::Checksums
                | BackupComponent::VerificationStatus => BackupSensitivity::Metadata,
                BackupComponent::PublicSshKeys => BackupSensitivity::Public,
                _ => BackupSensitivity::Sensitive,
            },
        }
    }

    fn volume(uuid: &str) -> LuksVolumeIdentity {
        LuksVolumeIdentity {
            uuid: LuksUuid::new(uuid).unwrap(),
            role: LuksVolumeRole::Root,
        }
    }

    fn portable_manifest() -> BackupManifest {
        BackupManifest {
            format: BackupFormat::NixKeyforgeBackup,
            schema_version: BACKUP_SCHEMA_VERSION,
            tool_version: VersionString::new("0.1.0").unwrap(),
            created_at: "2026-07-27T08:00:00Z".to_owned(),
            profile: BackupClass::PortableConfiguration,
            host: BackupHost {
                redacted_id: id("host", "test-host"),
            },
            luks_volumes: Vec::new(),
            authenticators: vec![
                ManifestAuthenticator {
                    role: AuthenticatorRole::Primary,
                    redacted_id: id("authenticator", "primary"),
                    verification: ManifestVerification::Verified,
                },
                ManifestAuthenticator {
                    role: AuthenticatorRole::Backup,
                    redacted_id: id("authenticator", "backup"),
                    verification: ManifestVerification::ManualTestPending,
                },
            ],
            entries: vec![entry(
                "components/configuration/nixkeyforge.json",
                BackupComponent::Configuration,
            )],
        }
    }

    #[test]
    fn portable_manifest_requires_and_accepts_age_encryption() {
        let manifest = portable_manifest();
        assert!(
            manifest
                .validate(&BackupPolicy::portable(), &EncryptionMethod::None)
                .is_err()
        );
        manifest
            .validate(&BackupPolicy::portable(), &encryption())
            .unwrap();
    }

    #[test]
    fn portable_backup_rejects_sensitive_components() {
        let mut manifest = portable_manifest();
        manifest.entries = vec![entry(
            "components/luks2-header/header.bin",
            BackupComponent::Luks2Header,
        )];
        assert!(
            manifest
                .validate(&BackupPolicy::portable(), &encryption())
                .is_err()
        );
    }

    #[test]
    fn sensitive_backup_requires_encryption_and_exact_volume() {
        let expected = volume("00000000-0000-4000-8000-000000000001");
        let mut manifest = portable_manifest();
        manifest.profile = BackupClass::SensitiveMachineRecovery;
        manifest.entries = vec![entry(
            "components/luks2-header/header.bin",
            BackupComponent::Luks2Header,
        )];
        manifest.luks_volumes = vec![expected.clone()];
        let policy = BackupPolicy::sensitive_machine_recovery().with_expected_luks_volume(expected);
        assert!(manifest.validate(&policy, &EncryptionMethod::None).is_err());
        manifest.validate(&policy, &encryption()).unwrap();
    }

    #[test]
    fn duplicate_and_unsorted_paths_are_rejected() {
        let mut duplicate = portable_manifest();
        duplicate.entries.push(duplicate.entries[0].clone());
        assert_eq!(
            duplicate.validate(&BackupPolicy::portable(), &encryption()),
            Err(ValidationError::DuplicateArchivePath)
        );

        let mut unsorted = portable_manifest();
        unsorted.entries = vec![
            entry(
                "components/configuration/z.json",
                BackupComponent::Configuration,
            ),
            entry(
                "components/configuration/a.json",
                BackupComponent::Configuration,
            ),
        ];
        assert!(
            unsorted
                .validate(&BackupPolicy::portable(), &encryption())
                .is_err()
        );
    }

    #[test]
    fn manipulated_checksum_is_rejected() {
        let content = b"expected contents";
        let entry = BackupEntry {
            component: BackupComponent::Configuration,
            path: ArchivePath::new("components/configuration/test").unwrap(),
            media_type: BackupMediaType::Json,
            length: u64::try_from(content.len()).unwrap(),
            sha256: Sha256Digest::of_bytes(content),
            mode: BackupFileMode::OwnerReadWrite,
            sensitivity: BackupSensitivity::Configuration,
        };
        entry.verify_content(content).unwrap();
        assert!(entry.verify_content(b"modified contents").is_err());
    }

    #[test]
    fn wrong_luks_uuid_and_schema_are_rejected() {
        let expected = volume("00000000-0000-4000-8000-000000000001");
        let wrong = volume("00000000-0000-4000-8000-000000000002");
        let mut manifest = portable_manifest();
        manifest.profile = BackupClass::SensitiveMachineRecovery;
        manifest.luks_volumes = vec![wrong];
        manifest.entries = vec![entry(
            "components/luks2-header/header.bin",
            BackupComponent::Luks2Header,
        )];
        let policy = BackupPolicy::sensitive_machine_recovery().with_expected_luks_volume(expected);
        assert!(manifest.validate(&policy, &encryption()).is_err());

        manifest.schema_version = BACKUP_SCHEMA_VERSION + 1;
        assert!(manifest.validate(&policy, &encryption()).is_err());
    }

    #[test]
    fn mutated_unencrypted_or_sensitive_portable_policies_are_rejected() {
        let mut portable = BackupPolicy::portable();
        portable.encryption_required = false;
        assert!(portable.validate().is_err());

        portable.encryption_required = true;
        portable
            .allowed_components
            .insert(BackupComponent::RecoveryMaterial);
        assert!(portable.validate().is_err());
    }

    #[test]
    fn invalid_calendar_timestamp_is_rejected() {
        let mut manifest = portable_manifest();
        manifest.created_at = "2026-02-30T08:00:00Z".to_owned();
        assert!(
            manifest
                .validate(&BackupPolicy::portable(), &encryption())
                .is_err()
        );
    }

    #[test]
    fn archive_layout_rejects_all_non_regular_types_and_duplicate_manifests() {
        let manifest = ArchiveMember {
            path: ArchivePath::new(MANIFEST_PATH).unwrap(),
            kind: ArchiveEntryKind::RegularFile,
        };
        validate_archive_members(std::slice::from_ref(&manifest)).unwrap();

        for kind in [
            ArchiveEntryKind::Directory,
            ArchiveEntryKind::Symlink,
            ArchiveEntryKind::Hardlink,
            ArchiveEntryKind::DeviceNode,
            ArchiveEntryKind::Fifo,
            ArchiveEntryKind::Socket,
            ArchiveEntryKind::SparseFile,
            ArchiveEntryKind::ExtendedHeader,
            ArchiveEntryKind::Other,
        ] {
            let members = [
                manifest.clone(),
                ArchiveMember {
                    path: ArchivePath::new("components/configuration/attack").unwrap(),
                    kind,
                },
            ];
            assert!(validate_archive_members(&members).is_err());
        }
        assert!(validate_archive_members(&[manifest.clone(), manifest]).is_err());
    }

    #[test]
    fn manifest_json_is_canonical_and_never_contains_raw_authenticator_ids() {
        let mut manifest = portable_manifest();
        let authenticator_canary = "actual-authenticator-serial";
        let host_canary = "actual-host-machine-id";
        let luks_canary = "00000000-0000-4000-8000-00000000cafe";
        manifest.authenticators[0].redacted_id = id("authenticator", authenticator_canary);
        manifest.host.redacted_id = id("host", host_canary);
        manifest.luks_volumes = vec![volume(luks_canary)];
        let json = serde_json::to_string(&manifest).unwrap();
        let debug = format!("{manifest:?}");
        assert!(json.starts_with("{\"format\":\"nixkeyforge-backup\",\"schema_version\":1,"));
        assert!(json.contains("\"profile\":\"portable-configuration\""));
        assert!(json.contains(luks_canary));
        for canary in [authenticator_canary, host_canary] {
            assert!(!json.contains(canary));
            assert!(!debug.contains(canary));
        }
        assert!(!debug.contains(luks_canary));
        assert!(!debug.contains("components/configuration/nixkeyforge.json"));
    }
}
