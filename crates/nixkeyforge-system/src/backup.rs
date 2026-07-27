use crate::apply::{ApplyConfirmation, ApplyMode};
use crate::luks::LuksUuid;
use crate::{RedactedId, sha256_hex};
use nixkeyforge_core::{
    ArchiveEntryKind, ArchiveMember, ArchivePath, BackupClass, BackupComponent, BackupFileMode,
    BackupManifest, BackupPolicy, EncryptionMethod, RedactedIdentifier, ValidationError,
    validate_archive_members,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroize;

pub use nixkeyforge_core::BACKUP_SCHEMA_VERSION;

const MAX_ARCHIVE_ENTRIES: usize = 4096;
const MAX_MANIFEST_SIZE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedArchiveKind {
    Regular,
    Directory,
    Symlink,
    Hardlink,
    CharacterDevice,
    BlockDevice,
    Fifo,
    Socket,
    ExtendedHeader,
    Sparse,
    Unknown,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ParsedArchiveEntry {
    pub path: String,
    pub kind: ParsedArchiveKind,
    pub mode: u32,
    data: Vec<u8>,
}

impl ParsedArchiveEntry {
    pub fn regular(path: impl Into<String>, data: impl Into<Vec<u8>>, mode: u32) -> Self {
        Self {
            path: path.into(),
            kind: ParsedArchiveKind::Regular,
            mode,
            data: data.into(),
        }
    }

    pub fn non_regular(path: impl Into<String>, kind: ParsedArchiveKind) -> Self {
        Self {
            path: path.into(),
            kind,
            mode: 0,
            data: Vec::new(),
        }
    }
}

impl fmt::Debug for ParsedArchiveEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedArchiveEntry")
            .field("path", &self.path)
            .field("kind", &self.kind)
            .field("mode", &format_args!("{:04o}", self.mode))
            .field("data", &"<redacted>")
            .field("size", &self.data.len())
            .finish()
    }
}

impl Drop for ParsedArchiveEntry {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedEnvelopeMode {
    AgeRecipients,
    InteractivePassphrase,
}

/// Evidence from the age adapter. Plaintext must not be passed to this module
/// until authenticated end-of-file has been reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedEnvelopeVerification {
    authenticated_encryption: bool,
    authentication_verified_through_eof: bool,
    mode: ParsedEnvelopeMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackupValidationError {
    UnauthenticatedEnvelope,
    TooManyEntries,
    ManifestTooLarge,
    InvalidPath,
    DuplicatePath,
    DuplicateManifest,
    MissingManifest,
    ManifestNotRegular,
    UnsupportedEntryType(ParsedArchiveKind),
    UnknownPath,
    InvalidManifest,
    IncompatibleSchema { found: u32 },
    LuksUuidMismatch,
    ChecksumMismatch,
    SizeMismatch,
    ManifestEntryMissing,
    UnmanifestedEntry,
    ComponentMismatch,
    InvalidMode,
    CorePolicy,
    ConfirmationRequired,
    StagingWriteFailed,
}

impl fmt::Display for BackupValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("backup or restore staging validation failed")
    }
}

impl std::error::Error for BackupValidationError {}

impl From<ValidationError> for BackupValidationError {
    fn from(_: ValidationError) -> Self {
        Self::CorePolicy
    }
}

/// Opaque, fixed staging categories. These are never live PAM, SSH, NixOS or
/// block-device destinations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StagingDestination {
    Configuration,
    GeneratedModule(String),
    RedactedMetadata {
        component: BackupComponent,
        name: String,
    },
    PublicSshKey(String),
    SensitivePamMapping,
    SensitiveLuksHeader,
    SensitiveRecoveryMaterial,
    SensitiveSshPrivateKey(String),
    SensitiveSshHostKey(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagingItem {
    pub source: String,
    pub destination: StagingDestination,
    pub mode: u32,
    pub requires_separate_live_recovery_runbook: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreStagingPlan {
    pub package_id: RedactedId,
    pub items: Vec<StagingItem>,
    pub staging_directory_mode: u32,
    pub exclusive_create_only: bool,
    pub writes_live_targets: bool,
    pub automatic_luks_header_restore: bool,
    pub fingerprint: String,
}

pub struct ValidatedParsedArchive {
    pub manifest: BackupManifest,
    plan: RestoreStagingPlan,
    payloads: BTreeMap<String, Vec<u8>>,
}

impl fmt::Debug for ValidatedParsedArchive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedParsedArchive")
            .field("manifest", &self.manifest)
            .field("plan", &self.plan)
            .field("payloads", &"<redacted>")
            .finish()
    }
}

impl ValidatedParsedArchive {
    pub fn staging_plan(&self) -> &RestoreStagingPlan {
        &self.plan
    }
}

impl Drop for ValidatedParsedArchive {
    fn drop(&mut self) {
        for payload in self.payloads.values_mut() {
            payload.zeroize();
        }
    }
}

pub fn validate_parsed_archive(
    entries: Vec<ParsedArchiveEntry>,
    envelope: ParsedEnvelopeVerification,
    expected_luks_uuid: Option<&LuksUuid>,
) -> Result<ValidatedParsedArchive, BackupValidationError> {
    if !envelope.authenticated_encryption || !envelope.authentication_verified_through_eof {
        return Err(BackupValidationError::UnauthenticatedEnvelope);
    }
    if entries.len() > MAX_ARCHIVE_ENTRIES {
        return Err(BackupValidationError::TooManyEntries);
    }
    let manifest_count = entries
        .iter()
        .filter(|entry| entry.path == nixkeyforge_core::MANIFEST_PATH)
        .count();
    if manifest_count > 1 {
        return Err(BackupValidationError::DuplicateManifest);
    }
    if manifest_count == 0 {
        return Err(BackupValidationError::MissingManifest);
    }

    let mut seen_paths = BTreeSet::new();
    let mut core_members = Vec::with_capacity(entries.len());
    for entry in &entries {
        let path =
            ArchivePath::new(entry.path.clone()).map_err(|_| BackupValidationError::InvalidPath)?;
        if !seen_paths.insert(path.clone()) {
            return Err(BackupValidationError::DuplicatePath);
        }
        let kind = match entry.kind {
            ParsedArchiveKind::Regular => ArchiveEntryKind::RegularFile,
            ParsedArchiveKind::Directory => ArchiveEntryKind::Directory,
            ParsedArchiveKind::Symlink => ArchiveEntryKind::Symlink,
            ParsedArchiveKind::Hardlink => ArchiveEntryKind::Hardlink,
            ParsedArchiveKind::CharacterDevice | ParsedArchiveKind::BlockDevice => {
                ArchiveEntryKind::DeviceNode
            }
            ParsedArchiveKind::Fifo
            | ParsedArchiveKind::Socket
            | ParsedArchiveKind::ExtendedHeader
            | ParsedArchiveKind::Sparse
            | ParsedArchiveKind::Unknown => ArchiveEntryKind::Other,
        };
        core_members.push(ArchiveMember { path, kind });
        if entry.kind != ParsedArchiveKind::Regular {
            return Err(BackupValidationError::UnsupportedEntryType(entry.kind));
        }
        if entry.path != nixkeyforge_core::MANIFEST_PATH {
            let _ = staging_destination_for(&entry.path)?;
        }
    }
    validate_archive_members(&core_members)?;

    let manifest_entry = entries
        .iter()
        .find(|entry| entry.path == nixkeyforge_core::MANIFEST_PATH)
        .ok_or(BackupValidationError::MissingManifest)?;
    if manifest_entry.kind != ParsedArchiveKind::Regular {
        return Err(BackupValidationError::ManifestNotRegular);
    }
    if manifest_entry.data.len() > MAX_MANIFEST_SIZE {
        return Err(BackupValidationError::ManifestTooLarge);
    }
    let manifest: BackupManifest = serde_json::from_slice(&manifest_entry.data)
        .map_err(|_| BackupValidationError::InvalidManifest)?;
    if manifest.schema_version != BACKUP_SCHEMA_VERSION {
        return Err(BackupValidationError::IncompatibleSchema {
            found: manifest.schema_version,
        });
    }
    validate_core_manifest(&manifest, expected_luks_uuid, envelope.mode)?;

    let mut manifest_entries = BTreeMap::new();
    for manifest_file in &manifest.entries {
        let path = manifest_file.path.as_str().to_owned();
        if manifest_entries.insert(path, manifest_file).is_some() {
            return Err(BackupValidationError::DuplicatePath);
        }
        let destination = staging_destination_for(manifest_file.path.as_str())?;
        if component_for_staging(&destination) != manifest_file.component {
            return Err(BackupValidationError::ComponentMismatch);
        }
        validate_component_mode(
            manifest_file.component,
            manifest_file.mode,
            manifest_file.path.as_str(),
            entries.as_slice(),
        )?;
    }

    let mut payloads = BTreeMap::new();
    let mut items = Vec::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.path != nixkeyforge_core::MANIFEST_PATH)
    {
        let manifest_file = manifest_entries
            .remove(&entry.path)
            .ok_or(BackupValidationError::UnmanifestedEntry)?;
        if manifest_file.length != entry.data.len() as u64 {
            return Err(BackupValidationError::SizeMismatch);
        }
        manifest_file
            .verify_content(&entry.data)
            .map_err(|_| BackupValidationError::ChecksumMismatch)?;
        let destination = staging_destination_for(&entry.path)?;
        let sensitive = manifest_file.component.is_sensitive();
        items.push(StagingItem {
            source: entry.path.clone(),
            destination,
            mode: if sensitive { 0o600 } else { entry.mode },
            requires_separate_live_recovery_runbook: sensitive,
        });
        payloads.insert(entry.path.clone(), entry.data.clone());
    }
    if !manifest_entries.is_empty() {
        return Err(BackupValidationError::ManifestEntryMissing);
    }
    items.sort_by(|left, right| left.source.cmp(&right.source));
    let package_id = RedactedId::from_sensitive(&manifest_entry.data);
    let fingerprint = sha256_hex(
        format!(
            "{}|{}|{}",
            package_id,
            manifest.schema_version,
            items
                .iter()
                .map(|item| item.source.as_str())
                .collect::<Vec<_>>()
                .join("|")
        )
        .as_bytes(),
    );
    Ok(ValidatedParsedArchive {
        manifest,
        plan: RestoreStagingPlan {
            package_id,
            items,
            staging_directory_mode: 0o700,
            exclusive_create_only: true,
            writes_live_targets: false,
            automatic_luks_header_restore: false,
            fingerprint,
        },
        payloads,
    })
}

fn validate_core_manifest(
    manifest: &BackupManifest,
    expected_luks_uuid: Option<&LuksUuid>,
    envelope_mode: ParsedEnvelopeMode,
) -> Result<(), BackupValidationError> {
    let policy = match manifest.profile {
        BackupClass::PortableConfiguration => BackupPolicy::portable(),
        BackupClass::SensitiveMachineRecovery => BackupPolicy::sensitive_machine_recovery(),
    };
    if let Some(expected) = expected_luks_uuid
        && (manifest.luks_volumes.len() != 1
            || manifest.luks_volumes[0].uuid.expose_for_identity_check() != expected.as_str())
    {
        return Err(BackupValidationError::LuksUuidMismatch);
    }
    let encryption = match envelope_mode {
        ParsedEnvelopeMode::AgeRecipients => EncryptionMethod::AgeRecipients {
            recipient_ids: vec![
                RedactedIdentifier::new("age-envelope", b"authenticated-recipient")
                    .map_err(|_| BackupValidationError::CorePolicy)?,
            ],
        },
        ParsedEnvelopeMode::InteractivePassphrase => EncryptionMethod::InteractivePassphrase,
    };
    manifest
        .validate(&policy, &encryption)
        .map_err(|_| BackupValidationError::CorePolicy)
}

fn safe_file_name(value: &str, suffix: &str) -> bool {
    value.ends_with(suffix)
        && value.len() > suffix.len()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn one_level_name<'a>(path: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let name = path.strip_prefix(prefix)?;
    (!name.contains('/') && safe_file_name(name, suffix)).then_some(name)
}

fn staging_destination_for(path: &str) -> Result<StagingDestination, BackupValidationError> {
    if path == "components/configuration/nixkeyforge.toml" {
        return Ok(StagingDestination::Configuration);
    }
    if let Some(name) = one_level_name(path, "components/generated-nix/", ".nix") {
        return Ok(StagingDestination::GeneratedModule(name.to_owned()));
    }
    for (prefix, component) in [
        (
            "components/redacted-system-information/",
            BackupComponent::RedactedSystemInformation,
        ),
        (
            "components/pam-credential-metadata/",
            BackupComponent::PamCredentialMetadata,
        ),
        (
            "components/authenticator-roles/",
            BackupComponent::AuthenticatorRoles,
        ),
        ("components/checksums/", BackupComponent::Checksums),
        (
            "components/verification-status/",
            BackupComponent::VerificationStatus,
        ),
    ] {
        if let Some(name) = one_level_name(path, prefix, ".json") {
            return Ok(StagingDestination::RedactedMetadata {
                component,
                name: name.to_owned(),
            });
        }
    }
    if let Some(name) = one_level_name(path, "components/public-ssh-key/", ".pub") {
        return Ok(StagingDestination::PublicSshKey(name.to_owned()));
    }
    if let Some(name) = one_level_name(path, "components/ssh-private-key/", ".key") {
        return Ok(StagingDestination::SensitiveSshPrivateKey(name.to_owned()));
    }
    if let Some(name) = one_level_name(path, "components/ssh-host-key/", ".key") {
        return Ok(StagingDestination::SensitiveSshHostKey(name.to_owned()));
    }
    match path {
        "components/pam-mapping/u2f-mapping" => Ok(StagingDestination::SensitivePamMapping),
        "components/luks2-header/header.bin" => Ok(StagingDestination::SensitiveLuksHeader),
        "components/recovery-material/recovery.age" => {
            Ok(StagingDestination::SensitiveRecoveryMaterial)
        }
        _ => Err(BackupValidationError::UnknownPath),
    }
}

fn component_for_staging(destination: &StagingDestination) -> BackupComponent {
    match destination {
        StagingDestination::Configuration => BackupComponent::Configuration,
        StagingDestination::GeneratedModule(_) => BackupComponent::GeneratedNixModules,
        StagingDestination::RedactedMetadata { component, .. } => *component,
        StagingDestination::PublicSshKey(_) => BackupComponent::PublicSshKeys,
        StagingDestination::SensitivePamMapping => BackupComponent::PamMapping,
        StagingDestination::SensitiveLuksHeader => BackupComponent::Luks2Header,
        StagingDestination::SensitiveRecoveryMaterial => BackupComponent::RecoveryMaterial,
        StagingDestination::SensitiveSshPrivateKey(_) => BackupComponent::SshPrivateKeys,
        StagingDestination::SensitiveSshHostKey(_) => BackupComponent::SshHostKeys,
    }
}

fn validate_component_mode(
    component: BackupComponent,
    declared_mode: BackupFileMode,
    path: &str,
    entries: &[ParsedArchiveEntry],
) -> Result<(), BackupValidationError> {
    let actual = entries
        .iter()
        .find(|entry| entry.path == path)
        .ok_or(BackupValidationError::ManifestEntryMissing)?
        .mode;
    let expected = match component {
        BackupComponent::PublicSshKeys => 0o644,
        _ => 0o600,
    };
    if actual != expected {
        return Err(BackupValidationError::InvalidMode);
    }
    let expected_manifest_mode = if expected == 0o644 {
        BackupFileMode::ReadOnlyPublic
    } else {
        BackupFileMode::OwnerReadWrite
    };
    if declared_mode != expected_manifest_mode {
        return Err(BackupValidationError::InvalidMode);
    }
    Ok(())
}

/// Writes only into a newly created, unprivileged 0700 staging directory. An
/// implementation must map the enum to generated opaque names, use exclusive
/// creation, and must never interpret archive paths as filesystem paths.
pub trait StagingWriter: Send + Sync {
    fn stage_exclusive(
        &self,
        destination: &StagingDestination,
        content: &[u8],
        mode: u32,
    ) -> Result<(), BackupValidationError>;
}

#[derive(Debug, Default)]
pub struct MockStagingWriter {
    writes: Mutex<Vec<(StagingDestination, usize, u32)>>,
}

impl MockStagingWriter {
    pub fn writes(&self) -> Vec<(StagingDestination, usize, u32)> {
        lock_unpoison(&self.writes).clone()
    }
}

impl StagingWriter for MockStagingWriter {
    fn stage_exclusive(
        &self,
        destination: &StagingDestination,
        content: &[u8],
        mode: u32,
    ) -> Result<(), BackupValidationError> {
        lock_unpoison(&self.writes).push((destination.clone(), content.len(), mode));
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreStagingResult {
    DryRun(RestoreStagingPlan),
    Staged { files: usize },
}

pub fn apply_restore_to_staging(
    archive: &ValidatedParsedArchive,
    writer: &dyn StagingWriter,
    mode: &ApplyMode,
) -> Result<RestoreStagingResult, BackupValidationError> {
    let ApplyMode::Confirmed(ApplyConfirmation {
        plan_fingerprint,
        interactive_phrase_matched: true,
        preconditions_revalidated: true,
    }) = mode
    else {
        if matches!(mode, ApplyMode::DryRun) {
            return Ok(RestoreStagingResult::DryRun(archive.plan.clone()));
        }
        return Err(BackupValidationError::ConfirmationRequired);
    };
    if plan_fingerprint != &archive.plan.fingerprint {
        return Err(BackupValidationError::ConfirmationRequired);
    }
    for item in &archive.plan.items {
        let content = archive
            .payloads
            .get(&item.source)
            .ok_or(BackupValidationError::ManifestEntryMissing)?;
        writer.stage_exclusive(&item.destination, content, item.mode)?;
    }
    Ok(RestoreStagingResult::Staged {
        files: archive.plan.items.len(),
    })
}

#[derive(Clone, Eq, PartialEq)]
pub struct BackupOutputPath(PathBuf);

impl BackupOutputPath {
    pub fn parse(path: &Path) -> Result<Self, BackupValidationError> {
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::CurDir | Component::Prefix(_)
                )
            })
            || path.file_name().is_none()
        {
            return Err(BackupValidationError::InvalidPath);
        }
        Ok(Self(path.to_path_buf()))
    }
}

impl fmt::Debug for BackupOutputPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BackupOutputPath(<redacted>)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCreatePlan {
    pub output: BackupOutputPath,
    pub directory_mode: u32,
    pub file_mode: u32,
    pub atomic_write: bool,
    pub authenticated_encryption: bool,
    pub components: BTreeSet<BackupComponent>,
}

impl BackupCreatePlan {
    pub fn new(
        output: BackupOutputPath,
        components: impl IntoIterator<Item = BackupComponent>,
    ) -> Self {
        Self {
            output,
            directory_mode: 0o700,
            file_mode: 0o600,
            atomic_write: true,
            authenticated_encryption: true,
            components: components.into_iter().collect(),
        }
    }
}

fn lock_unpoison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nixkeyforge_core::{
        BackupEntry, BackupFileMode, BackupFormat, BackupHost, BackupMediaType, BackupSensitivity,
        Sha256Digest, VersionString,
    };

    const LUKS_UUID: &str = "11111111-2222-3333-4444-555555555555";

    fn envelope() -> ParsedEnvelopeVerification {
        ParsedEnvelopeVerification {
            authenticated_encryption: true,
            authentication_verified_through_eof: true,
            mode: ParsedEnvelopeMode::AgeRecipients,
        }
    }

    fn valid_entries() -> Result<Vec<ParsedArchiveEntry>, Box<dyn std::error::Error>> {
        let payload = b"[policy]\ndry_run = true\n".to_vec();
        let host_id = RedactedIdentifier::new("host", b"synthetic-host")?;
        let manifest = BackupManifest {
            format: BackupFormat::NixKeyforgeBackup,
            schema_version: BACKUP_SCHEMA_VERSION,
            tool_version: VersionString::new("0.1.0")?,
            created_at: "2030-01-01T00:00:00Z".into(),
            profile: BackupClass::PortableConfiguration,
            host: BackupHost {
                redacted_id: host_id,
            },
            luks_volumes: Vec::new(),
            authenticators: Vec::new(),
            entries: vec![BackupEntry {
                path: ArchivePath::new("components/configuration/nixkeyforge.toml")?,
                sha256: Sha256Digest::of_bytes(&payload),
                length: payload.len() as u64,
                component: BackupComponent::Configuration,
                media_type: BackupMediaType::PlainText,
                mode: BackupFileMode::OwnerReadWrite,
                sensitivity: BackupSensitivity::Configuration,
            }],
        };
        Ok(vec![
            ParsedArchiveEntry::regular(
                nixkeyforge_core::MANIFEST_PATH,
                serde_json::to_vec(&manifest)?,
                0o600,
            ),
            ParsedArchiveEntry::regular(
                "components/configuration/nixkeyforge.toml",
                payload,
                0o600,
            ),
        ])
    }

    #[test]
    fn valid_archive_produces_staging_only_plan() -> Result<(), Box<dyn std::error::Error>> {
        let validated = validate_parsed_archive(valid_entries()?, envelope(), None)?;
        assert_eq!(validated.staging_plan().items.len(), 1);
        assert!(!validated.staging_plan().writes_live_targets);
        assert!(!validated.staging_plan().automatic_luks_header_restore);
        Ok(())
    }

    #[test]
    fn rejects_parent_and_absolute_paths() -> Result<(), Box<dyn std::error::Error>> {
        for path in ["../../etc/shadow", "/etc/shadow", r"..\..\etc\shadow"] {
            let mut entries = valid_entries()?;
            entries.push(ParsedArchiveEntry::regular(path, b"attack".to_vec(), 0o600));
            assert!(matches!(
                validate_parsed_archive(entries, envelope(), None),
                Err(BackupValidationError::InvalidPath)
            ));
        }
        Ok(())
    }

    #[test]
    fn rejects_symlinks_hardlinks_and_devices() -> Result<(), Box<dyn std::error::Error>> {
        for kind in [
            ParsedArchiveKind::Symlink,
            ParsedArchiveKind::Hardlink,
            ParsedArchiveKind::CharacterDevice,
            ParsedArchiveKind::BlockDevice,
        ] {
            let mut entries = valid_entries()?;
            entries.push(ParsedArchiveEntry::non_regular("configuration/evil", kind));
            assert!(matches!(
                validate_parsed_archive(entries, envelope(), None),
                Err(BackupValidationError::UnsupportedEntryType(found)) if found == kind
            ));
        }
        Ok(())
    }

    #[test]
    fn rejects_duplicate_manifest() -> Result<(), Box<dyn std::error::Error>> {
        let mut entries = valid_entries()?;
        let duplicate = entries
            .first()
            .cloned()
            .ok_or("test fixture must contain a manifest")?;
        entries.push(duplicate);
        assert!(matches!(
            validate_parsed_archive(entries, envelope(), None),
            Err(BackupValidationError::DuplicateManifest)
        ));
        Ok(())
    }

    #[test]
    fn rejects_manipulated_checksum() -> Result<(), Box<dyn std::error::Error>> {
        let mut entries = valid_entries()?;
        let payload = entries
            .get_mut(1)
            .ok_or("test fixture must contain a payload")?;
        payload.data.push(0);
        assert!(matches!(
            validate_parsed_archive(entries, envelope(), None),
            Err(BackupValidationError::SizeMismatch)
        ));
        Ok(())
    }

    #[test]
    fn rejects_wrong_luks_uuid() -> Result<(), Box<dyn std::error::Error>> {
        let expected = LuksUuid::parse(LUKS_UUID).map_err(|_| "valid synthetic UUID")?;
        assert!(matches!(
            validate_parsed_archive(valid_entries()?, envelope(), Some(&expected)),
            Err(BackupValidationError::LuksUuidMismatch)
        ));
        Ok(())
    }

    #[test]
    fn rejects_incompatible_schema() -> Result<(), Box<dyn std::error::Error>> {
        let mut entries = valid_entries()?;
        let manifest_entry = entries
            .first_mut()
            .ok_or("test fixture must contain a manifest")?;
        let mut manifest: serde_json::Value = serde_json::from_slice(&manifest_entry.data)?;
        manifest["schema_version"] = serde_json::Value::from(99);
        manifest_entry.data = serde_json::to_vec(&manifest)?;
        assert!(matches!(
            validate_parsed_archive(entries, envelope(), None),
            Err(BackupValidationError::IncompatibleSchema { found: 99 })
        ));
        Ok(())
    }

    #[test]
    fn rejects_unauthenticated_input_before_manifest_parsing()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut untrusted = envelope();
        untrusted.authentication_verified_through_eof = false;
        assert!(matches!(
            validate_parsed_archive(valid_entries()?, untrusted, None),
            Err(BackupValidationError::UnauthenticatedEnvelope)
        ));
        Ok(())
    }

    #[test]
    fn restore_is_dry_run_and_only_stages() -> Result<(), Box<dyn std::error::Error>> {
        let archive = validate_parsed_archive(valid_entries()?, envelope(), None)?;
        let writer = MockStagingWriter::default();
        assert!(matches!(
            apply_restore_to_staging(&archive, &writer, &ApplyMode::default())?,
            RestoreStagingResult::DryRun(_)
        ));
        assert!(writer.writes().is_empty());
        Ok(())
    }

    #[test]
    fn manifest_parser_does_not_panic_on_synthetic_inputs() {
        for length in 0..1024 {
            let input = (0..length)
                .map(|index| ((index * 17 + length) % 256) as u8)
                .collect::<Vec<_>>();
            let _: Result<BackupManifest, _> = serde_json::from_slice(&input);
        }
    }
}
