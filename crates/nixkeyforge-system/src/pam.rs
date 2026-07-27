use crate::apply::ApplyMode;
use crate::fs::{
    AtomicWriter, FileInspector, FileSecurityError, validate_secure_file, validate_secure_parent,
};
use crate::{AuthenticatorRole, RedactedId, sha256_hex};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const MAX_MAPPING_BYTES: usize = 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub struct PamCredential(String);

impl PamCredential {
    pub fn parse(value: &str) -> Result<Self, PamMappingError> {
        if value.is_empty()
            || value.len() > MAX_CREDENTIAL_BYTES
            || value.split(',').count() < 2
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b',' | b'+' | b'/' | b'=' | b'_' | b'-')
            })
        {
            return Err(PamMappingError::InvalidCredential);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn redacted_id(&self) -> RedactedId {
        RedactedId::from_sensitive(self.0.as_bytes())
    }
}

impl fmt::Debug for PamCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PamCredential")
            .field(&self.redacted_id())
            .finish()
    }
}

impl Drop for PamCredential {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PamMappingError {
    TooLarge,
    InvalidUtf8,
    InvalidUsername,
    InvalidCredential,
    InvalidLine { line: usize },
    DuplicateUserLine,
    DuplicateCredential,
    AlreadyPresent,
    FileSecurity(FileSecurityError),
    ConfirmationRequired,
    LiveApplyDisabled,
}

impl fmt::Display for PamMappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PAM mapping validation or update failed")
    }
}

impl std::error::Error for PamMappingError {}

impl From<FileSecurityError> for PamMappingError {
    fn from(value: FileSecurityError) -> Self {
        Self::FileSecurity(value)
    }
}

#[derive(Clone, Eq, PartialEq)]
struct MappingEntry {
    username: String,
    credentials: Vec<PamCredential>,
}

impl fmt::Debug for MappingEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MappingEntry")
            .field(
                "username",
                &RedactedId::from_sensitive(self.username.as_bytes()),
            )
            .field("credentials", &self.credentials)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
enum MappingLine {
    Blank,
    Comment(String),
    Entry(MappingEntry),
}

impl fmt::Debug for MappingLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blank => formatter.write_str("Blank"),
            Self::Comment(_) => formatter.write_str("Comment(<redacted>)"),
            Self::Entry(entry) => entry.fmt(formatter),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PamMappingDocument {
    lines: Vec<MappingLine>,
    trailing_newline: bool,
}

impl fmt::Debug for PamMappingDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PamMappingDocument")
            .field("lines", &self.lines)
            .field("trailing_newline", &self.trailing_newline)
            .finish()
    }
}

impl PamMappingDocument {
    pub fn parse(bytes: &[u8]) -> Result<Self, PamMappingError> {
        if bytes.len() > MAX_MAPPING_BYTES {
            return Err(PamMappingError::TooLarge);
        }
        let input = std::str::from_utf8(bytes).map_err(|_| PamMappingError::InvalidUtf8)?;
        let trailing_newline = input.ends_with('\n');
        let mut lines = Vec::new();
        for (index, raw) in input.lines().enumerate() {
            let raw = raw.strip_suffix('\r').unwrap_or(raw);
            if raw.is_empty() {
                lines.push(MappingLine::Blank);
            } else if raw.starts_with('#') {
                lines.push(MappingLine::Comment(raw.to_owned()));
            } else {
                let mut fields = raw.split(':');
                let username = fields.next().unwrap_or_default();
                validate_username(username)?;
                let credentials = fields
                    .map(PamCredential::parse)
                    .collect::<Result<Vec<_>, _>>()?;
                if credentials.is_empty() {
                    return Err(PamMappingError::InvalidLine { line: index + 1 });
                }
                let unique = credentials
                    .iter()
                    .map(PamCredential::redacted_id)
                    .collect::<BTreeSet<_>>();
                if unique.len() != credentials.len() {
                    return Err(PamMappingError::DuplicateCredential);
                }
                lines.push(MappingLine::Entry(MappingEntry {
                    username: username.to_owned(),
                    credentials,
                }));
            }
        }
        Ok(Self {
            lines,
            trailing_newline,
        })
    }

    pub fn empty() -> Self {
        Self {
            lines: Vec::new(),
            trailing_newline: true,
        }
    }

    pub fn inventory(&self) -> PamInventory {
        let mut users = Vec::new();
        let mut seen = BTreeMap::<&str, usize>::new();
        for line in &self.lines {
            if let MappingLine::Entry(entry) = line {
                *seen.entry(&entry.username).or_default() += 1;
                users.push(PamUserInventory {
                    user_id: RedactedId::from_sensitive(entry.username.as_bytes()),
                    credential_ids: entry
                        .credentials
                        .iter()
                        .map(PamCredential::redacted_id)
                        .collect(),
                });
            }
        }
        PamInventory {
            users,
            duplicate_user_lines: seen.values().filter(|count| **count > 1).count(),
        }
    }

    fn add(&mut self, username: &str, credential: PamCredential) -> Result<(), PamMappingError> {
        validate_username(username)?;
        let matching = self
            .lines
            .iter_mut()
            .filter_map(|line| match line {
                MappingLine::Entry(entry) if entry.username == username => Some(entry),
                _ => None,
            })
            .collect::<Vec<_>>();
        if matching.len() > 1 {
            return Err(PamMappingError::DuplicateUserLine);
        }
        if let Some(entry) = matching.into_iter().next() {
            if entry.credentials.contains(&credential) {
                return Err(PamMappingError::AlreadyPresent);
            }
            entry.credentials.push(credential);
        } else {
            self.lines.push(MappingLine::Entry(MappingEntry {
                username: username.to_owned(),
                credentials: vec![credential],
            }));
        }
        self.trailing_newline = true;
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut output = String::new();
        for (index, line) in self.lines.iter().enumerate() {
            if index > 0 {
                output.push('\n');
            }
            match line {
                MappingLine::Blank => {}
                MappingLine::Comment(comment) => output.push_str(comment),
                MappingLine::Entry(entry) => {
                    output.push_str(&entry.username);
                    for credential in &entry.credentials {
                        output.push(':');
                        output.push_str(&credential.0);
                    }
                }
            }
        }
        if self.trailing_newline && (!self.lines.is_empty() || !output.is_empty()) {
            output.push('\n');
        }
        output.into_bytes()
    }
}

fn validate_username(username: &str) -> Result<(), PamMappingError> {
    let mut characters = username.chars();
    let valid_first = characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic());
    if !valid_first
        || username.len() > 64
        || !characters
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(PamMappingError::InvalidUsername);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PamInventory {
    pub users: Vec<PamUserInventory>,
    pub duplicate_user_lines: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PamUserInventory {
    pub user_id: RedactedId,
    pub credential_ids: Vec<RedactedId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PamFilePolicy {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl Default for PamFilePolicy {
    fn default() -> Self {
        Self {
            mode: 0o600,
            uid: 0,
            gid: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PamUpdatePlan {
    pub target: PathBuf,
    pub backup: PathBuf,
    pub role: AuthenticatorRole,
    pub user_id: RedactedId,
    pub credential_id: RedactedId,
    pub previous_credential_count: usize,
    pub resulting_credential_count: usize,
    pub expected_original_sha256: Option<String>,
    pub target_mode: u32,
    pub target_uid: u32,
    pub target_gid: u32,
    pub atomic_same_directory: bool,
    pub fingerprint: String,
}

pub struct PreparedPamUpdate {
    plan: PamUpdatePlan,
    replacement: Vec<u8>,
}

impl fmt::Debug for PreparedPamUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPamUpdate")
            .field("plan", &self.plan)
            .field("replacement", &"<redacted>")
            .finish()
    }
}

impl Drop for PreparedPamUpdate {
    fn drop(&mut self) {
        self.replacement.zeroize();
    }
}

impl PreparedPamUpdate {
    pub fn plan(&self) -> &PamUpdatePlan {
        &self.plan
    }
}

pub fn prepare_mapping_update(
    inspector: &dyn FileInspector,
    target: &Path,
    username: &str,
    credential: PamCredential,
    role: AuthenticatorRole,
    policy: &PamFilePolicy,
) -> Result<PreparedPamUpdate, PamMappingError> {
    crate::fs::validate_absolute_path(target)?;
    let parent = target.parent().ok_or(FileSecurityError::ParentTraversal)?;
    let parent_facts = inspector
        .inspect_no_follow(parent)?
        .ok_or_else(|| FileSecurityError::Missing(parent.to_path_buf()))?;
    validate_secure_parent(parent, &parent_facts, policy.uid)?;

    let current_facts = inspector.inspect_no_follow(target)?;
    let (mut document, expected_original_sha256) = if let Some(facts) = current_facts {
        validate_secure_file(target, &facts, policy.mode, policy.uid, policy.gid)?;
        let bytes = inspector.read(target)?;
        let digest = sha256_hex(&bytes);
        (PamMappingDocument::parse(&bytes)?, Some(digest))
    } else {
        (PamMappingDocument::empty(), None)
    };
    let before = document
        .inventory()
        .users
        .iter()
        .find(|user| user.user_id == RedactedId::from_sensitive(username.as_bytes()))
        .map_or(0, |user| user.credential_ids.len());
    let credential_id = credential.redacted_id();
    document.add(username, credential)?;
    let replacement = document.encode();
    let backup = same_directory_backup_path(target)?;
    let user_id = RedactedId::from_sensitive(username.as_bytes());
    let fingerprint = sha256_hex(
        format!(
            "{}|{}|{}|{}|{:o}|{}|{}",
            target.display(),
            expected_original_sha256.as_deref().unwrap_or("new"),
            user_id,
            credential_id,
            policy.mode,
            policy.uid,
            policy.gid
        )
        .as_bytes(),
    );
    Ok(PreparedPamUpdate {
        plan: PamUpdatePlan {
            target: target.to_path_buf(),
            backup,
            role,
            user_id,
            credential_id,
            previous_credential_count: before,
            resulting_credential_count: before + 1,
            expected_original_sha256,
            target_mode: policy.mode,
            target_uid: policy.uid,
            target_gid: policy.gid,
            atomic_same_directory: true,
            fingerprint,
        },
        replacement,
    })
}

fn same_directory_backup_path(target: &Path) -> Result<PathBuf, PamMappingError> {
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(PamMappingError::InvalidLine { line: 0 })?;
    Ok(target.with_file_name(format!("{name}.nixkeyforge.bak")))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PamApplyResult {
    DryRun(PamUpdatePlan),
    Applied { fingerprint: String },
}

pub fn apply_mapping_update(
    _inspector: &dyn FileInspector,
    _writer: &dyn AtomicWriter,
    prepared: &PreparedPamUpdate,
    mode: &ApplyMode,
) -> Result<PamApplyResult, PamMappingError> {
    let ApplyMode::Confirmed(confirmation) = mode else {
        return Ok(PamApplyResult::DryRun(prepared.plan.clone()));
    };
    if !confirmation.is_valid_for(&prepared.plan.fingerprint) {
        return Err(PamMappingError::ConfirmationRequired);
    }
    Err(PamMappingError::LiveApplyDisabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::ApplyConfirmation;
    use crate::fs::{FileFacts, FileKind, MockFile, MockFileSystem};

    const CRED_A: &str = "a2V5SGFuZGxlQQ,cHVibGljS2V5QQ";
    const CRED_B: &str = "a2V5SGFuZGxlQg,cHVibGljS2V5Qg";
    const CRED_C: &str = "a2V5SGFuZGxlQw,cHVibGljS2V5Qw";

    fn facts(kind: FileKind, mode: u32, uid: u32, gid: u32) -> FileFacts {
        FileFacts {
            kind,
            mode,
            uid,
            gid,
            hard_links: 1,
            device: 1,
            inode: 2,
            size: 0,
        }
    }

    #[test]
    fn parses_multiple_credentials_and_redacts_debug() -> Result<(), PamMappingError> {
        let input = format!("sample:{CRED_A}:{CRED_B}\n");
        let document = PamMappingDocument::parse(input.as_bytes())?;
        assert_eq!(document.inventory().users[0].credential_ids.len(), 2);
        let debug = format!("{document:?}");
        assert!(!debug.contains(CRED_A));
        assert!(!debug.contains("sample"));
        Ok(())
    }

    #[test]
    fn rejects_argument_and_line_injection() {
        assert_eq!(
            PamCredential::parse("valid,key\nattacker:bad,key"),
            Err(PamMappingError::InvalidCredential)
        );
        assert!(PamMappingDocument::parse(b"--evil:valid,key\n").is_err());
    }

    #[test]
    fn duplicate_credentials_are_rejected() {
        let input = format!("sample:{CRED_A}:{CRED_A}\n");
        assert_eq!(
            PamMappingDocument::parse(input.as_bytes()),
            Err(PamMappingError::DuplicateCredential)
        );
    }

    #[test]
    fn update_preserves_foreign_user_line() -> Result<(), Box<dyn std::error::Error>> {
        let mut document =
            PamMappingDocument::parse(format!("first:{CRED_A}\nsecond:{CRED_B}\n").as_bytes())?;
        document.add("first", PamCredential::parse(CRED_C)?)?;
        let encoded = String::from_utf8(document.encode())?;
        assert!(encoded.contains(&format!("second:{CRED_B}")));
        assert!(encoded.contains(&format!("first:{CRED_A}:{CRED_C}")));
        Ok(())
    }

    #[test]
    fn prepared_update_is_dry_run_by_default_and_live_apply_is_disabled()
    -> Result<(), PamMappingError> {
        let fs = MockFileSystem::default();
        let directory = PathBuf::from("/safe");
        let target = directory.join("u2f_mappings");
        fs.insert(
            directory,
            MockFile {
                facts: facts(FileKind::Directory, 0o700, 0, 0),
                content: Vec::new(),
            },
        );
        fs.insert(
            target.clone(),
            MockFile {
                facts: facts(FileKind::Regular, 0o600, 0, 0),
                content: format!("sample:{CRED_A}\n").into_bytes(),
            },
        );
        let prepared = prepare_mapping_update(
            &fs,
            &target,
            "sample",
            PamCredential::parse(CRED_B)?,
            AuthenticatorRole::Backup,
            &PamFilePolicy::default(),
        )?;
        assert!(matches!(
            apply_mapping_update(&fs, &fs, &prepared, &ApplyMode::default())?,
            PamApplyResult::DryRun(_)
        ));
        assert!(fs.writes().is_empty());

        let confirmation = ApplyConfirmation {
            plan_fingerprint: prepared.plan().fingerprint.clone(),
            interactive_phrase_matched: true,
            preconditions_revalidated: true,
        };
        assert_eq!(
            apply_mapping_update(&fs, &fs, &prepared, &ApplyMode::Confirmed(confirmation)),
            Err(PamMappingError::LiveApplyDisabled)
        );
        assert!(fs.writes().is_empty());
        Ok(())
    }

    #[test]
    fn unsafe_mode_is_rejected_before_planning() -> Result<(), PamMappingError> {
        let fs = MockFileSystem::default();
        fs.insert(
            "/safe",
            MockFile {
                facts: facts(FileKind::Directory, 0o700, 0, 0),
                content: Vec::new(),
            },
        );
        fs.insert(
            "/safe/u2f_mappings",
            MockFile {
                facts: facts(FileKind::Regular, 0o644, 0, 0),
                content: format!("sample:{CRED_A}\n").into_bytes(),
            },
        );
        assert!(matches!(
            prepare_mapping_update(
                &fs,
                Path::new("/safe/u2f_mappings"),
                "sample",
                PamCredential::parse(CRED_B)?,
                AuthenticatorRole::Backup,
                &PamFilePolicy::default()
            ),
            Err(PamMappingError::FileSecurity(
                FileSecurityError::WrongMode { .. }
            ))
        ));
        Ok(())
    }

    #[test]
    fn parser_does_not_panic_on_synthetic_inputs() {
        for length in 0..512 {
            let bytes = (0..length)
                .map(|index| ((index * 31 + length) % 256) as u8)
                .collect::<Vec<_>>();
            let _ = PamMappingDocument::parse(&bytes);
        }
    }
}
