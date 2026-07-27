use crate::apply::{ApplyError, ApplyMode, ApplyResult, apply_command};
use crate::command::{CommandSpec, InputPolicy, Program};
use crate::fs::{FileFacts, FileSecurityError, validate_secure_file};
use crate::{AuthenticatorRole, RedactedId, sha256_hex};
use std::fmt;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Eq, PartialEq)]
pub struct SshDestination(String);

impl SshDestination {
    pub fn parse(value: &str) -> Result<Self, SshError> {
        if value.is_empty()
            || value.len() > 253
            || value.starts_with('-')
            || value.contains(|character: char| {
                character.is_whitespace()
                    || character.is_control()
                    || matches!(character, ';' | '`' | '$' | '(' | ')' | '\\')
            })
            || !value.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '@')
            })
        {
            return Err(SshError::InvalidDestination);
        }
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Debug for SshDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SshDestination")
            .field(&RedactedId::from_sensitive(self.0.as_bytes()))
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SshError {
    InvalidDestination,
    InvalidKeyPath,
    InvalidPublicKey,
    ForbiddenKeyOption,
    DuplicatePublicKey,
    FileSecurity(FileSecurityError),
    Apply(ApplyError),
}

impl fmt::Display for SshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SSH adapter validation failed")
    }
}

impl std::error::Error for SshError {}

impl From<ApplyError> for SshError {
    fn from(value: ApplyError) -> Self {
        Self::Apply(value)
    }
}

impl From<FileSecurityError> for SshError {
    fn from(value: FileSecurityError) -> Self {
        Self::FileSecurity(value)
    }
}

pub fn inspect_client_command(destination: &SshDestination) -> CommandSpec {
    CommandSpec::new(
        Program::Ssh,
        ["-G".to_owned(), "--".to_owned(), destination.0.clone()],
        InputPolicy::Null,
    )
}

#[derive(Clone, Eq, PartialEq)]
pub struct SshKeyPath(PathBuf);

impl SshKeyPath {
    pub fn parse(path: &Path) -> Result<Self, SshError> {
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::CurDir | Component::Prefix(_)
                )
            })
            || path.file_name().is_none()
        {
            return Err(SshError::InvalidKeyPath);
        }
        Ok(Self(path.to_path_buf()))
    }
}

impl fmt::Debug for SshKeyPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SshKeyPath")
            .field(&"<redacted-path>")
            .finish()
    }
}

pub fn inspect_public_key_command(path: &SshKeyPath) -> CommandSpec {
    CommandSpec::new(
        Program::SshKeygen,
        [
            "-l".to_owned(),
            "-f".to_owned(),
            path.0.display().to_string(),
        ],
        InputPolicy::Null,
    )
}

pub fn supported_key_types_command() -> CommandSpec {
    CommandSpec::new(Program::Ssh, ["-Q", "key"], InputPolicy::Null)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshKeyGenerationPlan {
    pub kind: UserKeyKind,
    pub authenticator_role: Option<AuthenticatorRole>,
    pub command: CommandSpec,
    pub interactive_passphrase_required: bool,
    pub user_presence_required: bool,
    pub user_verification_required: bool,
    pub host_key: bool,
    pub fingerprint: String,
}

pub fn plan_ed25519_user_key(path: &SshKeyPath) -> SshKeyGenerationPlan {
    let command = CommandSpec::new(
        Program::SshKeygen,
        [
            "-t".to_owned(),
            "ed25519".to_owned(),
            "-a".to_owned(),
            "64".to_owned(),
            "-f".to_owned(),
            path.0.display().to_string(),
        ],
        InputPolicy::ProtectedTty,
    );
    SshKeyGenerationPlan {
        kind: UserKeyKind::Ed25519,
        authenticator_role: None,
        fingerprint: sha256_hex(
            format!(
                "ssh-user-ed25519|{}",
                RedactedId::from_sensitive(path.0.as_os_str().as_encoded_bytes())
            )
            .as_bytes(),
        ),
        command,
        interactive_passphrase_required: true,
        user_presence_required: false,
        user_verification_required: false,
        host_key: false,
    }
}

pub fn plan_ed25519_sk_user_key(
    path: &SshKeyPath,
    role: AuthenticatorRole,
    verify_required: bool,
) -> SshKeyGenerationPlan {
    let mut arguments = vec![
        "-t".to_owned(),
        "ed25519-sk".to_owned(),
        "-f".to_owned(),
        path.0.display().to_string(),
    ];
    if verify_required {
        arguments.push("-O".to_owned());
        arguments.push("verify-required".to_owned());
    }
    let command = CommandSpec::new(Program::SshKeygen, arguments, InputPolicy::ProtectedTty);
    SshKeyGenerationPlan {
        kind: UserKeyKind::Ed25519SecurityKey,
        authenticator_role: Some(role),
        fingerprint: sha256_hex(
            format!(
                "ssh-user-ed25519-sk|{}|{:?}|{}",
                RedactedId::from_sensitive(path.0.as_os_str().as_encoded_bytes()),
                role,
                verify_required
            )
            .as_bytes(),
        ),
        command,
        interactive_passphrase_required: false,
        user_presence_required: true,
        user_verification_required: verify_required,
        host_key: false,
    }
}

pub fn apply_key_generation(
    executor: &dyn crate::command::Executor,
    plan: &SshKeyGenerationPlan,
    mode: &ApplyMode,
) -> Result<ApplyResult, SshError> {
    apply_command(executor, &plan.command, &plan.fingerprint, mode).map_err(Into::into)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserKeyKind {
    Ed25519,
    Ed25519SecurityKey,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SshPublicKey {
    kind: UserKeyKind,
    encoded: String,
    options: Vec<String>,
}

impl SshPublicKey {
    pub fn parse(line: &str) -> Result<Self, SshError> {
        if line.contains(['\n', '\r', '\0']) || line.len() > 32 * 1024 {
            return Err(SshError::InvalidPublicKey);
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let key_index = fields
            .iter()
            .position(|field| matches!(*field, "ssh-ed25519" | "sk-ssh-ed25519@openssh.com"))
            .ok_or(SshError::InvalidPublicKey)?;
        if fields.len() <= key_index + 1 {
            return Err(SshError::InvalidPublicKey);
        }
        let options = if key_index == 0 {
            Vec::new()
        } else {
            fields[..key_index]
                .join(" ")
                .split(',')
                .map(str::to_owned)
                .collect()
        };
        if options.iter().any(|option| {
            option.eq_ignore_ascii_case("no-touch-required") || option.contains("no-touch-required")
        }) {
            return Err(SshError::ForbiddenKeyOption);
        }
        let encoded = fields[key_index + 1];
        if encoded.len() < 16
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(SshError::InvalidPublicKey);
        }
        Ok(Self {
            kind: if fields[key_index] == "ssh-ed25519" {
                UserKeyKind::Ed25519
            } else {
                UserKeyKind::Ed25519SecurityKey
            },
            encoded: encoded.to_owned(),
            options,
        })
    }

    pub fn kind(&self) -> UserKeyKind {
        self.kind
    }

    pub fn redacted_id(&self) -> RedactedId {
        RedactedId::from_sensitive(self.encoded.as_bytes())
    }
}

impl fmt::Debug for SshPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshPublicKey")
            .field("kind", &self.kind)
            .field("id", &self.redacted_id())
            .field("option_count", &self.options.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedKeysInventory {
    pub recognized_key_ids: Vec<RedactedId>,
    pub foreign_line_count: usize,
    pub forbidden_no_touch_option_count: usize,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedKeysDocument {
    recognized: Vec<SshPublicKey>,
    foreign_line_ids: Vec<RedactedId>,
    forbidden_no_touch_option_count: usize,
}

impl fmt::Debug for AuthorizedKeysDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedKeysDocument")
            .field("recognized", &self.recognized)
            .field("foreign_line_ids", &self.foreign_line_ids)
            .field(
                "forbidden_no_touch_option_count",
                &self.forbidden_no_touch_option_count,
            )
            .finish()
    }
}

impl AuthorizedKeysDocument {
    pub fn parse(input: &[u8]) -> Result<Self, SshError> {
        if input.len() > 4 * 1024 * 1024 {
            return Err(SshError::InvalidPublicKey);
        }
        let text = std::str::from_utf8(input).map_err(|_| SshError::InvalidPublicKey)?;
        let mut recognized = Vec::new();
        let mut foreign_line_ids = Vec::new();
        let mut forbidden_no_touch_option_count = 0;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.contains("no-touch-required") {
                forbidden_no_touch_option_count += 1;
            }
            match SshPublicKey::parse(trimmed) {
                Ok(key) => recognized.push(key),
                Err(_) => {
                    foreign_line_ids.push(RedactedId::from_sensitive(trimmed.as_bytes()));
                }
            }
        }
        Ok(Self {
            recognized,
            foreign_line_ids,
            forbidden_no_touch_option_count,
        })
    }

    pub fn inventory(&self) -> AuthorizedKeysInventory {
        AuthorizedKeysInventory {
            recognized_key_ids: self
                .recognized
                .iter()
                .map(SshPublicKey::redacted_id)
                .collect(),
            foreign_line_count: self.foreign_line_ids.len(),
            forbidden_no_touch_option_count: self.forbidden_no_touch_option_count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedKeysPolicy {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedKeysUpdatePlan {
    pub target: PathBuf,
    pub key_id: RedactedId,
    pub preserves_all_existing_lines: bool,
    pub atomic_replace_required: bool,
    pub expected_mode: u32,
    pub expected_uid: u32,
    pub expected_gid: u32,
    /// Version 0.1 produces a reviewed staging plan; it never writes a live
    /// `authorized_keys` file.
    pub live_apply_supported: bool,
    pub fingerprint: String,
}

impl fmt::Debug for AuthorizedKeysUpdatePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedKeysUpdatePlan")
            .field(
                "target",
                &RedactedId::from_sensitive(self.target.as_os_str().as_encoded_bytes()),
            )
            .field("key_id", &self.key_id)
            .field(
                "preserves_all_existing_lines",
                &self.preserves_all_existing_lines,
            )
            .field("atomic_replace_required", &self.atomic_replace_required)
            .field("expected_mode", &format_args!("{:04o}", self.expected_mode))
            .field("expected_uid", &self.expected_uid)
            .field("expected_gid", &self.expected_gid)
            .field("live_apply_supported", &self.live_apply_supported)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

pub fn plan_authorized_keys_update(
    target: &Path,
    facts: &FileFacts,
    current: &[u8],
    new_key: &SshPublicKey,
    policy: &AuthorizedKeysPolicy,
) -> Result<AuthorizedKeysUpdatePlan, SshError> {
    validate_secure_file(target, facts, policy.mode, policy.uid, policy.gid)?;
    let document = AuthorizedKeysDocument::parse(current)?;
    let key_id = new_key.redacted_id();
    if document.inventory().recognized_key_ids.contains(&key_id) {
        return Err(SshError::DuplicatePublicKey);
    }
    let fingerprint = sha256_hex(
        format!(
            "{}|{}|{}|{:o}|{}|{}",
            RedactedId::from_sensitive(target.as_os_str().as_encoded_bytes()),
            RedactedId::from_sensitive(current),
            key_id,
            policy.mode,
            policy.uid,
            policy.gid
        )
        .as_bytes(),
    );
    Ok(AuthorizedKeysUpdatePlan {
        target: target.to_path_buf(),
        key_id,
        preserves_all_existing_lines: true,
        atomic_replace_required: true,
        expected_mode: policy.mode,
        expected_uid: policy.uid,
        expected_gid: policy.gid,
        live_apply_supported: false,
        fingerprint,
    })
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SshInspection {
    pub server_enabled: bool,
    pub password_authentication: Option<bool>,
    pub keyboard_interactive_authentication: Option<bool>,
    pub public_key_authentication: Option<bool>,
    pub home_manager_client_managed: bool,
}

pub fn parse_effective_client_config(output: &[u8]) -> Result<Vec<SshConfigFact>, SshError> {
    let text = std::str::from_utf8(output).map_err(|_| SshError::InvalidDestination)?;
    let wanted = [
        "hostname",
        "port",
        "user",
        "identitiesonly",
        "stricthostkeychecking",
        "hashknownhosts",
    ];
    Ok(text
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(' ')?;
            wanted.contains(&name).then(|| SshConfigFact {
                name: name.to_owned(),
                value: if matches!(name, "hostname" | "user") {
                    RedactedId::from_sensitive(value.as_bytes()).to_string()
                } else {
                    value.to_owned()
                },
            })
        })
        .collect())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshConfigFact {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SshPlanChange {
    AddUserPublicKey,
    AddSecurityKeyPublicKey,
    RequireUserVerification,
    DisablePasswordAuthentication,
    DisableKeyboardInteractiveAuthentication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshPlanRequest {
    pub inspection: SshInspection,
    pub desired_changes: Vec<SshPlanChange>,
    pub public_key_tested_in_second_connection: bool,
    pub private_ed25519_has_passphrase: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshPlan {
    pub changes: Vec<SshPlanChange>,
    pub blockers: Vec<&'static str>,
    pub warnings: Vec<&'static str>,
    pub apply_supported: bool,
}

pub fn plan_ssh(request: SshPlanRequest) -> SshPlan {
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let disables_fallback = request.desired_changes.iter().any(|change| {
        matches!(
            change,
            SshPlanChange::DisablePasswordAuthentication
                | SshPlanChange::DisableKeyboardInteractiveAuthentication
        )
    });
    if disables_fallback && !request.public_key_tested_in_second_connection {
        blockers.push("Public-key login must be verified in a second connection first.");
    }
    if request
        .desired_changes
        .contains(&SshPlanChange::AddUserPublicKey)
        && !request.private_ed25519_has_passphrase
    {
        blockers.push("A normal Ed25519 private key must be protected by a passphrase.");
    }
    if !request.inspection.server_enabled && disables_fallback {
        blockers.push("The OpenSSH server is disabled and will not be enabled automatically.");
    }
    if request.inspection.home_manager_client_managed {
        warnings.push("Client settings are managed by Home Manager and must not be overwritten.");
    }
    if request.desired_changes.iter().any(|change| {
        matches!(
            change,
            SshPlanChange::AddUserPublicKey | SshPlanChange::AddSecurityKeyPublicKey
        )
    }) {
        blockers.push(
            "Version 0.1 stages authorized_keys changes for review and does not write the live file.",
        );
    }
    SshPlan {
        changes: request.desired_changes,
        apply_supported: blockers.is_empty(),
        blockers,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::FileKind;

    const PUBLIC: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIE5vdFJlYWxLZXlNYXRlcmlhbA==";

    #[test]
    fn command_injection_destination_is_rejected() {
        for value in [
            "-oProxyCommand=touch",
            "host;touch",
            "$(touch /tmp/nope)",
            "host name",
        ] {
            assert_eq!(
                SshDestination::parse(value),
                Err(SshError::InvalidDestination)
            );
        }
    }

    #[test]
    fn no_touch_required_is_forbidden() {
        assert_eq!(
            SshPublicKey::parse(&format!(
                "no-touch-required sk-ssh-ed25519@openssh.com {PUBLIC}"
            )),
            Err(SshError::ForbiddenKeyOption)
        );
    }

    #[test]
    fn public_key_debug_is_redacted() -> Result<(), SshError> {
        let option_secret = "command=\"private-operation\"";
        let key =
            SshPublicKey::parse(&format!("{option_secret} ssh-ed25519 {PUBLIC} workstation"))?;
        let debug = format!("{key:?}");
        assert!(!debug.contains(PUBLIC));
        assert!(!debug.contains(option_secret));
        assert_eq!(key.kind(), UserKeyKind::Ed25519);
        Ok(())
    }

    #[test]
    fn cannot_disable_password_before_second_connection_test() {
        let plan = plan_ssh(SshPlanRequest {
            inspection: SshInspection {
                server_enabled: true,
                ..SshInspection::default()
            },
            desired_changes: vec![SshPlanChange::DisablePasswordAuthentication],
            public_key_tested_in_second_connection: false,
            private_ed25519_has_passphrase: true,
        });
        assert!(!plan.apply_supported);
        assert!(!plan.blockers.is_empty());
    }

    #[test]
    fn disabled_server_is_never_silently_enabled() {
        let plan = plan_ssh(SshPlanRequest {
            inspection: SshInspection::default(),
            desired_changes: vec![SshPlanChange::DisablePasswordAuthentication],
            public_key_tested_in_second_connection: true,
            private_ed25519_has_passphrase: true,
        });
        assert!(!plan.apply_supported);
    }

    #[test]
    fn effective_config_redacts_host_and_user() -> Result<(), SshError> {
        let facts = parse_effective_client_config(
            b"hostname private.example\nuser alice\nport 22\nstricthostkeychecking ask\n",
        )?;
        let debug = format!("{facts:?}");
        assert!(!debug.contains("private.example"));
        assert!(!debug.contains("alice"));
        assert!(debug.contains("22"));
        Ok(())
    }

    #[test]
    fn normal_keygen_requires_interactive_passphrase_without_secret_argument()
    -> Result<(), SshError> {
        let path = SshKeyPath::parse(Path::new("/safe/id_ed25519"))?;
        let plan = plan_ed25519_user_key(&path);
        assert!(plan.interactive_passphrase_required);
        assert!(!plan.host_key);
        assert!(
            !plan
                .command
                .arguments()
                .iter()
                .any(|argument| argument == "-N")
        );
        assert_eq!(plan.command.input_policy(), InputPolicy::ProtectedTty);
        Ok(())
    }

    #[test]
    fn security_key_plans_are_role_separated_and_never_disable_touch() -> Result<(), SshError> {
        let primary_path = SshKeyPath::parse(Path::new("/safe/id_primary_sk"))?;
        let backup_path = SshKeyPath::parse(Path::new("/safe/id_backup_sk"))?;
        let primary = plan_ed25519_sk_user_key(&primary_path, AuthenticatorRole::Primary, true);
        let backup = plan_ed25519_sk_user_key(&backup_path, AuthenticatorRole::Backup, false);
        assert_ne!(primary.fingerprint, backup.fingerprint);
        assert!(primary.user_presence_required);
        assert!(primary.user_verification_required);
        assert!(
            primary
                .command
                .arguments()
                .iter()
                .any(|argument| argument == "verify-required")
        );
        assert!(
            primary
                .command
                .arguments()
                .iter()
                .chain(backup.command.arguments())
                .all(|argument| argument != "no-touch-required")
        );
        assert!(!primary.host_key);
        assert!(!backup.host_key);
        Ok(())
    }

    #[test]
    fn authorized_keys_parser_redacts_foreign_lines_and_plan_is_staging_only()
    -> Result<(), SshError> {
        let current =
            format!("# preserved\nssh-rsa QUJDREVGR0hJSktMTU5PUA== legacy\nssh-ed25519 {PUBLIC}\n");
        let document = AuthorizedKeysDocument::parse(current.as_bytes())?;
        let inventory = document.inventory();
        assert_eq!(inventory.recognized_key_ids.len(), 1);
        assert_eq!(inventory.foreign_line_count, 1);
        assert!(!format!("{document:?}").contains("legacy"));

        let replacement = SshPublicKey::parse(&format!(
            "sk-ssh-ed25519@openssh.com {}",
            "QkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWg=="
        ))?;
        let plan = plan_authorized_keys_update(
            Path::new("/home/example/.ssh/authorized_keys"),
            &FileFacts {
                kind: FileKind::Regular,
                mode: 0o600,
                uid: 1000,
                gid: 100,
                hard_links: 1,
                device: 1,
                inode: 2,
                size: current.len() as u64,
            },
            current.as_bytes(),
            &replacement,
            &AuthorizedKeysPolicy {
                mode: 0o600,
                uid: 1000,
                gid: 100,
            },
        )?;
        assert!(plan.atomic_replace_required);
        assert!(plan.preserves_all_existing_lines);
        assert!(!plan.live_apply_supported);
        Ok(())
    }
}
