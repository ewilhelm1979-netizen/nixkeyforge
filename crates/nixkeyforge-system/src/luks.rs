use crate::apply::{ApplyError, ApplyMode, ApplyResult, apply_command};
use crate::command::{CommandSpec, Executor, InputPolicy, Program};
use crate::fido::FidoCapabilities;
use crate::{AuthenticatorRole, RedactedId, sha256_hex};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct LuksUuid(String);

impl LuksUuid {
    pub fn parse(value: &str) -> Result<Self, LuksError> {
        let lengths = [8, 4, 4, 4, 12];
        let fields = value.split('-').collect::<Vec<_>>();
        if fields.len() != lengths.len()
            || fields.iter().zip(lengths).any(|(field, length)| {
                field.len() != length || !field.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(LuksError::InvalidUuid);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for LuksUuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LuksUuid")
            .field(&RedactedId::from_sensitive(self.0.as_bytes()))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LuksDevicePath(PathBuf);

impl LuksDevicePath {
    pub fn by_uuid(uuid: &LuksUuid) -> Self {
        Self(PathBuf::from(format!("/dev/disk/by-uuid/{}", uuid.0)))
    }

    pub fn parse(path: &Path, expected_uuid: &LuksUuid) -> Result<Self, LuksError> {
        let expected = Self::by_uuid(expected_uuid);
        if path != expected.0 {
            return Err(LuksError::InvalidDevicePath);
        }
        Ok(expected)
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl fmt::Debug for LuksDevicePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LuksDevicePath")
            .field(&RedactedId::from_sensitive(
                self.0.as_os_str().as_encoded_bytes(),
            ))
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemRole {
    Root,
    Home,
    Swap,
    Data,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockDeviceIdentity {
    pub path: LuksDevicePath,
    pub luks_uuid: LuksUuid,
    pub major: u32,
    pub minor: u32,
    pub role: SystemRole,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LuksToken {
    pub token_id: u32,
    pub kind: LuksTokenKind,
    pub keyslots: BTreeSet<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LuksTokenKind {
    SystemdFido2,
    SystemdRecovery,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LuksInventory {
    pub uuid: LuksUuid,
    pub keyslots: BTreeSet<u32>,
    pub tokens: Vec<LuksToken>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LuksError {
    InvalidUuid,
    InvalidDevicePath,
    InvalidMetadata,
    NotLuks2,
    IdentityChanged,
    UuidChanged,
    RoleChanged,
    RecoveryAccessMissing,
    HeaderBackupPlanMissing,
    AuthenticatorCountNotOne,
    HmacSecretUnsupported,
    ClientPinUnsupported,
    UserPresenceUnsupported,
    UserVerificationUnsupported,
    PossibleSameAuthenticator,
    NoNewEnrollment,
    ExistingKeyslotRemoved,
    ExistingTokenRemoved,
    AmbiguousEnrollment,
    InvalidBackupPath,
    Apply(ApplyError),
}

impl fmt::Display for LuksError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LUKS2 adapter validation or execution failed")
    }
}

impl std::error::Error for LuksError {}

impl From<ApplyError> for LuksError {
    fn from(value: ApplyError) -> Self {
        Self::Apply(value)
    }
}

pub fn parse_luks2_metadata(input: &[u8]) -> Result<LuksInventory, LuksError> {
    let root: Value = serde_json::from_slice(input).map_err(|_| LuksError::InvalidMetadata)?;
    let metadata = root
        .get("metadata")
        .filter(|value| value.is_object())
        .unwrap_or(&root);
    let config = metadata
        .get("config")
        .and_then(Value::as_object)
        .ok_or(LuksError::InvalidMetadata)?;
    let json_size_present = config.contains_key("json_size");
    let keyslots_size_present = config.contains_key("keyslots_size");
    if !json_size_present || !keyslots_size_present {
        return Err(LuksError::NotLuks2);
    }
    let uuid = root
        .get("uuid")
        .or_else(|| metadata.get("uuid"))
        .and_then(Value::as_str)
        .ok_or(LuksError::InvalidMetadata)
        .and_then(LuksUuid::parse)?;
    let keyslots = parse_numeric_object_keys(
        metadata
            .get("keyslots")
            .and_then(Value::as_object)
            .ok_or(LuksError::InvalidMetadata)?,
    )?;
    let token_object = metadata
        .get("tokens")
        .and_then(Value::as_object)
        .ok_or(LuksError::InvalidMetadata)?;
    let mut tokens = Vec::new();
    for (token_id, token) in token_object {
        let token_id = token_id
            .parse::<u32>()
            .map_err(|_| LuksError::InvalidMetadata)?;
        let kind = match token.get("type").and_then(Value::as_str) {
            Some("systemd-fido2") => LuksTokenKind::SystemdFido2,
            Some("systemd-recovery") => LuksTokenKind::SystemdRecovery,
            Some(_) => LuksTokenKind::Other,
            None => return Err(LuksError::InvalidMetadata),
        };
        let token_keyslots = token
            .get("keyslots")
            .and_then(Value::as_array)
            .ok_or(LuksError::InvalidMetadata)?
            .iter()
            .map(|slot| {
                slot.as_str()
                    .ok_or(LuksError::InvalidMetadata)?
                    .parse::<u32>()
                    .map_err(|_| LuksError::InvalidMetadata)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if !token_keyslots.is_subset(&keyslots) {
            return Err(LuksError::InvalidMetadata);
        }
        tokens.push(LuksToken {
            token_id,
            kind,
            keyslots: token_keyslots,
        });
    }
    tokens.sort_by_key(|token| token.token_id);
    Ok(LuksInventory {
        uuid,
        keyslots,
        tokens,
    })
}

fn parse_numeric_object_keys(
    object: &serde_json::Map<String, Value>,
) -> Result<BTreeSet<u32>, LuksError> {
    object
        .keys()
        .map(|key| key.parse::<u32>().map_err(|_| LuksError::InvalidMetadata))
        .collect()
}

pub fn cryptsetup_inspect_command(device: &LuksDevicePath) -> CommandSpec {
    CommandSpec::new(
        Program::Cryptsetup,
        [
            "luksDump".to_owned(),
            "--dump-json-metadata".to_owned(),
            device.as_path().display().to_string(),
        ],
        InputPolicy::Null,
    )
}

pub fn lsblk_identity_command(device: &LuksDevicePath) -> CommandSpec {
    CommandSpec::new(
        Program::Lsblk,
        [
            "--json".to_owned(),
            "--output".to_owned(),
            "MAJ:MIN,FSTYPE,UUID,MOUNTPOINTS".to_owned(),
            "--".to_owned(),
            device.as_path().display().to_string(),
        ],
        InputPolicy::Null,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserVerificationPolicy {
    Required,
    TokenDefault,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentPreconditions {
    pub expected_device: BlockDeviceIdentity,
    pub current_device: BlockDeviceIdentity,
    pub inventory: LuksInventory,
    pub header_backup_planned: bool,
    pub independent_recovery_access_present: bool,
    pub connected_authenticators: usize,
    pub capabilities: FidoCapabilities,
    pub authenticator_id: RedactedId,
    pub other_role_authenticator_id: Option<RedactedId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LuksEnrollmentPlan {
    pub role: AuthenticatorRole,
    pub device: BlockDeviceIdentity,
    pub authenticator_id: RedactedId,
    pub before_keyslots: BTreeSet<u32>,
    pub before_token_ids: BTreeSet<u32>,
    pub command: CommandSpec,
    pub no_keyslot_deletion: bool,
    pub requires_post_inventory: bool,
    pub fingerprint: String,
}

pub fn plan_fido2_enrollment(
    role: AuthenticatorRole,
    preconditions: EnrollmentPreconditions,
    verification: UserVerificationPolicy,
) -> Result<LuksEnrollmentPlan, LuksError> {
    validate_identity(
        &preconditions.expected_device,
        &preconditions.current_device,
    )?;
    if preconditions.inventory.uuid != preconditions.current_device.luks_uuid {
        return Err(LuksError::UuidChanged);
    }
    if !preconditions.header_backup_planned {
        return Err(LuksError::HeaderBackupPlanMissing);
    }
    if !preconditions.independent_recovery_access_present {
        return Err(LuksError::RecoveryAccessMissing);
    }
    if preconditions.connected_authenticators != 1 {
        return Err(LuksError::AuthenticatorCountNotOne);
    }
    if !preconditions.capabilities.hmac_secret {
        return Err(LuksError::HmacSecretUnsupported);
    }
    if !preconditions.capabilities.client_pin {
        return Err(LuksError::ClientPinUnsupported);
    }
    if !preconditions.capabilities.user_presence {
        return Err(LuksError::UserPresenceUnsupported);
    }
    if verification == UserVerificationPolicy::Required
        && !preconditions.capabilities.user_verification
    {
        return Err(LuksError::UserVerificationUnsupported);
    }
    match (role, preconditions.other_role_authenticator_id.as_ref()) {
        (AuthenticatorRole::Backup, None) => {
            return Err(LuksError::PossibleSameAuthenticator);
        }
        (_, Some(other)) if other == &preconditions.authenticator_id => {
            return Err(LuksError::PossibleSameAuthenticator);
        }
        _ => {}
    }
    let mut arguments = vec![
        "--fido2-device=auto".to_owned(),
        "--fido2-with-client-pin=yes".to_owned(),
        "--fido2-with-user-presence=yes".to_owned(),
    ];
    if verification == UserVerificationPolicy::Required {
        arguments.push("--fido2-with-user-verification=yes".to_owned());
    }
    arguments.push("--".to_owned());
    arguments.push(
        preconditions
            .current_device
            .path
            .as_path()
            .display()
            .to_string(),
    );
    let before_token_ids = preconditions
        .inventory
        .tokens
        .iter()
        .map(|token| token.token_id)
        .collect::<BTreeSet<_>>();
    let fingerprint = sha256_hex(
        format!(
            "{}|{}:{}|{:?}|{:?}|{}|{:?}|{:?}|{:?}",
            preconditions.current_device.luks_uuid.as_str(),
            preconditions.current_device.major,
            preconditions.current_device.minor,
            preconditions.current_device.role,
            role,
            preconditions.authenticator_id,
            verification,
            preconditions.inventory.keyslots,
            before_token_ids
        )
        .as_bytes(),
    );
    Ok(LuksEnrollmentPlan {
        role,
        device: preconditions.current_device,
        authenticator_id: preconditions.authenticator_id,
        before_keyslots: preconditions.inventory.keyslots,
        before_token_ids,
        command: CommandSpec::new(
            Program::SystemdCryptenroll,
            arguments,
            InputPolicy::ProtectedTty,
        ),
        no_keyslot_deletion: true,
        requires_post_inventory: true,
        fingerprint,
    })
}

fn validate_identity(
    expected: &BlockDeviceIdentity,
    current: &BlockDeviceIdentity,
) -> Result<(), LuksError> {
    if expected.luks_uuid != current.luks_uuid || expected.path != current.path {
        return Err(LuksError::UuidChanged);
    }
    if expected.major != current.major || expected.minor != current.minor {
        return Err(LuksError::IdentityChanged);
    }
    if expected.role != current.role {
        return Err(LuksError::RoleChanged);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentDelta {
    pub new_token_id: u32,
    pub new_keyslots: BTreeSet<u32>,
}

pub fn verify_enrollment(
    plan: &LuksEnrollmentPlan,
    after: &LuksInventory,
) -> Result<EnrollmentDelta, LuksError> {
    if after.uuid != plan.device.luks_uuid {
        return Err(LuksError::UuidChanged);
    }
    if !plan.before_keyslots.is_subset(&after.keyslots) {
        return Err(LuksError::ExistingKeyslotRemoved);
    }
    let after_token_ids = after
        .tokens
        .iter()
        .map(|token| token.token_id)
        .collect::<BTreeSet<_>>();
    if !plan.before_token_ids.is_subset(&after_token_ids) {
        return Err(LuksError::ExistingTokenRemoved);
    }
    let new_tokens = after
        .tokens
        .iter()
        .filter(|token| {
            !plan.before_token_ids.contains(&token.token_id)
                && token.kind == LuksTokenKind::SystemdFido2
        })
        .collect::<Vec<_>>();
    if new_tokens.is_empty() {
        return Err(LuksError::NoNewEnrollment);
    }
    if new_tokens.len() != 1 {
        return Err(LuksError::AmbiguousEnrollment);
    }
    let new_keyslots = after
        .keyslots
        .difference(&plan.before_keyslots)
        .copied()
        .collect::<BTreeSet<_>>();
    if new_keyslots.is_empty() || !new_tokens[0].keyslots.is_subset(&new_keyslots) {
        return Err(LuksError::AmbiguousEnrollment);
    }
    Ok(EnrollmentDelta {
        new_token_id: new_tokens[0].token_id,
        new_keyslots,
    })
}

pub fn apply_enrollment(
    executor: &dyn Executor,
    plan: &LuksEnrollmentPlan,
    mode: &ApplyMode,
) -> Result<ApplyResult, LuksError> {
    apply_command(executor, &plan.command, &plan.fingerprint, mode).map_err(Into::into)
}

#[derive(Clone, Eq, PartialEq)]
pub struct HeaderBackupPath(PathBuf);

impl HeaderBackupPath {
    pub fn parse(path: &Path) -> Result<Self, LuksError> {
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::CurDir | Component::Prefix(_)
                )
            })
            || path.file_name().is_none()
        {
            return Err(LuksError::InvalidBackupPath);
        }
        Ok(Self(path.to_path_buf()))
    }
}

impl fmt::Debug for HeaderBackupPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HeaderBackupPath")
            .field(&"<sensitive-output-path>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::MockExecutor;

    const UUID: &str = "11111111-2222-3333-4444-555555555555";

    fn metadata(tokens: &str, keyslots: &str) -> Vec<u8> {
        format!(
            r#"{{
              "uuid": "{UUID}",
              "config": {{"json_size":"12288","keyslots_size":"16744448"}},
              "keyslots": {keyslots},
              "tokens": {tokens}
            }}"#
        )
        .into_bytes()
    }

    fn identity(major: u32, minor: u32) -> BlockDeviceIdentity {
        let uuid = LuksUuid(UUID.to_owned());
        BlockDeviceIdentity {
            path: LuksDevicePath::by_uuid(&uuid),
            luks_uuid: uuid,
            major,
            minor,
            role: SystemRole::Root,
        }
    }

    fn preconditions() -> EnrollmentPreconditions {
        EnrollmentPreconditions {
            expected_device: identity(259, 3),
            current_device: identity(259, 3),
            inventory: LuksInventory {
                uuid: LuksUuid(UUID.to_owned()),
                keyslots: BTreeSet::from([0]),
                tokens: vec![LuksToken {
                    token_id: 0,
                    kind: LuksTokenKind::SystemdRecovery,
                    keyslots: BTreeSet::from([0]),
                }],
            },
            header_backup_planned: true,
            independent_recovery_access_present: true,
            connected_authenticators: 1,
            capabilities: FidoCapabilities {
                hmac_secret: true,
                client_pin: true,
                user_presence: true,
                user_verification: true,
            },
            authenticator_id: RedactedId::from_sensitive(b"primary"),
            other_role_authenticator_id: None,
        }
    }

    #[test]
    fn parses_synthetic_luks2_inventory() -> Result<(), LuksError> {
        let inventory = parse_luks2_metadata(&metadata(
            r#"{"1":{"type":"systemd-fido2","keyslots":["1"]}}"#,
            r#"{"0":{"type":"luks2"},"1":{"type":"luks2"}}"#,
        ))?;
        assert_eq!(inventory.uuid, LuksUuid::parse(UUID)?);
        assert_eq!(inventory.keyslots, BTreeSet::from([0, 1]));
        assert_eq!(inventory.tokens[0].kind, LuksTokenKind::SystemdFido2);
        Ok(())
    }

    #[test]
    fn changed_major_minor_is_blocked() {
        let mut input = preconditions();
        input.current_device.major = 8;
        assert_eq!(
            plan_fido2_enrollment(
                AuthenticatorRole::Primary,
                input,
                UserVerificationPolicy::Required
            ),
            Err(LuksError::IdentityChanged)
        );
    }

    #[test]
    fn wrong_uuid_is_blocked() {
        let mut input = preconditions();
        input.current_device.luks_uuid =
            LuksUuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_owned());
        assert_eq!(
            plan_fido2_enrollment(
                AuthenticatorRole::Primary,
                input,
                UserVerificationPolicy::Required
            ),
            Err(LuksError::UuidChanged)
        );
    }

    #[test]
    fn missing_recovery_or_header_backup_is_blocked() {
        let mut input = preconditions();
        input.independent_recovery_access_present = false;
        assert_eq!(
            plan_fido2_enrollment(
                AuthenticatorRole::Primary,
                input,
                UserVerificationPolicy::Required
            ),
            Err(LuksError::RecoveryAccessMissing)
        );
        let mut input = preconditions();
        input.header_backup_planned = false;
        assert_eq!(
            plan_fido2_enrollment(
                AuthenticatorRole::Primary,
                input,
                UserVerificationPolicy::Required
            ),
            Err(LuksError::HeaderBackupPlanMissing)
        );
    }

    #[test]
    fn missing_pin_presence_or_required_uv_capability_is_blocked() {
        let mut input = preconditions();
        input.capabilities.client_pin = false;
        assert_eq!(
            plan_fido2_enrollment(
                AuthenticatorRole::Primary,
                input,
                UserVerificationPolicy::Required
            ),
            Err(LuksError::ClientPinUnsupported)
        );

        let mut input = preconditions();
        input.capabilities.user_presence = false;
        assert_eq!(
            plan_fido2_enrollment(
                AuthenticatorRole::Primary,
                input,
                UserVerificationPolicy::Required
            ),
            Err(LuksError::UserPresenceUnsupported)
        );

        let mut input = preconditions();
        input.capabilities.user_verification = false;
        assert_eq!(
            plan_fido2_enrollment(
                AuthenticatorRole::Primary,
                input,
                UserVerificationPolicy::Required
            ),
            Err(LuksError::UserVerificationUnsupported)
        );
    }

    #[test]
    fn same_authenticator_for_both_roles_is_blocked() {
        let mut input = preconditions();
        input.other_role_authenticator_id = Some(input.authenticator_id.clone());
        assert_eq!(
            plan_fido2_enrollment(
                AuthenticatorRole::Backup,
                input,
                UserVerificationPolicy::Required
            ),
            Err(LuksError::PossibleSameAuthenticator)
        );
    }

    #[test]
    fn backup_enrollment_without_primary_identity_evidence_is_blocked() {
        assert_eq!(
            plan_fido2_enrollment(
                AuthenticatorRole::Backup,
                preconditions(),
                UserVerificationPolicy::Required
            ),
            Err(LuksError::PossibleSameAuthenticator)
        );
    }

    #[test]
    fn fingerprint_binds_role_policy_and_exact_inventory() -> Result<(), LuksError> {
        let primary = plan_fido2_enrollment(
            AuthenticatorRole::Primary,
            preconditions(),
            UserVerificationPolicy::Required,
        )?;

        let token_default = plan_fido2_enrollment(
            AuthenticatorRole::Primary,
            preconditions(),
            UserVerificationPolicy::TokenDefault,
        )?;
        assert_ne!(primary.fingerprint, token_default.fingerprint);

        let mut backup_input = preconditions();
        backup_input.other_role_authenticator_id =
            Some(RedactedId::from_sensitive(b"known-primary"));
        backup_input.authenticator_id = RedactedId::from_sensitive(b"backup");
        let backup = plan_fido2_enrollment(
            AuthenticatorRole::Backup,
            backup_input,
            UserVerificationPolicy::Required,
        )?;
        assert_ne!(primary.fingerprint, backup.fingerprint);

        let mut changed_inventory = preconditions();
        changed_inventory.inventory.keyslots = BTreeSet::from([7]);
        changed_inventory.inventory.tokens[0].keyslots = BTreeSet::from([7]);
        let changed = plan_fido2_enrollment(
            AuthenticatorRole::Primary,
            changed_inventory,
            UserVerificationPolicy::Required,
        )?;
        assert_ne!(primary.fingerprint, changed.fingerprint);
        Ok(())
    }

    #[test]
    fn plan_never_contains_slot_deletion_and_is_dry_run() -> Result<(), LuksError> {
        let plan = plan_fido2_enrollment(
            AuthenticatorRole::Primary,
            preconditions(),
            UserVerificationPolicy::Required,
        )?;
        assert!(plan.no_keyslot_deletion);
        assert!(
            plan.command
                .arguments()
                .iter()
                .all(|argument| !argument.contains("wipe-slot"))
        );
        let mock = MockExecutor::default();
        assert!(matches!(
            apply_enrollment(&mock, &plan, &ApplyMode::default())?,
            ApplyResult::DryRun { .. }
        ));
        assert!(mock.seen().is_empty());
        Ok(())
    }

    #[test]
    fn verification_rejects_removed_slot() -> Result<(), LuksError> {
        let plan = plan_fido2_enrollment(
            AuthenticatorRole::Primary,
            preconditions(),
            UserVerificationPolicy::Required,
        )?;
        let after = parse_luks2_metadata(&metadata(
            r#"{"1":{"type":"systemd-fido2","keyslots":["1"]}}"#,
            r#"{"1":{"type":"luks2"}}"#,
        ))?;
        assert_eq!(
            verify_enrollment(&plan, &after),
            Err(LuksError::ExistingKeyslotRemoved)
        );
        Ok(())
    }

    #[test]
    fn verification_requires_exactly_one_new_mapping() -> Result<(), LuksError> {
        let plan = plan_fido2_enrollment(
            AuthenticatorRole::Primary,
            preconditions(),
            UserVerificationPolicy::Required,
        )?;
        let unchanged = parse_luks2_metadata(&metadata(
            r#"{"0":{"type":"systemd-recovery","keyslots":["0"]}}"#,
            r#"{"0":{"type":"luks2"}}"#,
        ))?;
        assert_eq!(
            verify_enrollment(&plan, &unchanged),
            Err(LuksError::NoNewEnrollment)
        );
        Ok(())
    }

    #[test]
    fn uuid_and_device_path_reject_argument_injection() -> Result<(), LuksError> {
        assert!(LuksUuid::parse("$(touch /tmp/nope)").is_err());
        let uuid = LuksUuid::parse(UUID)?;
        assert_eq!(
            LuksDevicePath::parse(Path::new("/dev/sda --help"), &uuid),
            Err(LuksError::InvalidDevicePath)
        );
        Ok(())
    }
}
