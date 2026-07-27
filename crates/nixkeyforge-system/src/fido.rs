use crate::RedactedId;
use crate::apply::ApplyMode;
use crate::command::{
    CommandSpec, ExecutionError, Executor, InputPolicy, ProcessExecutor, Program,
};
use crate::pam::PamCredential;
use crate::{AuthenticatorRole, sha256_hex};
use std::collections::VecDeque;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct HidrawDevice(PathBuf);

impl HidrawDevice {
    pub fn parse(path: impl AsRef<Path>) -> Result<Self, FidoError> {
        let path = path.as_ref();
        let Some(value) = path.to_str() else {
            return Err(FidoError::InvalidDevice);
        };
        let Some(suffix) = value.strip_prefix("/dev/hidraw") else {
            return Err(FidoError::InvalidDevice);
        };
        if suffix.is_empty()
            || suffix.len() > 5
            || !suffix.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(FidoError::InvalidDevice);
        }
        Ok(Self(path.to_path_buf()))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl fmt::Debug for HidrawDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HidrawDevice")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FidoError {
    InvalidDevice,
    InvalidOutput,
    NoAuthenticator,
    MultipleAuthenticators,
    HmacSecretUnsupported,
    ClientPinUnsupported,
    UserPresenceUnsupported,
    InvalidPamEnrollment,
    CredentialGenerationFailed,
    ConfirmationRequired,
    LiveApplyDisabled,
    Execution(ExecutionError),
}

impl fmt::Display for FidoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FIDO2 adapter validation or execution failed")
    }
}

impl std::error::Error for FidoError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectedAuthenticator {
    pub device: HidrawDevice,
    pub descriptor_id: RedactedId,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FidoCapabilities {
    pub hmac_secret: bool,
    pub client_pin: bool,
    pub user_presence: bool,
    pub user_verification: bool,
}

pub fn list_command() -> CommandSpec {
    CommandSpec::new(Program::Fido2Token, ["-L"], InputPolicy::Null)
}

pub fn info_command(device: &HidrawDevice) -> CommandSpec {
    CommandSpec::new(
        Program::Fido2Token,
        ["-I".to_owned(), device.as_path().display().to_string()],
        InputPolicy::Null,
    )
}

pub fn parse_list(output: &[u8]) -> Result<Vec<DetectedAuthenticator>, FidoError> {
    let output = std::str::from_utf8(output).map_err(|_| FidoError::InvalidOutput)?;
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (path, descriptor) = line.split_once(':').ok_or(FidoError::InvalidOutput)?;
            let device = HidrawDevice::parse(path.trim())?;
            Ok(DetectedAuthenticator {
                device,
                descriptor_id: RedactedId::from_sensitive(descriptor.trim().as_bytes()),
            })
        })
        .collect()
}

pub fn parse_capabilities(output: &[u8]) -> Result<FidoCapabilities, FidoError> {
    let output = std::str::from_utf8(output).map_err(|_| FidoError::InvalidOutput)?;
    let mut capabilities = FidoCapabilities::default();
    for line in output.lines() {
        let Some((label, values)) = line.split_once(':') else {
            continue;
        };
        let values = values
            .split(',')
            .map(|value| value.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        match label.trim().to_ascii_lowercase().as_str() {
            "extension strings" | "extensions" => {
                capabilities.hmac_secret |= values.iter().any(|value| value == "hmac-secret");
            }
            "options" => {
                capabilities.client_pin |= values.iter().any(|value| value == "clientpin");
                capabilities.user_presence |= values
                    .iter()
                    .any(|value| matches!(value.as_str(), "up" | "userpresence"));
                capabilities.user_verification |= values
                    .iter()
                    .any(|value| matches!(value.as_str(), "uv" | "userverification"));
            }
            _ => {}
        }
    }
    Ok(capabilities)
}

pub fn require_single_authenticator(
    authenticators: &[DetectedAuthenticator],
) -> Result<&DetectedAuthenticator, FidoError> {
    match authenticators {
        [] => Err(FidoError::NoAuthenticator),
        [only] => Ok(only),
        _ => Err(FidoError::MultipleAuthenticators),
    }
}

pub fn require_luks_capabilities(capabilities: &FidoCapabilities) -> Result<(), FidoError> {
    if !capabilities.hmac_secret {
        return Err(FidoError::HmacSecretUnsupported);
    }
    if !capabilities.client_pin {
        return Err(FidoError::ClientPinUnsupported);
    }
    if !capabilities.user_presence {
        return Err(FidoError::UserPresenceUnsupported);
    }
    Ok(())
}

#[derive(Clone, Eq, PartialEq)]
pub struct PamOrigin(String);

impl PamOrigin {
    pub fn parse(value: &str) -> Result<Self, FidoError> {
        let Some(identifier) = value.strip_prefix("pam://") else {
            return Err(FidoError::InvalidPamEnrollment);
        };
        if identifier.is_empty()
            || value.len() > 253
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(FidoError::InvalidPamEnrollment);
        }
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Debug for PamOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PamOrigin")
            .field(&RedactedId::from_sensitive(self.0.as_bytes()))
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PamEnrollmentOptions {
    pub role: AuthenticatorRole,
    pub origin: PamOrigin,
    pub app_id: PamOrigin,
    pub require_pin: bool,
    pub require_user_verification: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PamEnrollmentCommand {
    role: AuthenticatorRole,
    spec: CommandSpec,
    fingerprint: String,
}

impl fmt::Debug for PamEnrollmentCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PamEnrollmentCommand")
            .field("role", &self.role)
            .field("program", &self.spec.program())
            .field("user_presence", &true)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl PamEnrollmentCommand {
    pub fn role(&self) -> AuthenticatorRole {
        self.role
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn argument_names(&self) -> Vec<&'static str> {
        let mut names = vec!["user", "origin", "app-id", "credential-only"];
        if self
            .spec
            .arguments()
            .iter()
            .any(|argument| argument == "-N")
        {
            names.push("pin-required");
        }
        if self
            .spec
            .arguments()
            .iter()
            .any(|argument| argument == "-V")
        {
            names.push("user-verification-required");
        }
        names
    }
}

pub fn pam_enrollment_command(
    username: &str,
    options: PamEnrollmentOptions,
) -> Result<PamEnrollmentCommand, FidoError> {
    if username.is_empty()
        || username.len() > 64
        || username.starts_with('-')
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || (options.require_user_verification && !options.require_pin)
    {
        return Err(FidoError::InvalidPamEnrollment);
    }
    let mut arguments = vec![
        "-u".to_owned(),
        username.to_owned(),
        "-o".to_owned(),
        options.origin.0.clone(),
        "-i".to_owned(),
        options.app_id.0.clone(),
        "-n".to_owned(),
    ];
    if options.require_pin {
        arguments.push("-N".to_owned());
    }
    if options.require_user_verification {
        arguments.push("-V".to_owned());
    }
    // `-P` disables User Presence and is intentionally unrepresentable.
    let fingerprint = sha256_hex(
        format!(
            "{}|{}|{}|{:?}|{}|{}",
            RedactedId::from_sensitive(username.as_bytes()),
            RedactedId::from_sensitive(options.origin.0.as_bytes()),
            RedactedId::from_sensitive(options.app_id.0.as_bytes()),
            options.role,
            options.require_pin,
            options.require_user_verification
        )
        .as_bytes(),
    );
    Ok(PamEnrollmentCommand {
        role: options.role,
        spec: CommandSpec::new(Program::Pamu2fcfg, arguments, InputPolicy::ProtectedTty),
        fingerprint,
    })
}

pub trait PamCredentialExecutor: Send + Sync {
    /// Stdout is secret credential material and must be consumed directly into
    /// the PAM mapping update without logging or generic command presentation.
    fn generate(&self, command: &PamEnrollmentCommand) -> Result<PamCredential, FidoError>;
}

#[derive(Clone, Copy, Debug)]
pub struct ProcessPamCredentialExecutor {
    _private: (),
}

impl PamCredentialExecutor for ProcessPamCredentialExecutor {
    fn generate(&self, command: &PamEnrollmentCommand) -> Result<PamCredential, FidoError> {
        let mut output = ProcessExecutor::new()
            .execute(&command.spec)
            .map_err(FidoError::Execution)?;
        let credential = match std::str::from_utf8(&output.stdout) {
            Ok(text) => {
                PamCredential::parse(text.trim()).map_err(|_| FidoError::CredentialGenerationFailed)
            }
            Err(_) => Err(FidoError::CredentialGenerationFailed),
        };
        output.stdout.fill(0);
        output.stderr.fill(0);
        credential
    }
}

#[derive(Debug, Default)]
pub struct MockPamCredentialExecutor {
    credentials: Mutex<VecDeque<PamCredential>>,
    seen: Mutex<Vec<AuthenticatorRole>>,
}

impl MockPamCredentialExecutor {
    pub fn push(&self, credential: PamCredential) {
        lock_unpoison(&self.credentials).push_back(credential);
    }

    pub fn seen(&self) -> Vec<AuthenticatorRole> {
        lock_unpoison(&self.seen).clone()
    }
}

impl PamCredentialExecutor for MockPamCredentialExecutor {
    fn generate(&self, command: &PamEnrollmentCommand) -> Result<PamCredential, FidoError> {
        lock_unpoison(&self.seen).push(command.role);
        lock_unpoison(&self.credentials)
            .pop_front()
            .ok_or(FidoError::CredentialGenerationFailed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PamEnrollmentApplyResult {
    DryRun {
        role: AuthenticatorRole,
        fingerprint: String,
    },
    Generated(PamCredential),
}

pub fn apply_pam_enrollment(
    executor: &dyn PamCredentialExecutor,
    command: &PamEnrollmentCommand,
    mode: &ApplyMode,
) -> Result<PamEnrollmentApplyResult, FidoError> {
    let ApplyMode::Confirmed(confirmation) = mode else {
        return Ok(PamEnrollmentApplyResult::DryRun {
            role: command.role,
            fingerprint: command.fingerprint.clone(),
        });
    };
    if !confirmation.is_valid_for(&command.fingerprint) {
        return Err(FidoError::ConfirmationRequired);
    }
    let _ = executor;
    Err(FidoError::LiveApplyDisabled)
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
    use crate::apply::ApplyConfirmation;

    #[test]
    fn list_is_redacted_and_parsed() -> Result<(), FidoError> {
        let raw = b"/dev/hidraw3: vendor=Example, product=Security Key, serial=secret\n";
        let items = parse_list(raw)?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].device.as_path(), Path::new("/dev/hidraw3"));
        let debug = format!("{items:?}");
        assert!(!debug.contains("serial=secret"));
        Ok(())
    }

    #[test]
    fn device_argument_injection_is_rejected() {
        for malicious in [
            "--help",
            "/dev/hidraw1 --help",
            "/dev/hidraw1;touch",
            "/tmp/hidraw1",
            "/dev/hidraw",
        ] {
            assert_eq!(
                HidrawDevice::parse(malicious),
                Err(FidoError::InvalidDevice)
            );
        }
    }

    #[test]
    fn multiple_devices_block_auto_enrollment() -> Result<(), FidoError> {
        let devices = parse_list(b"/dev/hidraw1: one\n/dev/hidraw2: two\n")?;
        assert_eq!(
            require_single_authenticator(&devices),
            Err(FidoError::MultipleAuthenticators)
        );
        Ok(())
    }

    #[test]
    fn detects_required_capability() -> Result<(), FidoError> {
        let capabilities = parse_capabilities(
            b"extension strings: credProtect, hmac-secret\noptions: clientPin, up, uv",
        )?;
        assert!(capabilities.hmac_secret);
        assert!(capabilities.client_pin);
        assert!(capabilities.user_presence);
        require_luks_capabilities(&capabilities)?;
        Ok(())
    }

    #[test]
    fn incomplete_luks_capabilities_fail_closed() {
        let missing_pin = FidoCapabilities {
            hmac_secret: true,
            user_presence: true,
            ..FidoCapabilities::default()
        };
        assert_eq!(
            require_luks_capabilities(&missing_pin),
            Err(FidoError::ClientPinUnsupported)
        );

        let missing_presence = FidoCapabilities {
            hmac_secret: true,
            client_pin: true,
            ..FidoCapabilities::default()
        };
        assert_eq!(
            require_luks_capabilities(&missing_presence),
            Err(FidoError::UserPresenceUnsupported)
        );
    }

    #[test]
    fn negative_or_lookalike_capability_names_never_enable_features() -> Result<(), FidoError> {
        for output in [
            b"extension strings: nohmac-secret\noptions: noclientPin, noup, nouv".as_slice(),
            b"hmac-secret: false\nclientPin: false\nup=false\nuv=false".as_slice(),
        ] {
            let capabilities = parse_capabilities(output)?;
            assert_eq!(capabilities, FidoCapabilities::default());
            assert!(require_luks_capabilities(&capabilities).is_err());
        }
        Ok(())
    }

    #[test]
    fn pam_enrollment_is_typed_separated_and_keeps_presence() {
        let origin = PamOrigin::parse("pam://synthetic-host");
        assert!(origin.is_ok());
        if let Ok(origin) = origin {
            let command = pam_enrollment_command(
                "sample",
                PamEnrollmentOptions {
                    role: AuthenticatorRole::Primary,
                    origin: origin.clone(),
                    app_id: origin,
                    require_pin: true,
                    require_user_verification: true,
                },
            );
            assert!(command.is_ok());
            if let Ok(command) = command {
                assert_eq!(command.spec.program(), Program::Pamu2fcfg);
                assert!(command.spec.arguments().iter().any(|arg| arg == "-N"));
                assert!(!command.spec.arguments().iter().any(|arg| arg == "-P"));
                assert!(command.spec.arguments().iter().any(|arg| arg == "-V"));
                assert!(!format!("{command:?}").contains("synthetic-host"));
            }
        }
    }

    #[test]
    fn pam_origin_rejects_empty_or_option_like_identifiers() {
        for origin in [
            "pam://",
            "pam://host/other",
            "pam://host;--help",
            "https://host",
        ] {
            assert_eq!(
                PamOrigin::parse(origin),
                Err(FidoError::InvalidPamEnrollment)
            );
        }
    }

    #[test]
    fn confirmed_pam_enrollment_remains_disabled() -> Result<(), FidoError> {
        let origin = PamOrigin::parse("pam://synthetic-host")?;
        let command = pam_enrollment_command(
            "sample",
            PamEnrollmentOptions {
                role: AuthenticatorRole::Primary,
                origin: origin.clone(),
                app_id: origin,
                require_pin: true,
                require_user_verification: false,
            },
        )?;
        let executor = MockPamCredentialExecutor::default();
        let confirmation = ApplyConfirmation {
            plan_fingerprint: command.fingerprint().to_owned(),
            interactive_phrase_matched: true,
            preconditions_revalidated: true,
        };
        assert_eq!(
            apply_pam_enrollment(&executor, &command, &ApplyMode::Confirmed(confirmation)),
            Err(FidoError::LiveApplyDisabled)
        );
        assert!(executor.seen().is_empty());
        Ok(())
    }

    #[test]
    fn pam_credential_output_stays_redacted_in_result() {
        let credential = PamCredential::parse("a2V5SGFuZGxl,cHVibGljS2V5");
        assert!(credential.is_ok());
        if let Ok(credential) = credential {
            let debug = format!("{credential:?}");
            assert!(!debug.contains("a2V5SGFuZGxl"));
        }
    }
}
