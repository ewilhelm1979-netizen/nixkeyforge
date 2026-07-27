#![forbid(unsafe_code)]

use std::fmt::{self, Display};
use std::fs::{self, DirBuilder};
use std::path::{Component, Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
#[cfg(target_os = "linux")]
use nixkeyforge_system::fs::{AtomicWriteRequest, AtomicWriter, LinuxAtomicWriter};
use nixkeyforge_system::nixos::{PamU2fSource, discover_nixos_source};
use serde::Serialize;

pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_WARNING: u8 = 10;
pub const EXIT_BLOCKER: u8 = 20;
pub const EXIT_DRIFT: u8 = 30;
pub const EXIT_VERIFICATION_FAILED: u8 = 40;

#[derive(Debug, Parser)]
#[command(
    name = "nixkeyforge",
    version,
    about = "Secure access and recovery manager for NixOS",
    long_about = "NixKeyforge discovers, plans, and verifies FIDO2, PAM, LUKS2, SSH, and recovery configuration. Live changes are never implicit."
)]
pub struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    #[arg(long, global = true, default_value = "/etc/nixos")]
    pub config_root: PathBuf,

    #[command(subcommand)]
    pub command: TopCommand,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(Debug, Subcommand)]
pub enum TopCommand {
    Doctor,
    Status,
    Plan(PlanArgs),
    Generate(GenerateArgs),
    Fido {
        #[command(subcommand)]
        command: FidoCommand,
    },
    Luks {
        #[command(subcommand)]
        command: LuksCommand,
    },
    Ssh {
        #[command(subcommand)]
        command: SshCommand,
    },
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    Restore {
        #[command(subcommand)]
        command: RestoreCommand,
    },
}

#[derive(Debug, Args)]
pub struct PlanArgs {
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct GenerateArgs {
    #[arg(long)]
    pub output_dir: PathBuf,
    #[arg(long)]
    pub from_plan: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum FidoCommand {
    Detect,
    Inventory,
    Capabilities,
    Login {
        #[command(subcommand)]
        command: FidoLoginCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum FidoLoginCommand {
    Status,
    Plan(PlanArgs),
    Enroll(RoleExecutionArgs),
    Verify(RoleArgs),
}

#[derive(Debug, Subcommand)]
pub enum LuksCommand {
    Inspect(DeviceArgs),
    Status(DeviceArgs),
    Plan(DevicePlanArgs),
    Enroll(LuksExecutionArgs),
    Verify(LuksVerifyArgs),
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum RecoveryCommand {
    Plan(DevicePlanArgs),
}

#[derive(Debug, Subcommand)]
pub enum SshCommand {
    Inspect,
    Plan(PlanArgs),
}

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    Create(BackupCreateArgs),
    Inspect(BackupPathArgs),
    Verify(BackupPathArgs),
}

#[derive(Debug, Subcommand)]
pub enum RestoreCommand {
    Plan(BackupPathArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Primary,
    Backup,
}

impl Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primary => formatter.write_str("primary"),
            Self::Backup => formatter.write_str("backup"),
        }
    }
}

#[derive(Debug, Args)]
pub struct RoleArgs {
    #[arg(long, value_enum)]
    pub role: Role,
}

#[derive(Debug, Args)]
pub struct RoleExecutionArgs {
    #[command(flatten)]
    pub role: RoleArgs,
    #[command(flatten)]
    pub execution: ExecutionArgs,
}

#[derive(Debug, Args)]
pub struct DeviceArgs {
    #[arg(long)]
    pub device: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DevicePlanArgs {
    #[command(flatten)]
    pub device: DeviceArgs,
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct LuksExecutionArgs {
    #[command(flatten)]
    pub device: DeviceArgs,
    #[command(flatten)]
    pub role: RoleArgs,
    #[command(flatten)]
    pub execution: ExecutionArgs,
}

#[derive(Debug, Args)]
pub struct LuksVerifyArgs {
    #[command(flatten)]
    pub device: DeviceArgs,
    #[command(flatten)]
    pub role: RoleArgs,
}

#[derive(Debug, Args)]
pub struct ExecutionArgs {
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub dry_run: bool,
    #[arg(long, requires_all = ["plan_file", "fingerprint"])]
    pub apply: bool,
    #[arg(long, requires = "apply")]
    pub plan_file: Option<PathBuf>,
    #[arg(long, requires = "apply")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Args)]
pub struct BackupCreateArgs {
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long = "recipient")]
    pub recipients: Vec<String>,
    #[arg(long, conflicts_with = "recipients")]
    pub passphrase: bool,
    #[arg(long)]
    pub include_sensitive: bool,
}

#[derive(Debug, Args)]
pub struct BackupPathArgs {
    #[arg(long)]
    pub backup: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Information,
    Warning,
    High,
    Critical,
}

type ReportParts = (String, bool, Severity, &'static str, String, Vec<String>);

#[derive(Debug, Serialize)]
pub struct PamServiceReport {
    pub service: String,
    pub fido2_enabled: Option<bool>,
    pub unix_password_available: Option<bool>,
    pub source: &'static str,
}

#[derive(Debug, Serialize)]
pub struct CommandReport {
    pub operation: String,
    pub dry_run: bool,
    pub severity: Severity,
    pub state: &'static str,
    pub summary: String,
    pub affected_services: Vec<String>,
    pub unix_password_available: Option<bool>,
    pub pam_services: Vec<PamServiceReport>,
    pub intentionally_unchanged_services: Vec<String>,
    pub preconditions: Vec<String>,
    pub verification: Vec<String>,
    pub recovery: Vec<String>,
}

impl CommandReport {
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self.state {
            "configuration-drift" => EXIT_DRIFT,
            "failed-verification" => EXIT_VERIFICATION_FAILED,
            "lockout-risk" | "unsupported" | "blocked" => EXIT_BLOCKER,
            _ if matches!(self.severity, Severity::Warning | Severity::High) => EXIT_WARNING,
            _ => EXIT_SUCCESS,
        }
    }
}

#[derive(Debug)]
pub enum CliError {
    Json(serde_json::Error),
    UnsafeApply(String),
    UnsafeOutput(String),
    Io,
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "could not serialize redacted output: {error}"),
            Self::UnsafeApply(message) => formatter.write_str(message),
            Self::UnsafeOutput(message) => formatter.write_str(message),
            Self::Io => formatter.write_str("a local file operation failed"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub fn execute(cli: &Cli) -> Result<(String, u8), CliError> {
    if let TopCommand::Backup {
        command: BackupCommand::Create(args),
    } = &cli.command
    {
        validate_backup_encryption(args)?;
    }
    if let TopCommand::Generate(args) = &cli.command {
        generate_module(args)?;
    }
    let report = report_for(&cli.command, &cli.config_root)?;
    let code = report.exit_code();
    let rendered = match cli.format {
        OutputFormat::Human => render_human(&report),
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
    };
    Ok((rendered, code))
}

fn validate_backup_encryption(args: &BackupCreateArgs) -> Result<(), CliError> {
    if args.recipients.is_empty() && !args.passphrase {
        return Err(CliError::UnsafeApply(
            "backup creation requires at least one --recipient or protected interactive --passphrase mode"
                .to_owned(),
        ));
    }
    if args.recipients.iter().any(|recipient| {
        recipient.len() > 256
            || !recipient.starts_with("age1")
            || !recipient.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }) {
        return Err(CliError::UnsafeApply(
            "an age recipient has an invalid format".to_owned(),
        ));
    }
    Ok(())
}

fn report_for(command: &TopCommand, config_root: &Path) -> Result<CommandReport, CliError> {
    let (operation, dry_run, severity, state, summary, affected_services) = match command {
        TopCommand::Doctor => reference_status_report("doctor", config_root),
        TopCommand::Status => reference_status_report("status", config_root),
        TopCommand::Plan(_) => generic_plan("plan", Vec::new()),
        TopCommand::Generate(_args) => (
            "generate".to_owned(),
            false,
            Severity::Information,
            "generated",
            "A Nix module was created only in the explicitly selected output directory."
                .to_owned(),
            Vec::new(),
        ),
        TopCommand::Fido { command } => fido_report(command)?,
        TopCommand::Luks { command } => luks_report(command)?,
        TopCommand::Ssh { command } => match command {
            SshCommand::Inspect => (
                "ssh inspect".to_owned(),
                true,
                Severity::Information,
                "planned",
                "OpenSSH client and server are inspected separately; host keys are never FIDO2 credentials."
                    .to_owned(),
                Vec::new(),
            ),
            SshCommand::Plan(_) => generic_plan("ssh plan", Vec::new()),
        },
        TopCommand::Backup { command } => backup_report(command),
        TopCommand::Restore { command } => match command {
            RestoreCommand::Plan(_args) => (
                "restore plan".to_owned(),
                true,
                Severity::High,
                "unsupported",
                "Restore planning remains disabled until a production age/tar parser can authenticate and validate the selected package."
                    .to_owned(),
                Vec::new(),
            ),
        },
    };

    let pam_services = pam_service_reports(command, config_root);
    let unix_password_available = aggregate_unix_password_availability(&pam_services);

    Ok(CommandReport {
        unix_password_available,
        pam_services,
        intentionally_unchanged_services: if operation.starts_with("fido login") {
            vec![
                "sudo".to_owned(),
                "polkit-1".to_owned(),
                "su".to_owned(),
                "sshd".to_owned(),
            ]
        } else {
            Vec::new()
        },
        operation,
        dry_run,
        severity,
        state,
        summary,
        affected_services,
        preconditions: default_preconditions(),
        verification: default_verification(),
        recovery: default_recovery(),
    })
}

fn pam_service_reports(command: &TopCommand, config_root: &Path) -> Vec<PamServiceReport> {
    if matches!(command, TopCommand::Doctor | TopCommand::Status) {
        let Some(configuration) = find_host_configuration(config_root) else {
            return Vec::new();
        };
        let Ok(source) = fs::read_to_string(configuration) else {
            return Vec::new();
        };
        return discover_nixos_source(&source)
            .pam_services
            .into_iter()
            .map(|service| PamServiceReport {
                service: service.service.nix_name().to_owned(),
                fido2_enabled: service.u2f_auth,
                unix_password_available: service.unix_auth,
                source: match service.u2f_source {
                    PamU2fSource::Explicit => "explicit",
                    PamU2fSource::GlobalInherited => "global-inherited",
                    PamU2fSource::Unknown => "unknown",
                },
            })
            .collect();
    }
    if matches!(
        command,
        TopCommand::Fido {
            command: FidoCommand::Login { .. }
        }
    ) {
        return ["login", "sddm", "kde"]
            .into_iter()
            .map(|service| PamServiceReport {
                service: service.to_owned(),
                fido2_enabled: Some(true),
                unix_password_available: Some(true),
                source: "planned-explicit",
            })
            .collect();
    }
    Vec::new()
}

fn aggregate_unix_password_availability(services: &[PamServiceReport]) -> Option<bool> {
    let affected = services
        .iter()
        .filter(|service| service.fido2_enabled == Some(true))
        .collect::<Vec<_>>();
    if affected.is_empty() {
        return None;
    }
    if affected
        .iter()
        .all(|service| service.unix_password_available == Some(true))
    {
        return Some(true);
    }
    if affected
        .iter()
        .all(|service| service.unix_password_available == Some(false))
    {
        return Some(false);
    }
    None
}

fn reference_status_report(
    operation: &str,
    config_root: &Path,
) -> (String, bool, Severity, &'static str, String, Vec<String>) {
    let Some(configuration) = find_host_configuration(config_root) else {
        return (
            operation.to_owned(),
            true,
            Severity::Critical,
            "unsupported",
            "The expected NixOS host configuration could not be identified safely; no readiness claim is possible."
                .to_owned(),
            Vec::new(),
        );
    };
    let Ok(source) = fs::read_to_string(configuration) else {
        return (
            operation.to_owned(),
            true,
            Severity::Critical,
            "unsupported",
            "The expected NixOS host configuration could not be read; no readiness claim is possible."
                .to_owned(),
            Vec::new(),
        );
    };
    let discovery = discover_nixos_source(&source);
    let passwordless_services = discovery
        .pam_services
        .iter()
        .filter(|service| service.u2f_auth == Some(true) && service.unix_auth == Some(false))
        .map(|service| service.service.nix_name().to_owned())
        .collect::<Vec<_>>();
    let affected_services = discovery
        .pam_services
        .iter()
        .filter(|service| service.u2f_auth == Some(true))
        .map(|service| service.service.nix_name().to_owned())
        .collect::<Vec<_>>();

    if !passwordless_services.is_empty() {
        return (
            operation.to_owned(),
            true,
            Severity::Critical,
            "lockout-risk",
            format!(
                "Passwordless FIDO2 is effective for {}; read-only discovery cannot prove two independent working authenticators.",
                passwordless_services.join(", ")
            ),
            affected_services,
        );
    }
    if discovery.systemd_initrd == Some(true)
        || discovery.luks_fido2_auto
        || !affected_services.is_empty()
    {
        return (
            operation.to_owned(),
            true,
            Severity::Warning,
            "recovery-unverified",
            "Configuration was discovered, but separate primary, backup, boot, and recovery proofs remain manual."
                .to_owned(),
            affected_services,
        );
    }
    (
        operation.to_owned(),
        true,
        Severity::Warning,
        "unconfigured",
        "No supported FIDO2/PAM/LUKS2 configuration was proven.".to_owned(),
        affected_services,
    )
}

fn find_host_configuration(config_root: &Path) -> Option<PathBuf> {
    let expected = config_root.join("hosts/nixos/configuration.nix");
    if is_regular_file_without_symlink(&expected) {
        return Some(expected);
    }

    let hosts = config_root.join("hosts");
    let mut candidates = fs::read_dir(hosts)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("configuration.nix"))
        .filter(|path| is_regular_file_without_symlink(path))
        .collect::<Vec<_>>();
    candidates.sort();
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn is_regular_file_without_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

const GENERATED_MODULE: &str = r#"{ ... }:
{
  # Generated by NixKeyforge. Credential material remains outside the Nix store.
  # Review this fragment and import it manually; NixKeyforge never rewrites a flake.
  services.nixkeyforge = {
    enable = true;
    pam = {
      enable = true;
      services = [
        "login"
        "sddm"
        "kde"
      ];
      authFile = "/etc/u2f_mappings";
    };
  };
}
"#;

fn generate_module(args: &GenerateArgs) -> Result<(), CliError> {
    if args.from_plan.is_some() {
        return Err(CliError::UnsafeOutput(
            "--from-plan requires a validated plan parser and is not enabled in this build"
                .to_owned(),
        ));
    }
    validate_output_path(&args.output_dir)?;
    reject_symlink_components(&args.output_dir, true)?;
    if args.output_dir.exists() {
        let metadata = fs::symlink_metadata(&args.output_dir).map_err(|_| CliError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CliError::UnsafeOutput(
                "the output directory must be a real directory, not a link".to_owned(),
            ));
        }
    } else {
        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&args.output_dir).map_err(|_| {
            CliError::UnsafeOutput(
                "create the output directory's parent first; recursive creation is refused"
                    .to_owned(),
            )
        })?;
    }
    reject_symlink_components(&args.output_dir, false)?;
    write_generated_module(&args.output_dir)
}

fn validate_output_path(path: &Path) -> Result<(), CliError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(CliError::UnsafeOutput(
            "the output directory must not contain parent traversal".to_owned(),
        ));
    }
    Ok(())
}

fn reject_symlink_components(path: &Path, allow_missing_tail: bool) -> Result<(), CliError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| CliError::Io)?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if allow_missing_tail && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(_) => return Err(CliError::Io),
        };
        if metadata.file_type().is_symlink() {
            return Err(CliError::UnsafeOutput(
                "the output directory path must not traverse symbolic links".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_generated_module(output_dir: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt;

    let directory = fs::canonicalize(output_dir).map_err(|_| CliError::Io)?;
    let metadata = fs::metadata(&directory).map_err(|_| CliError::Io)?;
    if !metadata.is_dir() || metadata.mode() & 0o7777 != 0o700 {
        return Err(CliError::UnsafeOutput(
            "the output directory must have mode 0700".to_owned(),
        ));
    }
    let target = directory.join("nixkeyforge-generated.nix");
    let writer = LinuxAtomicWriter::default();
    writer
        .atomic_replace(&AtomicWriteRequest {
            backup: directory.join(".nixkeyforge-generated.unused-backup"),
            target,
            expected_original_sha256: None,
            content: GENERATED_MODULE.as_bytes().to_vec(),
            mode: 0o600,
            uid: metadata.uid(),
            gid: metadata.gid(),
            fsync_file_and_directory: true,
        })
        .map_err(|_| {
            CliError::UnsafeOutput(
                "secure atomic generation failed or the target already exists".to_owned(),
            )
        })
}

#[cfg(not(target_os = "linux"))]
fn write_generated_module(_output_dir: &Path) -> Result<(), CliError> {
    Err(CliError::UnsafeOutput(
        "secure module generation is currently supported only on Linux".to_owned(),
    ))
}

fn generic_plan(
    operation: &str,
    affected_services: Vec<String>,
) -> (String, bool, Severity, &'static str, String, Vec<String>) {
    (
        operation.to_owned(),
        true,
        Severity::Information,
        "planned",
        "Discovery, preconditions, plan fingerprint, confirmation, apply, verification, and recovery remain separate."
            .to_owned(),
        affected_services,
    )
}

fn fido_report(command: &FidoCommand) -> Result<ReportParts, CliError> {
    Ok(match command {
        FidoCommand::Detect => (
            "fido detect".to_owned(),
            true,
            Severity::Information,
            "planned",
            "Authenticator detection never treats an attached device as verified.".to_owned(),
            Vec::new(),
        ),
        FidoCommand::Inventory => (
            "fido inventory".to_owned(),
            true,
            Severity::Information,
            "planned",
            "Inventory identifiers are hashed and credential handles are never displayed."
                .to_owned(),
            Vec::new(),
        ),
        FidoCommand::Capabilities => (
            "fido capabilities".to_owned(),
            true,
            Severity::Information,
            "planned",
            "User presence, PIN, user verification, and hmac-secret are checked independently."
                .to_owned(),
            Vec::new(),
        ),
        FidoCommand::Login { command } => match command {
            FidoLoginCommand::Status => (
                "fido login status".to_owned(),
                true,
                Severity::Warning,
                "recovery-unverified",
                "Credential count alone is not proof that both physical authenticators work."
                    .to_owned(),
                vec!["login".to_owned(), "sddm".to_owned(), "kde".to_owned()],
            ),
            FidoLoginCommand::Plan(_) => (
                "fido login plan".to_owned(),
                true,
                Severity::High,
                "planned",
                "The supported profile keeps Unix password authentication and requires FIDO2 as an additional factor for each explicit service."
                    .to_owned(),
                vec!["login".to_owned(), "sddm".to_owned(), "kde".to_owned()],
            ),
            FidoLoginCommand::Enroll(args) => {
                validate_execution(&args.execution)?;
                (
                    format!("fido login enroll --role {}", args.role.role),
                    !args.execution.apply,
                    Severity::High,
                    "planned",
                    "Only one explicitly assigned authenticator may be attached during enrollment."
                        .to_owned(),
                    vec!["login".to_owned(), "sddm".to_owned(), "kde".to_owned()],
                )
            }
            FidoLoginCommand::Verify(args) => (
                format!("fido login verify --role {}", args.role),
                true,
                Severity::High,
                "recovery-unverified",
                "Verification must keep a privileged session open and test a second session."
                    .to_owned(),
                vec!["login".to_owned(), "sddm".to_owned(), "kde".to_owned()],
            ),
        },
    })
}

fn luks_report(command: &LuksCommand) -> Result<ReportParts, CliError> {
    Ok(match command {
        LuksCommand::Inspect(_) => (
            "luks inspect".to_owned(),
            true,
            Severity::Information,
            "planned",
            "Inspection records LUKS version, UUID, major/minor, keyslots, and redacted token metadata."
                .to_owned(),
            Vec::new(),
        ),
        LuksCommand::Status(_) => (
            "luks status".to_owned(),
            true,
            Severity::Warning,
            "recovery-unverified",
            "Two token metadata entries are insufficient without separate boot tests and recovery proof."
                .to_owned(),
            Vec::new(),
        ),
        LuksCommand::Plan(_) => generic_plan("luks plan", Vec::new()),
        LuksCommand::Enroll(args) => {
            validate_execution(&args.execution)?;
            (
                format!("luks enroll --role {}", args.role.role),
                !args.execution.apply,
                Severity::Critical,
                "planned",
                "Enrollment is additive only; no existing keyslot or recovery access is removed."
                    .to_owned(),
                Vec::new(),
            )
        }
        LuksCommand::Verify(args) => (
            format!("luks verify --role {}", args.role.role),
            true,
            Severity::Critical,
            "recovery-unverified",
            "Final proof is a manual boot with only the selected authenticator attached."
                .to_owned(),
            Vec::new(),
        ),
        LuksCommand::Recovery { command } => match command {
            RecoveryCommand::Plan(_) => (
                "luks recovery plan".to_owned(),
                true,
                Severity::Critical,
                "planned",
                "A systemd recovery key or strong passphrase remains independent of both tokens."
                    .to_owned(),
                Vec::new(),
            ),
        },
    })
}

fn backup_report(
    command: &BackupCommand,
) -> (String, bool, Severity, &'static str, String, Vec<String>) {
    match command {
        BackupCommand::Create(args) => (
            "backup create".to_owned(),
            true,
            if args.include_sensitive {
                Severity::Critical
            } else {
                Severity::High
            },
            "unsupported",
            "The NKFB encryption and manifest policy is modeled, but the production age writer is not enabled in this release."
                .to_owned(),
            Vec::new(),
        ),
        BackupCommand::Inspect(_args) => (
            "backup inspect".to_owned(),
            true,
            Severity::High,
            "unsupported",
            "Ciphertext inspection is disabled until the production age/tar trust boundary is implemented."
                .to_owned(),
            Vec::new(),
        ),
        BackupCommand::Verify(_args) => (
            "backup verify".to_owned(),
            true,
            Severity::High,
            "unsupported",
            "In-memory schema validation exists, but it is not accepted as proof of age authentication or safe tar parsing."
                .to_owned(),
            Vec::new(),
        ),
    }
}

fn validate_execution(args: &ExecutionArgs) -> Result<(), CliError> {
    if args.apply {
        if args.dry_run {
            return Err(CliError::UnsafeApply(
                "apply requires the explicit --dry-run=false acknowledgement".to_owned(),
            ));
        }
        if args.plan_file.is_none() || args.fingerprint.is_none() {
            return Err(CliError::UnsafeApply(
                "apply requires both --plan-file and --fingerprint".to_owned(),
            ));
        }
        return Err(CliError::UnsafeApply(
            "live apply is intentionally unavailable in this development build; review the plan and manual runbook"
                .to_owned(),
        ));
    }
    Ok(())
}

fn default_preconditions() -> Vec<String> {
    [
        "Re-check user, host, configuration revision, and file hashes.",
        "Re-check device major/minor, LUKS UUID, mount role, and keyslots.",
        "Re-check the single attached authenticator and its assigned role.",
        "Recompute and compare the plan fingerprint immediately before apply.",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_verification() -> Vec<String> {
    [
        "Verify primary and backup credentials independently.",
        "Verify the independent recovery route without removing existing access.",
        "Treat hardware-dependent login and boot checks as manual until recorded.",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_recovery() -> Vec<String> {
    [
        "Keep an existing privileged session open for PAM testing.",
        "Keep rescue media, a previous NixOS generation, and recovery material available.",
        "Do not automatically restore a LUKS2 header or remove keyslots.",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn render_human(report: &CommandReport) -> String {
    let mut lines = vec![
        format!("Operation: {}", report.operation),
        format!("State: {}", report.state),
        format!("Dry run: {}", report.dry_run),
        format!("Severity: {:?}", report.severity).to_lowercase(),
        format!("Summary: {}", report.summary),
    ];
    if !report.affected_services.is_empty() {
        lines.push(format!(
            "Affected PAM services: {}",
            report.affected_services.join(", ")
        ));
    }
    if let Some(available) = report.unix_password_available {
        lines.push(format!("Unix password available: {available}"));
    }
    if !report.pam_services.is_empty() {
        lines.push("Per-service PAM state:".to_owned());
        lines.extend(report.pam_services.iter().map(|service| {
            format!(
                "- {}: FIDO2={}, Unix password={}, source={}",
                service.service,
                optional_bool(service.fido2_enabled),
                optional_bool(service.unix_password_available),
                service.source
            )
        }));
    }
    if !report.intentionally_unchanged_services.is_empty() {
        lines.push(format!(
            "Intentionally unchanged PAM services: {}",
            report.intentionally_unchanged_services.join(", ")
        ));
    }
    lines.push("Preconditions:".to_owned());
    lines.extend(report.preconditions.iter().map(|item| format!("- {item}")));
    lines.push("Verification:".to_owned());
    lines.extend(report.verification.iter().map(|item| format!("- {item}")));
    lines.push("Recovery:".to_owned());
    lines.extend(report.recovery.iter().map(|item| format!("- {item}")));
    lines.join("\n")
}

fn optional_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_required_command_family() {
        let commands = [
            ["nixkeyforge", "doctor"].as_slice(),
            ["nixkeyforge", "status"].as_slice(),
            ["nixkeyforge", "plan"].as_slice(),
            ["nixkeyforge", "generate", "--output-dir", "./generated"].as_slice(),
            ["nixkeyforge", "fido", "detect"].as_slice(),
            ["nixkeyforge", "fido", "inventory"].as_slice(),
            ["nixkeyforge", "fido", "capabilities"].as_slice(),
            ["nixkeyforge", "fido", "login", "status"].as_slice(),
            ["nixkeyforge", "fido", "login", "plan"].as_slice(),
            [
                "nixkeyforge",
                "fido",
                "login",
                "enroll",
                "--role",
                "primary",
            ]
            .as_slice(),
            ["nixkeyforge", "fido", "login", "verify", "--role", "backup"].as_slice(),
            ["nixkeyforge", "luks", "inspect"].as_slice(),
            ["nixkeyforge", "luks", "status"].as_slice(),
            ["nixkeyforge", "luks", "plan"].as_slice(),
            ["nixkeyforge", "luks", "enroll", "--role", "primary"].as_slice(),
            ["nixkeyforge", "luks", "verify", "--role", "backup"].as_slice(),
            ["nixkeyforge", "luks", "recovery", "plan"].as_slice(),
            ["nixkeyforge", "ssh", "inspect"].as_slice(),
            ["nixkeyforge", "ssh", "plan"].as_slice(),
            [
                "nixkeyforge",
                "backup",
                "create",
                "--output",
                "backup.age",
                "--recipient",
                "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            ]
            .as_slice(),
            ["nixkeyforge", "backup", "inspect", "--backup", "backup.age"].as_slice(),
            ["nixkeyforge", "backup", "verify", "--backup", "backup.age"].as_slice(),
            ["nixkeyforge", "restore", "plan", "--backup", "backup.age"].as_slice(),
        ];

        for command in commands {
            assert!(Cli::try_parse_from(command).is_ok(), "{command:?}");
        }
    }

    #[test]
    fn json_output_contains_no_credential_material() {
        let cli = Cli::try_parse_from(["nixkeyforge", "--format", "json", "fido", "inventory"]);
        assert!(cli.is_ok());
        let result = cli.and_then(|parsed| {
            execute(&parsed).map_err(|error| clap::Error::raw(clap::error::ErrorKind::Io, error))
        });
        assert!(result.is_ok());
        if let Ok((output, _)) = result {
            assert!(!output.contains("keyHandle"));
            assert!(!output.contains("publicKey"));
            assert!(!output.contains("private"));
        }
    }

    #[test]
    fn apply_is_blocked_in_development_build() {
        let cli = Cli::try_parse_from([
            "nixkeyforge",
            "luks",
            "enroll",
            "--role",
            "primary",
            "--dry-run=false",
            "--apply",
            "--plan-file",
            "plan.json",
            "--fingerprint",
            "sha256:abc",
        ]);
        assert!(cli.is_ok());
        if let Ok(parsed) = cli {
            assert!(execute(&parsed).is_err());
        }
    }

    #[test]
    fn generation_rejects_parent_traversal() {
        let args = GenerateArgs {
            output_dir: PathBuf::from("../unsafe"),
            from_plan: None,
        };
        assert!(matches!(
            generate_module(&args),
            Err(CliError::UnsafeOutput(_))
        ));
    }

    #[test]
    fn generation_is_atomic_and_refuses_overwrite() {
        let temporary = tempfile::tempdir();
        assert!(temporary.is_ok());
        if let Ok(temporary) = temporary {
            let output = temporary.path().join("generated");
            let args = GenerateArgs {
                output_dir: output.clone(),
                from_plan: None,
            };
            assert!(generate_module(&args).is_ok());
            let generated = fs::read_to_string(output.join("nixkeyforge-generated.nix"));
            assert!(generated.is_ok());
            if let Ok(generated) = generated {
                assert!(generated.contains("authFile"));
                assert!(!generated.contains("credential-handle"));
            }
            assert!(generate_module(&args).is_err());
        }
    }

    #[test]
    fn anonymized_passwordless_reference_is_lockout_risk() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/reference")
            .canonicalize();
        assert!(root.is_ok());
        if let Ok(root) = root {
            let cli = Cli {
                format: OutputFormat::Json,
                config_root: root,
                command: TopCommand::Status,
            };
            let result = execute(&cli);
            assert!(result.is_ok());
            if let Ok((report, code)) = result {
                assert_eq!(code, EXIT_BLOCKER);
                assert!(report.contains("lockout-risk"));
                assert!(report.contains("\"unix_password_available\": null"));
                assert!(report.contains("\"pam_services\""));
                assert!(!report.contains("00000000-0000"));
            }
        }
    }

    #[test]
    fn planned_fido_profile_reports_password_fallback_per_service() {
        let cli = Cli {
            format: OutputFormat::Json,
            config_root: PathBuf::from("/unused"),
            command: TopCommand::Fido {
                command: FidoCommand::Login {
                    command: FidoLoginCommand::Plan(PlanArgs { output: None }),
                },
            },
        };
        let result = execute(&cli);
        assert!(result.is_ok());
        if let Ok((report, _)) = result {
            assert!(report.contains("\"unix_password_available\": true"));
            assert!(report.contains("\"source\": \"planned-explicit\""));
        }
    }

    #[test]
    fn backup_requires_authenticated_encryption_selection() {
        let cli = Cli::try_parse_from([
            "nixkeyforge",
            "backup",
            "create",
            "--output",
            "backup.nkfb.age",
        ]);
        assert!(cli.is_ok());
        if let Ok(cli) = cli {
            assert!(execute(&cli).is_err());
        }
    }

    #[test]
    fn backup_rejects_recipient_argument_injection() {
        let cli = Cli::try_parse_from([
            "nixkeyforge",
            "backup",
            "create",
            "--output",
            "backup.nkfb.age",
            "--recipient",
            "age1safe;--output=/etc/shadow",
        ]);
        assert!(cli.is_ok());
        if let Ok(cli) = cli {
            assert!(execute(&cli).is_err());
        }
    }

    #[test]
    fn backup_commands_fail_closed_until_ciphertext_boundary_exists() {
        let cli = Cli::try_parse_from([
            "nixkeyforge",
            "backup",
            "verify",
            "--backup",
            "backup.nkfb.age",
        ]);
        assert!(cli.is_ok());
        if let Ok(cli) = cli {
            let result = execute(&cli);
            assert!(result.is_ok());
            if let Ok((output, code)) = result {
                assert_eq!(code, EXIT_BLOCKER);
                assert!(output.contains("unsupported"));
                assert!(!output.contains("backup.nkfb.age"));
            }
        }
    }
}
