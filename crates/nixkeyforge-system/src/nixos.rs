use crate::command::{CommandSpec, InputPolicy, Program};
use crate::pam::PamInventory;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PamService {
    Login,
    Sddm,
    PlasmaScreenLocker,
    Sudo,
    Polkit,
    Su,
    Sshd,
}

impl PamService {
    const ALL: [Self; 7] = [
        Self::Login,
        Self::Sddm,
        Self::PlasmaScreenLocker,
        Self::Sudo,
        Self::Polkit,
        Self::Su,
        Self::Sshd,
    ];

    pub const fn nix_name(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Sddm => "sddm",
            Self::PlasmaScreenLocker => "kde",
            Self::Sudo => "sudo",
            Self::Polkit => "polkit-1",
            Self::Su => "su",
            Self::Sshd => "sshd",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PamServiceDiscovery {
    pub service: PamService,
    pub u2f_auth: Option<bool>,
    pub unix_auth: Option<bool>,
    pub u2f_source: PamU2fSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PamU2fSource {
    Explicit,
    GlobalInherited,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NixosDiscovery {
    pub systemd_initrd: Option<bool>,
    pub luks_fido2_auto: bool,
    pub pam_services: Vec<PamServiceDiscovery>,
    pub openssh_server_enabled: Option<bool>,
    pub global_u2f_mapping: bool,
    pub global_u2f_enabled: Option<bool>,
}

/// Conservative structural discovery for Nix source. Unknown settings remain `None`;
/// this never claims to replace evaluation against the pinned nixpkgs revision.
pub fn discover_nixos_source(source: &str) -> NixosDiscovery {
    let compact = compact_nix(source);
    let boot_scope = find_nested_scope(&compact, &["boot"]);
    let initrd_scope = boot_scope.and_then(|scope| find_nested_scope(scope, &["initrd"]));
    let initrd_systemd_scope =
        initrd_scope.and_then(|scope| find_nested_scope(scope, &["systemd"]));
    let systemd_initrd = assigned_bool(&compact, "boot.initrd.systemd.enable=")
        .or_else(|| initrd_systemd_scope.and_then(|scope| assigned_bool(scope, "enable=")));
    let security_pam_scope = find_nested_scope(&compact, &["security", "pam"]);
    let global_u2f_scope = security_pam_scope.and_then(|scope| find_nested_scope(scope, &["u2f"]));
    let global_u2f_enabled = assigned_bool(&compact, "security.pam.u2f.enable=")
        .or_else(|| global_u2f_scope.and_then(|scope| assigned_bool(scope, "enable=")));
    let pam_services = PamService::ALL
        .into_iter()
        .filter_map(|service| -> Option<PamServiceDiscovery> {
            let prefix = format!("security.pam.services.{}.", service.nix_name());
            let service_scope = security_pam_scope
                .and_then(|scope| find_nested_scope(scope, &["services", service.nix_name()]));
            let explicit_u2f = assigned_bool(&compact, &format!("{prefix}u2fAuth="))
                .or_else(|| assigned_bool(&compact, &format!("{prefix}u2f.enable=")))
                .or_else(|| service_scope.and_then(|scope| assigned_bool(scope, "u2fAuth=")))
                .or_else(|| {
                    service_scope
                        .and_then(|scope| find_nested_scope(scope, &["u2f"]))
                        .and_then(|scope| assigned_bool(scope, "enable="))
                });
            let unix_auth = assigned_bool(&compact, &format!("{prefix}unixAuth="))
                .or_else(|| service_scope.and_then(|scope| assigned_bool(scope, "unixAuth=")));
            let u2f_auth = explicit_u2f.or(global_u2f_enabled);
            (u2f_auth.is_some() || unix_auth.is_some()).then_some(PamServiceDiscovery {
                service,
                u2f_auth,
                unix_auth,
                u2f_source: if explicit_u2f.is_some() {
                    PamU2fSource::Explicit
                } else if global_u2f_enabled.is_some() {
                    PamU2fSource::GlobalInherited
                } else {
                    PamU2fSource::Unknown
                },
            })
        })
        .collect();
    let openssh_server_enabled =
        assigned_bool(&compact, "services.openssh.enable=").or_else(|| {
            find_nested_scope(&compact, &["services", "openssh"])
                .and_then(|scope| assigned_bool(scope, "enable="))
        });
    NixosDiscovery {
        systemd_initrd,
        luks_fido2_auto: compact.contains("fido2-device=auto"),
        pam_services,
        openssh_server_enabled,
        global_u2f_mapping: compact.contains("/etc/u2f_mappings")
            || compact.contains("security.pam.u2f.settings.authfile=")
            || global_u2f_scope.is_some_and(|scope| scope.contains("settings.authfile=")),
        global_u2f_enabled,
    }
}

fn compact_nix(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .flat_map(str::chars)
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn assigned_bool(compact: &str, prefix: &str) -> Option<bool> {
    let remainder = compact.split_once(prefix)?.1;
    if remainder.starts_with("true;") {
        Some(true)
    } else if remainder.starts_with("false;") {
        Some(false)
    } else {
        None
    }
}

fn find_nested_scope<'a>(source: &'a str, path: &[&str]) -> Option<&'a str> {
    let (first, remaining) = path.split_first()?;
    let joined = path.join(".");
    if let Some(scope) = find_attrset_scope(source, &joined) {
        return Some(scope);
    }
    let scope = find_attrset_scope(source, first)?;
    if remaining.is_empty() {
        Some(scope)
    } else {
        find_nested_scope(scope, remaining)
    }
}

fn find_attrset_scope<'a>(source: &'a str, attribute: &str) -> Option<&'a str> {
    let needle = format!("{attribute}={{");
    let start = source.find(&needle)? + needle.len();
    let bytes = source.as_bytes();
    let mut depth = 1_u32;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, byte) in bytes[start..].iter().copied().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return source.get(start..start + offset);
                }
            }
            _ => {}
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NixosOption {
    SystemdInitrd,
    PamU2fAuth,
    PamUnixAuth,
    LuksCrypttabExtraOpts,
}

impl NixosOption {
    const fn attribute(self) -> &'static str {
        match self {
            Self::SystemdInitrd => "evaluated.options.boot.initrd.systemd.enable.type.description",
            Self::PamU2fAuth => "services.u2f.enable.type.description",
            Self::PamUnixAuth => "services.unixAuth.type.description",
            Self::LuksCrypttabExtraOpts => "luks.crypttabExtraOpts.type.description",
        }
    }
}

const PINNED_NIXPKGS_REVISION: &str = "597283ad8aa0b331c788e97c4c262d58877074ef";

pub fn nixos_version_command() -> CommandSpec {
    CommandSpec::new(Program::NixosVersion, ["--json"], InputPolicy::Null)
}

/// The flake reference is deliberately fixed; arbitrary nix expressions cannot be
/// supplied through this adapter.
pub fn nixos_option_command(option: NixosOption) -> CommandSpec {
    let expression = format!(
        "let nixpkgs = builtins.getFlake \"github:NixOS/nixpkgs/{PINNED_NIXPKGS_REVISION}\"; \
         evaluated = nixpkgs.lib.nixosSystem {{ system = \"x86_64-linux\"; modules = [ ]; }}; \
         services = evaluated.options.security.pam.services.type.getSubOptions [ ]; \
         luks = evaluated.options.boot.initrd.luks.devices.type.getSubOptions [ ]; \
         in {}",
        option.attribute()
    );
    CommandSpec::new(
        Program::Nix,
        [
            "eval".to_owned(),
            "--json".to_owned(),
            "--expr".to_owned(),
            expression,
        ],
        InputPolicy::Null,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticState {
    Unconfigured,
    SingleToken,
    DualTokenIncomplete,
    DualTokenReady,
    RecoveryUnverified,
    LockoutRisk,
    ConfigurationDrift,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingSeverity {
    Information,
    Warning,
    Blocker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceFinding {
    pub code: &'static str,
    pub severity: FindingSeverity,
    pub message: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceDiagnosis {
    pub state: DiagnosticState,
    pub findings: Vec<ReferenceFinding>,
    pub configured_credentials: usize,
    pub credentials_hardware_verified: bool,
}

/// Diagnose a reference configuration without exposing usernames or credentials.
pub fn diagnose_reference(
    discovery: &NixosDiscovery,
    inventory: &PamInventory,
    verified_hardware_credentials: Option<usize>,
    recovery_verified: bool,
) -> ReferenceDiagnosis {
    let configured_credentials = inventory
        .users
        .iter()
        .map(|user| user.credential_ids.len())
        .max()
        .unwrap_or(0);
    let passwordless_u2f = discovery
        .pam_services
        .iter()
        .any(|service| service.u2f_auth == Some(true) && service.unix_auth == Some(false));
    let mut findings = Vec::new();

    if inventory.duplicate_user_lines > 0 {
        findings.push(ReferenceFinding {
            code: "PAM_MAPPING_DUPLICATE_USER",
            severity: FindingSeverity::Blocker,
            message: "The PAM mapping contains ambiguous duplicate user records.",
        });
    }
    if passwordless_u2f {
        findings.push(ReferenceFinding {
            code: "PAM_PASSWORDLESS_DUAL_TOKEN_UNVERIFIED",
            severity: FindingSeverity::Blocker,
            message:
                "This structural diagnostic cannot bind two independent hardware proofs to the passwordless PAM services.",
        });
    }
    if verified_hardware_credentials.is_none() && configured_credentials > 0 {
        findings.push(ReferenceFinding {
            code: "PAM_HARDWARE_NOT_VERIFIED",
            severity: FindingSeverity::Warning,
            message: "Mapping entries exist, but authenticator operation was not verified.",
        });
    }
    if !recovery_verified && configured_credentials >= 2 {
        findings.push(ReferenceFinding {
            code: "RECOVERY_NOT_VERIFIED",
            severity: FindingSeverity::Warning,
            message: "An independent recovery path has not been verified.",
        });
    }
    if verified_hardware_credentials.is_some_and(|count| count >= 2) {
        findings.push(ReferenceFinding {
            code: "PAM_HARDWARE_COUNT_UNBOUND",
            severity: FindingSeverity::Warning,
            message:
                "A hardware count without per-role, per-service credential evidence cannot prove dual-token readiness.",
        });
    }

    let state = if inventory.duplicate_user_lines > 0 || passwordless_u2f {
        DiagnosticState::LockoutRisk
    } else {
        match verified_hardware_credentials {
            None if configured_credentials == 0 => DiagnosticState::Unconfigured,
            None => DiagnosticState::DualTokenIncomplete,
            Some(0) => DiagnosticState::Unconfigured,
            Some(1) => DiagnosticState::SingleToken,
            Some(count) if count >= 2 && !recovery_verified => DiagnosticState::RecoveryUnverified,
            Some(count) if count >= 2 => DiagnosticState::DualTokenIncomplete,
            Some(_) => DiagnosticState::DualTokenIncomplete,
        }
    };
    ReferenceDiagnosis {
        state,
        findings,
        configured_credentials,
        credentials_hardware_verified: false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NixosPaths {
    pub root: PathBuf,
    pub host_configuration: PathBuf,
    pub hardware_configuration: PathBuf,
    pub home_manager_configuration: PathBuf,
    pub flake: PathBuf,
    pub lock: PathBuf,
}

impl NixosPaths {
    pub fn under(root: &Path) -> Result<Self, crate::fs::FileSecurityError> {
        crate::fs::validate_absolute_path(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            host_configuration: root.join("hosts/nixos/configuration.nix"),
            hardware_configuration: root.join("hosts/nixos/hardware-configuration.nix"),
            home_manager_configuration: root.join("home/example/home.nix"),
            flake: root.join("flake.nix"),
            lock: root.join("flake.lock"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pam::PamMappingDocument;

    const REFERENCE_SHAPE: &str = r#"
      boot.initrd.systemd.enable = true;
      boot.initrd.luks.devices."redacted".crypttabExtraOpts = [
        "fido2-device=auto"
      ];
      security.pam.u2f.settings.authfile = "/etc/u2f_mappings";
      security.pam.services.login.u2fAuth = true;
      security.pam.services.login.unixAuth = false;
      security.pam.services.sddm.u2fAuth = true;
      security.pam.services.sddm.unixAuth = false;
      services.openssh.enable = false;
    "#;

    #[test]
    fn discovers_anonymized_reference_structure() {
        let discovery = discover_nixos_source(REFERENCE_SHAPE);
        assert_eq!(discovery.systemd_initrd, Some(true));
        assert!(discovery.luks_fido2_auto);
        assert!(discovery.global_u2f_mapping);
        assert_eq!(discovery.openssh_server_enabled, Some(false));
        assert_eq!(discovery.pam_services.len(), 2);
    }

    #[test]
    fn passwordless_single_credential_is_lockout_risk() -> Result<(), crate::pam::PamMappingError> {
        let discovery = discover_nixos_source(REFERENCE_SHAPE);
        let mapping = PamMappingDocument::parse(b"example:a2V5SGFuZGxl,cHVibGljS2V5\n")?;
        let diagnosis = diagnose_reference(&discovery, &mapping.inventory(), Some(1), false);
        assert_eq!(diagnosis.state, DiagnosticState::LockoutRisk);
        assert_eq!(diagnosis.configured_credentials, 1);
        Ok(())
    }

    #[test]
    fn unavailable_hardware_never_returns_ready() -> Result<(), crate::pam::PamMappingError> {
        let discovery = discover_nixos_source(
            "security.pam.services.login.u2fAuth=true;\
             security.pam.services.login.unixAuth=true;",
        );
        let mapping =
            PamMappingDocument::parse(b"example:a2V5SGFuZGxl,cHVibGljS2V5:b3RoZXI,a2V5\n")?;
        let diagnosis = diagnose_reference(&discovery, &mapping.inventory(), None, true);
        assert_ne!(diagnosis.state, DiagnosticState::DualTokenReady);
        assert!(!diagnosis.credentials_hardware_verified);
        Ok(())
    }

    #[test]
    fn unbound_hardware_count_never_returns_ready() -> Result<(), crate::pam::PamMappingError> {
        let discovery = discover_nixos_source(
            "security.pam.services.login.u2fAuth=true;\
             security.pam.services.login.unixAuth=true;",
        );
        let mapping =
            PamMappingDocument::parse(b"example:a2V5SGFuZGxl,cHVibGljS2V5:b3RoZXI,a2V5\n")?;
        let diagnosis = diagnose_reference(&discovery, &mapping.inventory(), Some(2), true);
        assert_eq!(diagnosis.state, DiagnosticState::DualTokenIncomplete);
        assert!(!diagnosis.credentials_hardware_verified);
        Ok(())
    }

    #[test]
    fn comments_do_not_create_false_discovery() {
        let discovery = discover_nixos_source(
            "# boot.initrd.systemd.enable = true;\nservices.openssh.enable = false;",
        );
        assert_ne!(discovery.systemd_initrd, Some(true));
    }

    #[test]
    fn option_checks_are_fixed_to_the_pinned_revision() {
        for option in [
            NixosOption::SystemdInitrd,
            NixosOption::PamU2fAuth,
            NixosOption::PamUnixAuth,
            NixosOption::LuksCrypttabExtraOpts,
        ] {
            let command = nixos_option_command(option);
            assert_eq!(command.program(), Program::Nix);
            assert!(command.arguments().iter().any(|argument| {
                argument.contains(PINNED_NIXPKGS_REVISION) && argument.contains("builtins.getFlake")
            }));
            assert!(
                !command
                    .arguments()
                    .iter()
                    .any(|argument| argument == "--apply")
            );
        }
    }

    #[test]
    fn reads_nested_reference_fixture_and_models_global_inheritance() {
        let source =
            include_str!("../../../tests/fixtures/reference/hosts/workstation/configuration.nix");
        let discovery = discover_nixos_source(source);
        assert_eq!(discovery.systemd_initrd, Some(true));
        assert_eq!(discovery.global_u2f_enabled, Some(true));
        assert_eq!(discovery.openssh_server_enabled, Some(false));
        let inherited = discovery
            .pam_services
            .iter()
            .filter(|service| service.u2f_source == PamU2fSource::GlobalInherited)
            .count();
        assert!(inherited >= 1);

        let mapping = PamMappingDocument::parse(b"example:a2V5SGFuZGxl,cHVibGljS2V5\n");
        assert!(mapping.is_ok());
        if let Ok(mapping) = mapping {
            let diagnosis = diagnose_reference(&discovery, &mapping.inventory(), Some(1), false);
            assert_eq!(diagnosis.state, DiagnosticState::LockoutRisk);
        }
    }
}
