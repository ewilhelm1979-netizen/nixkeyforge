use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::RedactedIdentifier;

/// The operational role of one independent physical authenticator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorRole {
    Primary,
    Backup,
}

impl AuthenticatorRole {
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::Primary => Self::Backup,
            Self::Backup => Self::Primary,
        }
    }
}

impl fmt::Display for AuthenticatorRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primary => formatter.write_str("primary"),
            Self::Backup => formatter.write_str("backup"),
        }
    }
}

impl FromStr for AuthenticatorRole {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "primary" => Ok(Self::Primary),
            "backup" => Ok(Self::Backup),
            _ => Err("role must be `primary` or `backup`"),
        }
    }
}

/// A protection surface with an independent enrollment and verification state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionDomain {
    PamLogin,
    PamDisplayManager,
    PamScreenLocker,
    Luks2,
    SshUser,
}

impl ProtectionDomain {
    #[must_use]
    pub const fn is_pam(self) -> bool {
        matches!(
            self,
            Self::PamLogin | Self::PamDisplayManager | Self::PamScreenLocker
        )
    }
}

/// Lifecycle state of a single role/domain enrollment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnrollmentState {
    Unconfigured,
    Planned,
    Enrolled,
    Verified,
    Degraded,
    Drifted,
    Failed,
}

impl EnrollmentState {
    #[must_use]
    pub const fn is_present(self) -> bool {
        !matches!(self, Self::Unconfigured)
    }
}

/// The user-facing aggregate setup states required by the product.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SetupStatus {
    Unconfigured,
    SingleToken,
    DualTokenIncomplete,
    DualTokenReady,
    RecoveryUnverified,
    LockoutRisk,
    ConfigurationDrift,
    Unsupported,
}

/// Whether credential observations are complete enough for a safety decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceQuality {
    Complete,
    Unverifiable,
}

/// Whether Unix-password authentication remains available.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnixAuthState {
    Enabled,
    Disabled,
    Unknown,
}

/// State of the independent LUKS2 recovery route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryState {
    Missing,
    PresentUnverified,
    Verified,
    Unknown,
}

/// Redacted evidence for one enrollment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentEvidence {
    pub role: AuthenticatorRole,
    pub domain: ProtectionDomain,
    pub state: EnrollmentState,
    /// Fingerprint of the physical authenticator, when it can be established.
    pub authenticator_id: Option<RedactedIdentifier>,
    /// Fingerprint of the PAM, SSH, or LUKS credential entry.
    pub credential_id: Option<RedactedIdentifier>,
    /// Fingerprint of a LUKS token/keyslot assignment.
    pub assignment_id: Option<RedactedIdentifier>,
}

impl EnrollmentEvidence {
    #[must_use]
    pub const fn unconfigured(role: AuthenticatorRole, domain: ProtectionDomain) -> Self {
        Self {
            role,
            domain,
            state: EnrollmentState::Unconfigured,
            authenticator_id: None,
            credential_id: None,
            assignment_id: None,
        }
    }
}

/// Read-only observations supplied by system adapters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupEvidence {
    pub supported: bool,
    pub configuration_drift: bool,
    pub unix_auth: UnixAuthState,
    pub credential_inventory: EvidenceQuality,
    pub recovery: RecoveryState,
    pub privileged_session_retained: bool,
    pub enrollments: Vec<EnrollmentEvidence>,
}

impl Default for SetupEvidence {
    fn default() -> Self {
        Self {
            supported: true,
            configuration_drift: false,
            unix_auth: UnixAuthState::Unknown,
            credential_inventory: EvidenceQuality::Unverifiable,
            recovery: RecoveryState::Unknown,
            privileged_session_retained: false,
            enrollments: Vec::new(),
        }
    }
}

/// Domains that must work for both roles before readiness is reported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupPolicy {
    pub required_domains: BTreeSet<ProtectionDomain>,
    pub require_recovery: bool,
    pub require_privileged_session: bool,
}

impl Default for SetupPolicy {
    fn default() -> Self {
        Self {
            required_domains: [ProtectionDomain::PamLogin, ProtectionDomain::Luks2]
                .into_iter()
                .collect(),
            require_recovery: true,
            require_privileged_session: true,
        }
    }
}

/// Machine-readable explanation for a conservative aggregate status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatusReason {
    UnsupportedPlatform,
    UnixAuthDisabled,
    CredentialInventoryUnverifiable,
    FewerThanTwoVerifiedPamCredentials,
    ConfigurationDriftDetected,
    NoEnrollment,
    OnlyOneAuthenticatorRole,
    RequiredEnrollmentNotVerified,
    DuplicateEnrollmentEvidence,
    AuthenticatorIdentityUnverifiable,
    DuplicateAuthenticator,
    CredentialIdentityUnverifiable,
    DuplicatePamCredential,
    LuksAssignmentUnverifiable,
    DuplicateLuksAssignment,
    RecoveryMissing,
    RecoveryUnverified,
    PrivilegedSessionNotRetained,
}

/// Aggregate status plus the reasons needed by human and JSON frontends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusAssessment {
    pub status: SetupStatus,
    pub reasons: BTreeSet<StatusReason>,
    pub verified_pam_credentials: usize,
}

fn verified_pam_credentials(evidence: &SetupEvidence, policy: &SetupPolicy) -> (usize, bool) {
    let mut pam_domains: BTreeSet<_> = policy
        .required_domains
        .iter()
        .copied()
        .filter(|domain| domain.is_pam())
        .collect();
    if pam_domains.is_empty() {
        pam_domains.extend(
            evidence
                .enrollments
                .iter()
                .map(|entry| entry.domain)
                .filter(|domain| domain.is_pam()),
        );
    }

    let mut minimum_count = None;
    let mut every_domain_has_two_roles = !pam_domains.is_empty();
    for domain in pam_domains {
        let mut credentials = BTreeSet::new();
        let mut roles = BTreeSet::new();
        let mut authenticators = BTreeSet::new();
        let mut missing_authenticator_identity = false;
        for enrollment in &evidence.enrollments {
            if enrollment.domain == domain && enrollment.state == EnrollmentState::Verified {
                if let Some(identifier) = enrollment.credential_id {
                    credentials.insert(identifier);
                    roles.insert(enrollment.role);
                }
                match enrollment.authenticator_id {
                    Some(identifier) => {
                        authenticators.insert(identifier);
                    }
                    None => missing_authenticator_identity = true,
                }
            }
        }
        minimum_count = Some(minimum_count.map_or(credentials.len(), |current: usize| {
            current.min(credentials.len())
        }));
        every_domain_has_two_roles &= credentials.len() >= 2
            && roles.len() >= 2
            && authenticators.len() >= 2
            && !missing_authenticator_identity;
    }
    (minimum_count.unwrap_or(0), every_domain_has_two_roles)
}

/// Derives status without optimistic assumptions.
///
/// `lockout-risk` deliberately takes precedence over drift: a disabled Unix
/// fallback with fewer than two independently verified or inspectable PAM
/// credentials is the most urgent finding.
#[must_use]
pub fn derive_status(evidence: &SetupEvidence, policy: &SetupPolicy) -> StatusAssessment {
    let (verified_pam_count, every_pam_domain_has_two_roles) =
        verified_pam_credentials(evidence, policy);
    let mut reasons = BTreeSet::new();

    if !evidence.supported {
        reasons.insert(StatusReason::UnsupportedPlatform);
        return StatusAssessment {
            status: SetupStatus::Unsupported,
            reasons,
            verified_pam_credentials: verified_pam_count,
        };
    }

    if evidence.unix_auth == UnixAuthState::Disabled {
        reasons.insert(StatusReason::UnixAuthDisabled);
        if evidence.credential_inventory == EvidenceQuality::Unverifiable {
            reasons.insert(StatusReason::CredentialInventoryUnverifiable);
        }
        if !every_pam_domain_has_two_roles {
            reasons.insert(StatusReason::FewerThanTwoVerifiedPamCredentials);
        }
        if evidence.credential_inventory == EvidenceQuality::Unverifiable
            || !every_pam_domain_has_two_roles
        {
            return StatusAssessment {
                status: SetupStatus::LockoutRisk,
                reasons,
                verified_pam_credentials: verified_pam_count,
            };
        }
    }

    if evidence.configuration_drift
        || evidence
            .enrollments
            .iter()
            .any(|entry| entry.state == EnrollmentState::Drifted)
    {
        reasons.insert(StatusReason::ConfigurationDriftDetected);
        return StatusAssessment {
            status: SetupStatus::ConfigurationDrift,
            reasons,
            verified_pam_credentials: verified_pam_count,
        };
    }

    let present_roles: BTreeSet<_> = evidence
        .enrollments
        .iter()
        .filter(|entry| entry.state.is_present())
        .map(|entry| entry.role)
        .collect();
    if present_roles.is_empty() {
        reasons.insert(StatusReason::NoEnrollment);
        return StatusAssessment {
            status: SetupStatus::Unconfigured,
            reasons,
            verified_pam_credentials: verified_pam_count,
        };
    }
    if present_roles.len() == 1 {
        reasons.insert(StatusReason::OnlyOneAuthenticatorRole);
        return StatusAssessment {
            status: SetupStatus::SingleToken,
            reasons,
            verified_pam_credentials: verified_pam_count,
        };
    }

    let mut by_role_domain: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for enrollment in &evidence.enrollments {
        by_role_domain
            .entry((enrollment.role, enrollment.domain))
            .or_default()
            .push(enrollment);
    }

    let mut complete = true;
    if evidence.credential_inventory == EvidenceQuality::Unverifiable {
        reasons.insert(StatusReason::CredentialInventoryUnverifiable);
        complete = false;
    }
    let mut authenticator_ids = BTreeMap::new();
    for role in [AuthenticatorRole::Primary, AuthenticatorRole::Backup] {
        for domain in &policy.required_domains {
            let Some(entries) = by_role_domain.get(&(role, *domain)) else {
                reasons.insert(StatusReason::RequiredEnrollmentNotVerified);
                complete = false;
                continue;
            };
            if entries.len() != 1 {
                reasons.insert(StatusReason::DuplicateEnrollmentEvidence);
                complete = false;
                continue;
            }
            let entry = entries[0];
            if entry.state != EnrollmentState::Verified {
                reasons.insert(StatusReason::RequiredEnrollmentNotVerified);
                complete = false;
            }
            match entry.authenticator_id {
                Some(identifier) => {
                    if authenticator_ids
                        .insert(role, identifier)
                        .is_some_and(|previous| previous != identifier)
                    {
                        reasons.insert(StatusReason::AuthenticatorIdentityUnverifiable);
                        complete = false;
                    }
                }
                None => {
                    reasons.insert(StatusReason::AuthenticatorIdentityUnverifiable);
                    complete = false;
                }
            }
        }
    }

    if let (Some(primary), Some(backup)) = (
        authenticator_ids.get(&AuthenticatorRole::Primary),
        authenticator_ids.get(&AuthenticatorRole::Backup),
    ) {
        if primary == backup {
            reasons.insert(StatusReason::DuplicateAuthenticator);
            complete = false;
        }
    }

    for domain in &policy.required_domains {
        let primary = by_role_domain
            .get(&(AuthenticatorRole::Primary, *domain))
            .and_then(|entries| (entries.len() == 1).then_some(entries[0]));
        let backup = by_role_domain
            .get(&(AuthenticatorRole::Backup, *domain))
            .and_then(|entries| (entries.len() == 1).then_some(entries[0]));

        if domain.is_pam() {
            match (
                primary.and_then(|entry| entry.credential_id),
                backup.and_then(|entry| entry.credential_id),
            ) {
                (Some(first), Some(second)) if first != second => {}
                (Some(_), Some(_)) => {
                    reasons.insert(StatusReason::DuplicatePamCredential);
                    complete = false;
                }
                _ => {
                    reasons.insert(StatusReason::CredentialIdentityUnverifiable);
                    complete = false;
                }
            }
        }

        if *domain == ProtectionDomain::Luks2 {
            match (
                primary.and_then(|entry| entry.assignment_id),
                backup.and_then(|entry| entry.assignment_id),
            ) {
                (Some(first), Some(second)) if first != second => {}
                (Some(_), Some(_)) => {
                    reasons.insert(StatusReason::DuplicateLuksAssignment);
                    complete = false;
                }
                _ => {
                    reasons.insert(StatusReason::LuksAssignmentUnverifiable);
                    complete = false;
                }
            }
        }
    }

    if !complete {
        return StatusAssessment {
            status: SetupStatus::DualTokenIncomplete,
            reasons,
            verified_pam_credentials: verified_pam_count,
        };
    }

    if policy.require_recovery {
        match evidence.recovery {
            RecoveryState::Verified => {}
            RecoveryState::Missing => {
                reasons.insert(StatusReason::RecoveryMissing);
                return StatusAssessment {
                    status: SetupStatus::DualTokenIncomplete,
                    reasons,
                    verified_pam_credentials: verified_pam_count,
                };
            }
            RecoveryState::PresentUnverified | RecoveryState::Unknown => {
                reasons.insert(StatusReason::RecoveryUnverified);
                return StatusAssessment {
                    status: SetupStatus::RecoveryUnverified,
                    reasons,
                    verified_pam_credentials: verified_pam_count,
                };
            }
        }
    }

    if policy.require_privileged_session && !evidence.privileged_session_retained {
        reasons.insert(StatusReason::PrivilegedSessionNotRetained);
        return StatusAssessment {
            status: SetupStatus::DualTokenIncomplete,
            reasons,
            verified_pam_credentials: verified_pam_count,
        };
    }

    StatusAssessment {
        status: SetupStatus::DualTokenReady,
        reasons,
        verified_pam_credentials: verified_pam_count,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn id(domain: &'static str, value: &str) -> RedactedIdentifier {
        RedactedIdentifier::new(domain, value.as_bytes()).unwrap()
    }

    fn verified(
        role: AuthenticatorRole,
        domain: ProtectionDomain,
        auth: &str,
        credential: &str,
        assignment: Option<&str>,
    ) -> EnrollmentEvidence {
        EnrollmentEvidence {
            role,
            domain,
            state: EnrollmentState::Verified,
            authenticator_id: Some(id("authenticator", auth)),
            credential_id: Some(id("credential", credential)),
            assignment_id: assignment.map(|value| id("assignment", value)),
        }
    }

    fn ready_evidence() -> SetupEvidence {
        SetupEvidence {
            supported: true,
            configuration_drift: false,
            unix_auth: UnixAuthState::Disabled,
            credential_inventory: EvidenceQuality::Complete,
            recovery: RecoveryState::Verified,
            privileged_session_retained: true,
            enrollments: vec![
                verified(
                    AuthenticatorRole::Primary,
                    ProtectionDomain::PamLogin,
                    "primary",
                    "pam-primary",
                    None,
                ),
                verified(
                    AuthenticatorRole::Backup,
                    ProtectionDomain::PamLogin,
                    "backup",
                    "pam-backup",
                    None,
                ),
                verified(
                    AuthenticatorRole::Primary,
                    ProtectionDomain::Luks2,
                    "primary",
                    "luks-primary",
                    Some("slot-primary"),
                ),
                verified(
                    AuthenticatorRole::Backup,
                    ProtectionDomain::Luks2,
                    "backup",
                    "luks-backup",
                    Some("slot-backup"),
                ),
            ],
        }
    }

    #[test]
    fn roles_round_trip_and_have_an_inverse() {
        for role in [AuthenticatorRole::Primary, AuthenticatorRole::Backup] {
            assert_eq!(role.to_string().parse(), Ok(role));
            assert_eq!(role.other().other(), role);
        }
    }

    #[test]
    fn status_transitions_are_conservative() {
        let policy = SetupPolicy::default();
        let mut evidence = SetupEvidence {
            credential_inventory: EvidenceQuality::Complete,
            unix_auth: UnixAuthState::Enabled,
            ..SetupEvidence::default()
        };
        assert_eq!(
            derive_status(&evidence, &policy).status,
            SetupStatus::Unconfigured
        );

        evidence.enrollments.push(EnrollmentEvidence {
            state: EnrollmentState::Planned,
            ..EnrollmentEvidence::unconfigured(
                AuthenticatorRole::Primary,
                ProtectionDomain::PamLogin,
            )
        });
        assert_eq!(
            derive_status(&evidence, &policy).status,
            SetupStatus::SingleToken
        );

        evidence = ready_evidence();
        evidence.recovery = RecoveryState::PresentUnverified;
        assert_eq!(
            derive_status(&evidence, &policy).status,
            SetupStatus::RecoveryUnverified
        );
        evidence.recovery = RecoveryState::Verified;
        assert_eq!(
            derive_status(&evidence, &policy).status,
            SetupStatus::DualTokenReady
        );
    }

    #[test]
    fn disabled_unix_auth_with_one_credential_is_lockout_risk() {
        let mut evidence = SetupEvidence {
            unix_auth: UnixAuthState::Disabled,
            credential_inventory: EvidenceQuality::Complete,
            ..SetupEvidence::default()
        };
        evidence.enrollments.push(verified(
            AuthenticatorRole::Primary,
            ProtectionDomain::PamLogin,
            "primary",
            "pam-primary",
            None,
        ));
        let assessment = derive_status(&evidence, &SetupPolicy::default());
        assert_eq!(assessment.status, SetupStatus::LockoutRisk);
        assert!(
            assessment
                .reasons
                .contains(&StatusReason::FewerThanTwoVerifiedPamCredentials)
        );
    }

    #[test]
    fn disabled_unix_auth_with_unverifiable_hardware_is_lockout_risk() {
        let mut evidence = ready_evidence();
        evidence.credential_inventory = EvidenceQuality::Unverifiable;
        assert_eq!(
            derive_status(&evidence, &SetupPolicy::default()).status,
            SetupStatus::LockoutRisk
        );
    }

    #[test]
    fn credentials_from_different_pam_domains_do_not_mask_lockout_risk() {
        let evidence = SetupEvidence {
            unix_auth: UnixAuthState::Disabled,
            credential_inventory: EvidenceQuality::Complete,
            enrollments: vec![
                verified(
                    AuthenticatorRole::Primary,
                    ProtectionDomain::PamLogin,
                    "primary",
                    "pam-login-primary",
                    None,
                ),
                verified(
                    AuthenticatorRole::Backup,
                    ProtectionDomain::PamDisplayManager,
                    "backup",
                    "pam-sddm-backup",
                    None,
                ),
            ],
            ..SetupEvidence::default()
        };
        assert_eq!(
            derive_status(&evidence, &SetupPolicy::default()).status,
            SetupStatus::LockoutRisk
        );
    }

    #[test]
    fn unverifiable_inventory_never_reports_ready_with_unix_auth_enabled() {
        let mut evidence = ready_evidence();
        evidence.unix_auth = UnixAuthState::Enabled;
        evidence.credential_inventory = EvidenceQuality::Unverifiable;
        assert_eq!(
            derive_status(&evidence, &SetupPolicy::default()).status,
            SetupStatus::DualTokenIncomplete
        );
    }

    #[test]
    fn duplicate_physical_authenticator_never_becomes_ready() {
        let mut evidence = ready_evidence();
        evidence.unix_auth = UnixAuthState::Enabled;
        let duplicate = id("authenticator", "primary");
        for enrollment in &mut evidence.enrollments {
            enrollment.authenticator_id = Some(duplicate);
        }
        let assessment = derive_status(&evidence, &SetupPolicy::default());
        assert_eq!(assessment.status, SetupStatus::DualTokenIncomplete);
        assert!(
            assessment
                .reasons
                .contains(&StatusReason::DuplicateAuthenticator)
        );
    }

    #[test]
    fn duplicate_physical_authenticator_with_disabled_unix_auth_is_lockout_risk() {
        let mut evidence = ready_evidence();
        let duplicate = id("authenticator", "primary");
        for enrollment in &mut evidence.enrollments {
            enrollment.authenticator_id = Some(duplicate);
        }
        assert_eq!(
            derive_status(&evidence, &SetupPolicy::default()).status,
            SetupStatus::LockoutRisk
        );
    }

    #[test]
    fn duplicate_luks_assignment_never_becomes_ready() {
        let mut evidence = ready_evidence();
        let duplicate = id("assignment", "slot-primary");
        for enrollment in &mut evidence.enrollments {
            if enrollment.domain == ProtectionDomain::Luks2 {
                enrollment.assignment_id = Some(duplicate);
            }
        }
        let assessment = derive_status(&evidence, &SetupPolicy::default());
        assert_eq!(assessment.status, SetupStatus::DualTokenIncomplete);
        assert!(
            assessment
                .reasons
                .contains(&StatusReason::DuplicateLuksAssignment)
        );
    }

    #[test]
    fn lockout_risk_takes_precedence_over_drift() {
        let evidence = SetupEvidence {
            configuration_drift: true,
            unix_auth: UnixAuthState::Disabled,
            credential_inventory: EvidenceQuality::Unverifiable,
            ..SetupEvidence::default()
        };
        assert_eq!(
            derive_status(&evidence, &SetupPolicy::default()).status,
            SetupStatus::LockoutRisk
        );
    }

    #[test]
    fn unsupported_and_drift_states_are_derived_explicitly() {
        let unsupported = SetupEvidence {
            supported: false,
            ..SetupEvidence::default()
        };
        assert_eq!(
            derive_status(&unsupported, &SetupPolicy::default()).status,
            SetupStatus::Unsupported
        );

        let drifted = SetupEvidence {
            configuration_drift: true,
            unix_auth: UnixAuthState::Enabled,
            credential_inventory: EvidenceQuality::Complete,
            ..SetupEvidence::default()
        };
        assert_eq!(
            derive_status(&drifted, &SetupPolicy::default()).status,
            SetupStatus::ConfigurationDrift
        );
    }
}
