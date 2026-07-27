use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    AuthenticatorRole, BackupClass, ProtectionDomain, RedactedIdentifier, Sha256Digest,
    ValidationError,
};

pub const PLAN_SCHEMA_VERSION: u32 = 1;

/// Security impact of a planned action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// A fixed operation vocabulary; arbitrary executable names are not representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanOperation {
    GenerateConfiguration,
    EnrollPamCredential,
    VerifyPamCredential,
    EnrollLuks2Token,
    VerifyLuks2Token,
    PlanLuksRecovery,
    ConfigureSsh,
    CreateBackup,
    VerifyBackup,
    PlanRestore,
}

/// State that must match immediately before applying a plan.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "identifier")]
pub enum BindingSubject {
    User,
    Host,
    ConfigurationRevision,
    File(RedactedIdentifier),
    DeviceMajorMinor,
    LuksUuid,
    ExpectedMountRole,
    Authenticator,
    AuthenticatorRole,
}

/// A redacted/hash-only precondition captured during discovery.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanBinding {
    pub subject: BindingSubject,
    pub expected: RedactedIdentifier,
}

/// Typed actions that a system adapter may translate to allowlisted commands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum PlanAction {
    GenerateNixModule,
    EnsureOnlyAuthenticatorPresent {
        role: AuthenticatorRole,
    },
    CreatePamCredential {
        role: AuthenticatorRole,
        domain: ProtectionDomain,
    },
    UpdatePamMappingAtomically {
        role: AuthenticatorRole,
    },
    CreateEncryptedLuksHeaderBackup,
    EnrollLuks2Token {
        role: AuthenticatorRole,
    },
    InventoryLuks2Tokens,
    VerifyEnrollment {
        role: AuthenticatorRole,
        domain: ProtectionDomain,
    },
    ConfigureSshClient,
    ConfigureSshServer,
    CreateBackup {
        class: BackupClass,
    },
    VerifyBackup,
    StageRestore,
}

/// One ordered plan action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStep {
    pub sequence: u16,
    pub action: PlanAction,
    pub risk: RiskLevel,
    pub requires_confirmation: bool,
}

/// Evidence that must be collected after apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationKind {
    PamAuthentication,
    SeparatePamCredential,
    LuksEnrollment,
    SeparateLuksAssignment,
    ManualBootWithOnlySelectedAuthenticator,
    IndependentRecovery,
    FileOwnershipAndMode,
    BackupAuthentication,
    BackupChecksum,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRequirement {
    pub role: Option<AuthenticatorRole>,
    pub domain: Option<ProtectionDomain>,
    pub kind: VerificationKind,
}

/// Recovery guidance is typed so secrets cannot be embedded in free-form text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryAction {
    KeepPrivilegedSessionOpen,
    PreservePreviousNixosGeneration,
    KeepRescueMediaAvailable,
    KeepIndependentRecoveryAvailable,
    RestorePreviousPamMapping,
    RevertGeneratedModule,
    RestoreStagedFiles,
    ManualLuksHeaderRestoreOnlyAfterIdentityCheck,
}

/// A secret-free, deterministic plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: u32,
    pub operation: PlanOperation,
    pub bindings: Vec<PlanBinding>,
    pub steps: Vec<PlanStep>,
    pub verification: Vec<VerificationRequirement>,
    pub recovery: Vec<RecoveryAction>,
}

impl Plan {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != PLAN_SCHEMA_VERSION {
            return Err(ValidationError::PolicyViolation(
                "unsupported plan schema version",
            ));
        }
        if self.bindings.is_empty() {
            return Err(ValidationError::PolicyViolation(
                "a plan must bind discovered system state",
            ));
        }
        let unique_bindings: BTreeSet<_> = self.bindings.iter().collect();
        if unique_bindings.len() != self.bindings.len() {
            return Err(ValidationError::PolicyViolation(
                "duplicate plan bindings are forbidden",
            ));
        }
        if self.steps.is_empty() {
            return Err(ValidationError::PolicyViolation(
                "a plan must contain at least one step",
            ));
        }
        for (index, step) in self.steps.iter().enumerate() {
            let expected = u16::try_from(index + 1)
                .map_err(|_| ValidationError::PolicyViolation("a plan contains too many steps"))?;
            if step.sequence != expected {
                return Err(ValidationError::PolicyViolation(
                    "plan step sequence must be contiguous and start at one",
                ));
            }
            if step.risk >= RiskLevel::High && !step.requires_confirmation {
                return Err(ValidationError::PolicyViolation(
                    "high-risk plan steps require explicit confirmation",
                ));
            }
        }
        if self.verification.is_empty() {
            return Err(ValidationError::PolicyViolation(
                "a plan must define verification",
            ));
        }
        if self.recovery.is_empty() {
            return Err(ValidationError::PolicyViolation(
                "a plan must define recovery guidance",
            ));
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<PlanFingerprint, ValidationError> {
        self.validate()?;
        let canonical = serde_json::to_vec(self)
            .map_err(|_| ValidationError::PolicyViolation("plan serialization failed"))?;
        Ok(PlanFingerprint(Sha256Digest::of_bytes(&canonical)))
    }
}

/// SHA-256 over the complete deterministic JSON representation of a validated plan.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanFingerprint(Sha256Digest);

impl fmt::Display for PlanFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Debug for PlanFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PlanFingerprint")
            .field(&self.to_string())
            .finish()
    }
}

impl Serialize for PlanFingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PlanFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Sha256Digest::deserialize(deserializer)
            .map(Self)
            .map_err(de::Error::custom)
    }
}

/// A plan persisted together with the exact fingerprint confirmed by the user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FingerprintedPlan {
    plan: Plan,
    fingerprint: PlanFingerprint,
}

impl FingerprintedPlan {
    pub fn new(plan: Plan) -> Result<Self, ValidationError> {
        let fingerprint = plan.fingerprint()?;
        Ok(Self { plan, fingerprint })
    }

    #[must_use]
    pub const fn plan(&self) -> &Plan {
        &self.plan
    }

    #[must_use]
    pub const fn fingerprint(&self) -> PlanFingerprint {
        self.fingerprint
    }

    pub fn verify(&self) -> Result<(), ValidationError> {
        if self.plan.fingerprint()? != self.fingerprint {
            return Err(ValidationError::PolicyViolation(
                "plan fingerprint does not match current plan",
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

    fn example_plan() -> Plan {
        Plan {
            schema_version: PLAN_SCHEMA_VERSION,
            operation: PlanOperation::EnrollLuks2Token,
            bindings: vec![
                PlanBinding {
                    subject: BindingSubject::Host,
                    expected: id("host", "host-a"),
                },
                PlanBinding {
                    subject: BindingSubject::LuksUuid,
                    expected: id("luks-uuid", "not-a-real-uuid"),
                },
            ],
            steps: vec![
                PlanStep {
                    sequence: 1,
                    action: PlanAction::CreateEncryptedLuksHeaderBackup,
                    risk: RiskLevel::High,
                    requires_confirmation: true,
                },
                PlanStep {
                    sequence: 2,
                    action: PlanAction::EnrollLuks2Token {
                        role: AuthenticatorRole::Primary,
                    },
                    risk: RiskLevel::High,
                    requires_confirmation: true,
                },
            ],
            verification: vec![VerificationRequirement {
                role: Some(AuthenticatorRole::Primary),
                domain: Some(ProtectionDomain::Luks2),
                kind: VerificationKind::LuksEnrollment,
            }],
            recovery: vec![RecoveryAction::KeepIndependentRecoveryAvailable],
        }
    }

    #[test]
    fn fingerprint_is_stable_across_json_round_trip() {
        let plan = example_plan();
        let before = plan.fingerprint().unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        let after = serde_json::from_str::<Plan>(&json)
            .unwrap()
            .fingerprint()
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn plan_drift_changes_fingerprint() {
        let plan = example_plan();
        let before = plan.fingerprint().unwrap();
        let mut drifted = plan;
        drifted.bindings[0].expected = id("host", "host-b");
        assert_ne!(before, drifted.fingerprint().unwrap());
    }

    #[test]
    fn envelope_detects_tampering() {
        let envelope = FingerprintedPlan::new(example_plan()).unwrap();
        let mut value = serde_json::to_value(envelope).unwrap();
        value["plan"]["steps"][1]["action"]["role"] =
            serde_json::Value::String("backup".to_owned());
        let tampered: FingerprintedPlan = serde_json::from_value(value).unwrap();
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn plan_serialization_cannot_leak_bound_raw_identifiers() {
        let secret = "private-host-id";
        let mut plan = example_plan();
        plan.bindings[0].expected = id("host", secret);
        let output = format!("{plan:?}{}", serde_json::to_string(&plan).unwrap());
        assert!(!output.contains(secret));
    }

    #[test]
    fn high_risk_steps_without_confirmation_are_rejected() {
        let mut plan = example_plan();
        plan.steps[0].requires_confirmation = false;
        assert!(plan.validate().is_err());
    }
}
