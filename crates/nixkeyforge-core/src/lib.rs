//! Pure domain types for NixKeyforge.
//!
//! This crate deliberately has no filesystem, process, network, or device access.
//! System adapters provide observations as [`SetupEvidence`]; this crate validates
//! them and derives conservative status and policy decisions.

#![forbid(unsafe_code)]

mod backup;
mod domain;
mod plan;
mod policy;
mod validation;

pub use backup::{
    ArchiveEntryKind, ArchiveMember, BACKUP_SCHEMA_VERSION, BackupClass, BackupComponent,
    BackupEntry, BackupFileMode, BackupFormat, BackupHost, BackupManifest, BackupMediaType,
    BackupPolicy, BackupSensitivity, EncryptionMethod, LuksUuid, LuksVolumeIdentity,
    LuksVolumeRole, MANIFEST_PATH, ManifestAuthenticator, ManifestVerification,
    validate_archive_members,
};
pub use domain::{
    AuthenticatorRole, EnrollmentEvidence, EnrollmentState, EvidenceQuality, ProtectionDomain,
    RecoveryState, SetupEvidence, SetupPolicy, SetupStatus, StatusAssessment, StatusReason,
    UnixAuthState, derive_status,
};
pub use plan::{
    BindingSubject, FingerprintedPlan, PLAN_SCHEMA_VERSION, Plan, PlanAction, PlanBinding,
    PlanFingerprint, PlanOperation, PlanStep, RecoveryAction, RiskLevel, VerificationKind,
    VerificationRequirement,
};
pub use policy::{LuksEnrollmentPolicy, PamAuthenticationMode, PamPolicy, UserVerificationPolicy};
pub use validation::{
    ArchivePath, RedactedIdentifier, Sha256Digest, ValidationError, VersionString,
};
