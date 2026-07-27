#![allow(clippy::unwrap_used)]

use nixkeyforge_core::{
    ArchivePath, AuthenticatorRole, BackupClass, BackupComponent, BackupEntry, BackupFileMode,
    BackupFormat, BackupHost, BackupManifest, BackupMediaType, BackupPolicy, BackupSensitivity,
    BindingSubject, EncryptionMethod, EvidenceQuality, Plan, PlanAction, PlanBinding,
    PlanOperation, PlanStep, RecoveryAction, RedactedIdentifier, RiskLevel, SetupEvidence,
    SetupPolicy, SetupStatus, Sha256Digest, UnixAuthState, VerificationKind,
    VerificationRequirement, VersionString, derive_status,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn authenticator_role_other_is_an_involution(primary in any::<bool>()) {
        let role = if primary {
            AuthenticatorRole::Primary
        } else {
            AuthenticatorRole::Backup
        };
        prop_assert_eq!(role.other().other(), role);
    }

    #[test]
    fn unverifiable_passwordless_pam_is_always_lockout_risk(
        configuration_drift in any::<bool>(),
        privileged_session_retained in any::<bool>(),
    ) {
        let evidence = SetupEvidence {
            supported: true,
            configuration_drift,
            unix_auth: UnixAuthState::Disabled,
            credential_inventory: EvidenceQuality::Unverifiable,
            privileged_session_retained,
            ..SetupEvidence::default()
        };
        prop_assert_eq!(
            derive_status(&evidence, &SetupPolicy::default()).status,
            SetupStatus::LockoutRisk
        );
    }

    #[test]
    fn archive_paths_with_parent_components_are_always_rejected(
        prefix in "[a-zA-Z0-9_-]{0,24}",
        suffix in "[a-zA-Z0-9_.-]{0,24}",
    ) {
        let candidate = format!("{prefix}/../{suffix}");
        prop_assert!(ArchivePath::new(candidate).is_err());
    }

    #[test]
    fn archive_paths_with_an_absolute_prefix_are_always_rejected(
        suffix in "[a-zA-Z0-9_./-]{0,64}",
    ) {
        let candidate = format!("/{suffix}");
        prop_assert!(ArchivePath::new(candidate).is_err());
    }

    #[test]
    fn redaction_never_serializes_the_source(source in "[a-zA-Z0-9_-]{8,128}") {
        let redacted = RedactedIdentifier::new("property-test", source.as_bytes()).unwrap();
        let debug = format!("{redacted:?}");
        let json = serde_json::to_string(&redacted).unwrap();
        prop_assert!(!debug.contains(&source));
        prop_assert!(!json.contains(&source));
    }

    #[test]
    fn portable_manifest_round_trips_without_semantic_change(
        file_name in "[a-zA-Z0-9_-]{1,32}\\.json",
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let manifest = BackupManifest {
            format: BackupFormat::NixKeyforgeBackup,
            schema_version: 1,
            tool_version: VersionString::new("0.1.0").unwrap(),
            created_at: "2026-07-27T08:00:00Z".to_owned(),
            profile: BackupClass::PortableConfiguration,
            host: BackupHost {
                redacted_id: RedactedIdentifier::new("host", b"property-host").unwrap(),
            },
            luks_volumes: Vec::new(),
            authenticators: Vec::new(),
            entries: vec![BackupEntry {
                component: BackupComponent::Configuration,
                path: ArchivePath::new(format!("components/configuration/{file_name}")).unwrap(),
                media_type: BackupMediaType::Json,
                length: u64::try_from(bytes.len()).unwrap(),
                sha256: Sha256Digest::of_bytes(&bytes),
                mode: BackupFileMode::OwnerReadWrite,
                sensitivity: BackupSensitivity::Configuration,
            }],
        };
        let encryption = EncryptionMethod::AgeRecipients {
            recipient_ids: vec![
                RedactedIdentifier::new("age-recipient", b"property-recipient").unwrap()
            ],
        };
        manifest
            .validate(&BackupPolicy::portable(), &encryption)
            .unwrap();
        let encoded = serde_json::to_vec(&manifest).unwrap();
        let decoded: BackupManifest = serde_json::from_slice(&encoded).unwrap();
        prop_assert_eq!(manifest, decoded);
    }

    #[test]
    fn every_binding_drift_changes_the_plan_fingerprint(
        original in "[a-zA-Z0-9_-]{1,64}",
        changed in "[a-zA-Z0-9_-]{1,64}",
    ) {
        prop_assume!(original != changed);
        let make_plan = |host: &str| Plan {
            schema_version: 1,
            operation: PlanOperation::GenerateConfiguration,
            bindings: vec![PlanBinding {
                subject: BindingSubject::Host,
                expected: RedactedIdentifier::new("host", host.as_bytes()).unwrap(),
            }],
            steps: vec![PlanStep {
                sequence: 1,
                action: PlanAction::GenerateNixModule,
                risk: RiskLevel::Low,
                requires_confirmation: false,
            }],
            verification: vec![VerificationRequirement {
                role: None,
                domain: None,
                kind: VerificationKind::FileOwnershipAndMode,
            }],
            recovery: vec![RecoveryAction::RevertGeneratedModule],
        };
        prop_assert_ne!(
            make_plan(&original).fingerprint().unwrap(),
            make_plan(&changed).fingerprint().unwrap()
        );
    }
}
