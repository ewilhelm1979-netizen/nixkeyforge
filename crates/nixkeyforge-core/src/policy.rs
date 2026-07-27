use serde::{Deserialize, Serialize};

use crate::{SetupStatus, StatusAssessment, ValidationError};

/// PAM mode analyzed by NixKeyforge. Version 0.1 only applies the first mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PamAuthenticationMode {
    PasswordAndFido2,
    Passwordless,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UserVerificationPolicy {
    Required,
    Preferred,
    CapabilityDependent,
}

/// Explicit PAM safety properties; permissive fallback flags are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PamPolicy {
    pub mode: PamAuthenticationMode,
    pub user_presence_required: bool,
    pub user_verification: UserVerificationPolicy,
    pub allow_missing_user: bool,
    pub always_succeed: bool,
}

impl Default for PamPolicy {
    fn default() -> Self {
        Self {
            mode: PamAuthenticationMode::PasswordAndFido2,
            user_presence_required: true,
            user_verification: UserVerificationPolicy::CapabilityDependent,
            allow_missing_user: false,
            always_succeed: false,
        }
    }
}

impl PamPolicy {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if !self.user_presence_required {
            return Err(ValidationError::PolicyViolation(
                "PAM user presence must remain enabled",
            ));
        }
        if self.allow_missing_user {
            return Err(ValidationError::PolicyViolation(
                "PAM `nouserok` behavior is forbidden",
            ));
        }
        if self.always_succeed {
            return Err(ValidationError::PolicyViolation(
                "PAM `alwaysok` behavior is forbidden",
            ));
        }
        Ok(())
    }

    /// Passwordless PAM can be analyzed, but version 0.1 must not apply it.
    pub fn validate_for_apply(&self, assessment: &StatusAssessment) -> Result<(), ValidationError> {
        self.validate()?;
        if self.mode == PamAuthenticationMode::Passwordless {
            if assessment.status != SetupStatus::DualTokenReady {
                return Err(ValidationError::PolicyViolation(
                    "passwordless PAM requires a dual-token-ready assessment",
                ));
            }
            return Err(ValidationError::PolicyViolation(
                "passwordless PAM apply is unavailable in version 0.1",
            ));
        }
        Ok(())
    }
}

/// Secure enrollment defaults for LUKS2 FIDO2 tokens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LuksEnrollmentPolicy {
    pub client_pin_required: bool,
    pub user_presence_required: bool,
    pub user_verification: UserVerificationPolicy,
    pub preserve_recovery_access: bool,
    pub remove_keyslots: bool,
    pub encrypted_header_backup_required: bool,
}

impl Default for LuksEnrollmentPolicy {
    fn default() -> Self {
        Self {
            client_pin_required: true,
            user_presence_required: true,
            user_verification: UserVerificationPolicy::CapabilityDependent,
            preserve_recovery_access: true,
            remove_keyslots: false,
            encrypted_header_backup_required: true,
        }
    }
}

impl LuksEnrollmentPolicy {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if !self.client_pin_required {
            return Err(ValidationError::PolicyViolation(
                "LUKS2 authenticator client PIN must remain enabled",
            ));
        }
        if !self.user_presence_required {
            return Err(ValidationError::PolicyViolation(
                "LUKS2 user presence must remain enabled",
            ));
        }
        if !self.preserve_recovery_access {
            return Err(ValidationError::PolicyViolation(
                "an independent recovery route must be preserved",
            ));
        }
        if self.remove_keyslots {
            return Err(ValidationError::PolicyViolation(
                "keyslot removal is forbidden in version 0.1",
            ));
        }
        if !self.encrypted_header_backup_required {
            return Err(ValidationError::PolicyViolation(
                "an encrypted LUKS2 header backup plan is required",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{SetupStatus, StatusAssessment};
    use std::collections::BTreeSet;

    #[test]
    fn secure_defaults_validate() {
        PamPolicy::default().validate().unwrap();
        LuksEnrollmentPolicy::default().validate().unwrap();
    }

    #[test]
    fn pam_permissive_flags_are_rejected() {
        let policy = PamPolicy {
            allow_missing_user: true,
            ..PamPolicy::default()
        };
        assert!(policy.validate().is_err());
        let policy = PamPolicy {
            always_succeed: true,
            ..PamPolicy::default()
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn passwordless_apply_is_forbidden_even_when_ready() {
        let policy = PamPolicy {
            mode: PamAuthenticationMode::Passwordless,
            ..PamPolicy::default()
        };
        let assessment = StatusAssessment {
            status: SetupStatus::DualTokenReady,
            reasons: BTreeSet::new(),
            verified_pam_credentials: 2,
        };
        assert!(policy.validate_for_apply(&assessment).is_err());
    }

    #[test]
    fn unsafe_luks_policy_is_rejected() {
        let policy = LuksEnrollmentPolicy {
            remove_keyslots: true,
            ..LuksEnrollmentPolicy::default()
        };
        assert!(policy.validate().is_err());
    }
}
