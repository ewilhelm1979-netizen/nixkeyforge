#![forbid(unsafe_code)]

//! Explicitly ignored evidence gates for tests that cannot be automated safely.
//!
//! These tests never call PAM, SSH, cryptsetup, systemd-cryptenroll, or reboot.
//! Operators perform the linked runbook and set the non-secret confirmation
//! marker only for the isolated test invocation.

fn require_recorded_manual_evidence(marker: &str) {
    assert_eq!(
        std::env::var("NIXKEYFORGE_MANUAL_EVIDENCE").as_deref(),
        Ok(marker),
        "complete docs/manual-hardware-tests.md and supply the matching non-secret evidence marker"
    );
}

#[test]
#[ignore = "manual: requires Primary-only PAM checks with a retained privileged session"]
fn primary_authenticator_pam_evidence_is_recorded() {
    require_recorded_manual_evidence("primary-pam-recorded");
}

#[test]
#[ignore = "manual: requires Backup-only PAM checks with a retained privileged session"]
fn backup_authenticator_pam_evidence_is_recorded() {
    require_recorded_manual_evidence("backup-pam-recorded");
}

#[test]
#[ignore = "manual: requires separate Primary/Backup boots and independent recovery proof"]
fn separate_luks2_boot_and_recovery_evidence_is_recorded() {
    require_recorded_manual_evidence("luks2-and-recovery-recorded");
}
