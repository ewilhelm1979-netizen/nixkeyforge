# Security Policy

NixKeyforge handles authentication, encrypted-volume enrollment, and recovery
material. Treat every defect that could expose credentials, grant privilege, or
deny local login or boot as security-sensitive.

## Supported versions

NixKeyforge is pre-release software. Until a stable release policy is published,
security fixes are made on the default branch and in the newest published
release only. Older commits, development branches, generated plans, and locally
modified builds are not supported.

No release is a substitute for a tested rescue medium, an independent LUKS2
recovery key or strong passphrase, and a retained known-good NixOS generation.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use the repository's **Security** tab to submit a private GitHub security
advisory. Include:

- the affected version or commit;
- a minimal reproduction with invented identifiers and credentials;
- the expected and observed security boundary;
- the likely confidentiality, integrity, and availability impact; and
- any suggested mitigation.

Do not include real recovery keys, passphrases, PAM-U2F mappings, SSH private
keys, LUKS headers, hardware identifiers, host names, or user names. If the
private-advisory feature is unavailable, contact a maintainer through their
public GitHub profile and ask for a private reporting channel without disclosing
the vulnerability details.

Maintainers will acknowledge reports and coordinate validation, remediation, and
disclosure on a best-effort basis. We do not promise a fixed response or repair
time because severity and safe remediation vary. Please allow a reasonable
embargo for a fix and affected-user guidance.

## High-priority report classes

Reports are especially valuable when they involve:

- command or argument injection into privileged system tools;
- path traversal, symlink, hardlink, race, or unsafe archive extraction;
- applying a stale plan or targeting the wrong LUKS2 device;
- secret disclosure through human, JSON, diagnostic, or error output;
- bypass of plan confirmation, identity checks, or privilege boundaries;
- unsafe PAM changes that can cause account lockout;
- unsafe LUKS2, initrd, or header operations that can prevent boot or destroy
  recovery access;
- accepting tampered backups, manifests, release artifacts, or dependencies; or
- incorrectly reporting `dual-token-ready` or verified recovery.

## Security invariants

Contributions must preserve these rules:

- Two authenticators provide one-of-two redundancy. They are independent
  physical devices with independent credentials, not a 2-of-2 scheme.
- A backup authenticator does not replace an independent LUKS2 recovery key or
  strong passphrase.
- Authenticator-internal private keys are non-exportable. NixKeyforge cannot
  clone them or restore them from a backup.
- Passwordless PAM is not automatically enabled in version 0.1.
- NixKeyforge does not remove LUKS keyslots or automatically restore a LUKS2
  header in version 0.1.
- NixKeyforge does not invoke `sudo`, install a setuid binary, run a permanently
  privileged daemon, reboot, or silently edit live PAM, SSH, NixOS, initrd, or
  block-device configuration.
- Discovery, planning, apply, and verification are separate phases. Apply
  requires a reviewed plan and fresh target validation.
- Secrets must not enter Git, the Nix store, process arguments, environment
  variables, logs, telemetry, plans, status files, or diagnostic output.
- External tools are invoked as fixed executables with separated arguments,
  never through a shell command string.
- Hardware-dependent PAM and LUKS2 verification remains manual. Primary and
  backup LUKS2 enrollments require separate boots with only the token under test
  attached.

See [the threat model](docs/threat-model.md), [the recovery
runbook](docs/recovery-runbook.md), and [the manual hardware test
procedure](docs/manual-hardware-tests.md) for the security assumptions and
operational limits.

## Safe research

Use disposable fixtures, temporary directories, mocked command executors, and
NixOS virtual machines. Never test a report by changing a real user's PAM stack,
SSH access, initrd, LUKS2 header, keyslots, or boot configuration without that
system owner's explicit authorization and a recovery plan.

Never publish live credentials or a decryptable LUKS2 header. A header can
support offline password guessing and is sensitive even without the data
device.

## Disclosure and credit

We prefer coordinated disclosure. Once a fix and migration guidance are ready,
the project may publish an advisory describing affected versions, impact, and
remediation without exposing user secrets. Reporters may request credit or
anonymity.
