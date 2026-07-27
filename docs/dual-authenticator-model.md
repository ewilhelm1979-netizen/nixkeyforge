# Dual-authenticator model

## Meaning of “two keys”

NixKeyforge uses two separate physical FIDO2 authenticators. Each device
creates its own PAM credential, LUKS2 `hmac-secret` enrollment, and optional
OpenSSH `ed25519-sk` credential. The internal private keys are distinct and
non-exportable.

Either authenticator is sufficient for a configured login or unlock. Both are
never required simultaneously. This availability model is not cloning,
synchronization, secret sharing, or two-of-two authentication.

## Roles

| Role | Normal use | Required handling |
| --- | --- | --- |
| Primary | Daily PAM login and LUKS2 unlock | Carried by the user |
| Backup | Replacement PAM login and LUKS2 unlock | Tested, powered off, and stored separately |
| Recovery key/passphrase | Independent LUKS2 emergency path | Stored separately from host and both devices |
| Rescue media | Repair boot/PAM failures | Tested before enrollment |

The backup authenticator does not replace recovery material. Recovery material
does not replace the backup authenticator.

## Enrollment ceremony

1. Remove every authenticator.
2. Attach only the intended primary.
3. Detect capabilities, including user presence, PIN/UV, and LUKS2
   `hmac-secret`.
4. Assign and record a redacted primary identity.
5. Create the primary PAM credential and atomically add it to the mapping.
6. Inventory the intended LUKS2 volume, preserve recovery access, and create
   the encrypted header-backup plan.
7. Enroll primary with `systemd-cryptenroll`.
8. Re-inventory token/keyslot metadata and confirm one additive enrollment.
9. Remove primary.
10. Attach only the intended backup.
11. Prove it is not the already assigned primary.
12. Repeat PAM and LUKS2 enrollment, producing distinct entries.
13. Remove backup and store it separately.

Automatic `auto` enrollment must never run while both devices are connected.
Uncertain device identity or a missing new enrollment aborts the ceremony.

## Verification matrix

| Proof | Primary | Backup |
| --- | --- | --- |
| PAM credential is a distinct mapping entry | Required | Required |
| TTY login in a second session | Required | Required |
| SDDM login when selected | Required | Required |
| Screen locker when selected | Required | Required |
| LUKS2 token/keyslot association is distinct | Required | Required |
| Boot with only this token attached | Required | Required |

The independent recovery key or passphrase also needs a controlled proof.
During PAM tests, keep a privileged session open. During boot tests, keep
rescue media, recovery material, and a previous NixOS generation available.

## State derivation

- No enrollment: `unconfigured`.
- One working token: `single-token`.
- Two recorded tokens but missing any role/domain proof:
  `dual-token-incomplete`.
- Both roles verified everywhere but recovery untested: `recovery-unverified`.
- All role/domain and recovery proofs current: `dual-token-ready`.
- Passwordless PAM without proof of both authenticators and recovery:
  `lockout-risk`.
- Facts changed after planning: `configuration-drift`.
- Required platform/capability unavailable: `unsupported`.

`dual-token-ready` is evidence-based. A count of two credential strings or two
LUKS token records does not prove they represent two devices or that either
works.

## Passwordless boundary

Version 0.1 does not apply passwordless PAM. It may diagnose an existing
passwordless stack and produce a controlled migration plan. Even a future
passwordless workflow must first prove both devices for every selected PAM
service, independent recovery, a second successful session, and an open
privileged fallback session.
