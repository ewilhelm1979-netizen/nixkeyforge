# ADR 004: Use independent authenticators for one-of-two redundancy

- Status: Accepted
- Date: 2026-07-27

## Context

A single hardware authenticator is an availability dependency. Calling a copied
configuration a "backup key" is misleading: authenticator-internal credentials
cannot be cloned or exported, and success in metadata discovery does not prove a
spare token works for PAM or early boot.

A second token also does not protect against simultaneous loss, theft, a shared
configuration defect, an unsupported systemd version, or a damaged LUKS2
header.

## Decision

The recommended model contains:

- a **Primary** authenticator for daily PAM login and LUKS2 unlock;
- a physically distinct **Backup** authenticator, stored unused and separately;
- an independent LUKS2 recovery key or strong passphrase, stored separately
  from the computer and both authenticators; and
- a tested rescue medium and retained known-good NixOS generation.

Primary and Backup each receive their own PAM-U2F/FIDO2 credential and their own
LUKS2 FIDO2 enrollment. Either authenticator is sufficient for the configured
operation. This is one-of-two redundancy, not a 2-of-2 ceremony.

Enrollment is sequential. All tokens are removed, the intended role is inserted
and identified, one PAM credential and one LUKS2 enrollment are created and
inventoried, then that token is removed before the other role is processed.
Automatic `fido2-device=auto` enrollment must never run with both tokens
attached.

If NixKeyforge cannot establish that a new, distinct credential and enrollment
were created for a physically different authenticator, it stops and reports
ambiguity. Redacted identifiers can support comparison, but are not proof that
two devices are independent.

`dual-token-ready` requires recorded manual evidence that:

- Primary and Backup each work for every intended PAM service;
- Primary and Backup each unlock the LUKS2 volume in separate boot tests with
  only the token under test attached;
- the independent recovery method works without either token;
- PAM credentials and LUKS2 token/keyslot associations are distinct; and
- no pre-existing recovery access was removed.

Until then, status remains `single-token`, `dual-token-incomplete`,
`recovery-unverified`, `lockout-risk`, or another non-ready state. Passwordless
PAM is not automatically enabled in version 0.1.

## Consequences

- Loss or failure of one authenticator need not remove local login and boot
  access.
- Enrollment and testing take longer and require physical custody discipline.
- The Backup must be periodically tested and then returned to separate secure
  storage.
- The independent recovery method remains necessary.
- Multiple attached FIDO2 devices can produce ambiguous early-boot selection and
  repeated PIN, user-verification, or touch prompts; separate boot tests are
  mandatory.
- Theft of a token remains a security event. User presence alone is not user
  verification, and local policy must account for token PIN/UV capabilities.

## Rejected alternatives

- **Clone the Primary:** FIDO2 private credentials are deliberately
  non-exportable and cloning is neither available nor a valid recovery model.
- **Require both tokens (2-of-2):** increases lockout risk and does not meet the
  availability goal.
- **Use only a recovery key:** recovery material is an emergency path, not a
  routinely tested replacement authenticator.
- **Infer readiness from metadata:** enrollment records do not prove that PAM or
  initrd prompts work on the real hardware.
