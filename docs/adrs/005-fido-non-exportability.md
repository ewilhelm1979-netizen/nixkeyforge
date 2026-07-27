# ADR 005: Never represent FIDO credentials as exportable or clonable

- Status: Accepted
- Date: 2026-07-27

## Context

PAM-U2F, LUKS2 FIDO2 enrollment, OpenSSH security-key credentials, and WebAuthn
passkeys use related authenticator technology but are different credential
domains. Their private credential material is generated or held by the
authenticator and is not available to NixKeyforge for export.

PAM mappings, LUKS2 token metadata, and OpenSSH public-key or key-handle files can
contain public or opaque credential data. Backing up those files does not back
up the authenticator's private key. Some authenticators may implement
vendor-specific backup features, but NixKeyforge cannot assume, control, or
describe those as cloning.

## Decision

NixKeyforge never offers, documents, or reports a FIDO private-key export,
credential clone, or authenticator restore.

Backups may contain only the explicitly allowed artifacts for a backup profile:

- redacted authenticator roles and verification state;
- public SSH keys;
- PAM credential metadata, redacted by default;
- a deliberately selected PAM mapping only in the sensitive machine-recovery
  profile; and
- LUKS2 header/token metadata or a LUKS2 header only when explicitly selected
  for the sensitive profile.

Credential handles, public keys, salts, relying-party identifiers, and LUKS2
token metadata are not private authenticator keys, but they are still treated as
sensitive because they reveal system and authentication relationships.

Restoring metadata never restores possession of an authenticator credential. A
lost or failed token requires a new physical authenticator and fresh enrollment
in every protection domain: each PAM service policy, LUKS2, and each desired
OpenSSH `ed25519-sk` credential. A restore report must say this explicitly.

Terminology in code and technical documentation distinguishes:

- FIDO2 authenticator or hardware security key;
- PAM-U2F/FIDO2 credential;
- LUKS2 FIDO2 enrollment using the authenticator's `hmac-secret` capability;
- OpenSSH security-key credential; and
- WebAuthn passkey.

User-facing prose may use "passkey" only when the surrounding context makes the
actual credential domain clear.

## Consequences

- Backup and restore cannot reproduce a lost token.
- Primary and Backup require separate enrollment and separate testing.
- Redundant SSH access requires separate `ed25519-sk` credentials and public-key
  authorization for both tokens.
- Sensitive metadata remains encrypted and redacted even though it is not the
  authenticator's private key.
- Recovery documentation must direct operators to re-enrollment rather than
  imply that importing an archive reconstructs hardware state.

## Rejected alternatives

- **Call the Backup a clone:** technically false and encourages unsafe custody
  assumptions.
- **Treat public or opaque metadata as harmless:** it can disclose user,
  authenticator, and disk relationships.
- **Restore a mapping and claim success:** file restoration does not establish
  possession, touch/PIN behavior, PAM integration, or boot usability.
