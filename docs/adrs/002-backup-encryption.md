# ADR 002: Authenticated age encryption for sensitive backups

- Status: Accepted
- Date: 2026-07-27

## Context

Portable configuration facts and sensitive machine recovery material have
different confidentiality needs. LUKS2 headers, selected recovery material,
PAM mappings, and private SSH keys can enable offline attack or host
impersonation. Checksums alone do not authenticate backups.

## Decision

Portable backups exclude secrets by default. Sensitive recovery backups
require explicit component selection and authenticated encryption to one or
more age recipients. Passphrase mode, if added, reads through secure
interactive input and never through arguments or environment.

The encrypted payload has a versioned manifest and diagnostic checksums.
Restore first authenticates and validates the whole structure, then stages
allowlisted regular files without uncontrolled archive extraction. A LUKS2
header is never restored automatically.

## Consequences

Recipients must be managed and tested separately from the protected host.
Losing every recipient key makes the backup unavailable. Additional checksums
help diagnose corruption but do not replace authenticated encryption.
