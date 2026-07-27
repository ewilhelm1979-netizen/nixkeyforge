# PAM lockout recovery

## Scope

Use this runbook when TTY `login`, SDDM, a screen locker, `sudo`, polkit, `su`,
or SSH-PAM no longer authenticates as planned. These are separate PAM services;
success or failure in one does not establish the state of another.

NixKeyforge 0.1 does not automatically edit PAM, toggle `unixAuth`, replace
`/etc/u2f_mappings`, activate a NixOS generation, or reboot. The operator must
review and perform any recovery action using NixOS procedures and known-good
media.

## Critical warnings

- Keep at least one existing privileged session open throughout diagnosis and
  testing. Do not lock its screen.
- Do not repeatedly test the only remaining login path.
- Do not add `nouserok`, `alwaysok`, permissive control flags, or debug options
  to regain convenience.
- Do not print or copy the full PAM-U2F mapping. Credential handles and public
  keys are sensitive metadata.
- Do not assume the Backup works because it is present in a mapping.
- Do not copy a mapping into the Nix store or put a recovery password in a Nix
  expression.
- Do not change `login`, SDDM, and screen-locker policies together.

## Before planned PAM testing

Do not begin unless:

- Primary and Backup have separate mapping entries;
- the intended service policy and Unix-password behavior are explicit;
- the exact NixOS options and PAM control behavior were checked against the
  pinned Nixpkgs revision;
- a privileged session is already open and known to work;
- another TTY or session is available for testing;
- a known-good generation and rescue medium are available;
- disk recovery works independently of both tokens; and
- raw mapping content and secrets are excluded from the test record.

Passwordless PAM remains analysis-only in version 0.1. A configuration with
`unixAuth = false` and fewer than two independently verified credentials is
`lockout-risk`, not ready.

## Diagnose without mutation

1. Identify exactly one failing PAM service and the authentication mode expected
   for it: password plus FIDO2, either method, or a legacy configuration.
2. Record the booted generation, configured revision, service name, PAM module
   versions, and redacted error. Do not collect a raw debug dump.
3. Determine whether Unix-password authentication is configured for that
   service. Do not infer it from another service.
4. Inspect mapping metadata without displaying records:
   - target is a regular file;
   - neither target nor parent path is a symlink;
   - hardlink count is expected;
   - owner is `root:root` and mode is `0600` unless a reviewed host policy says
     otherwise;
   - the affected user has the expected number of syntactically valid, distinct
     credentials; and
   - unrelated user records are present and unchanged.
5. Attach only the authenticator under test. Confirm its physical role through
   custody records; enumeration order is not identity.
6. Check for relevant NixOS, pam-u2f, display-manager, or screen-locker version
   drift.

If the mapping or PAM stack changed unexpectedly, treat it as a potential
security incident. Preserve evidence and use a trusted environment rather than
editing first.

## Recovery branches

### A. A privileged session remains open

This is the safest branch.

1. Preserve the session and save redacted observations.
2. Compare the declarative configuration and generated PAM result with the last
   known-good NixOS generation.
3. Select the smallest repair: one service definition or one intended mapping
   record. Do not modify unrelated users or services.
4. Build and inspect the corrected NixOS generation before any test or
   activation. Retain the currently working generation.
5. If the mapping itself must be replaced, first preserve the current file in
   protected storage. A human-reviewed replacement must use a link-safe atomic
   operation and revalidate content hash, type, owner, `0600` mode, and
   unrelated-user preservation.
6. Test the affected service from a second session. Only after it succeeds with
   Primary, Backup, and the reviewed password policy may the old test session be
   closed.

NixKeyforge may prepare a plan and redacted diff; it does not perform these live
steps during development or claim that they succeeded.

### B. No privileged session, but a known-good generation is bootable

At the bootloader, a human operator may select the previously tested generation.
Do not delete it after the first successful login.

Once logged in, follow branch A to inspect the failed generation. Correct the
declarative source; do not treat a temporary generated `/etc/pam.d` edit as a
durable NixOS repair. Build and inspect before a controlled test boot.

### C. No local login works

1. Stop login attempts.
2. Use the tested rescue medium and the independent LUKS2 recovery key or strong
   passphrase. A token-only recovery path is insufficient for this branch.
3. Verify the exact LUKS UUID and expected system role before unlocking or
   mounting anything.
4. Prefer selecting or restoring access to a known-good NixOS generation over
   constructing a new PAM stack from memory.
5. Inspect the declarative configuration and mapping metadata offline. Never
   expose raw mapping content in support logs.
6. Prepare a single-layer repair, unmount cleanly, then test through a known-good
   boot path.

If disk recovery fails, leave PAM diagnosis and follow
[luks2-recovery.md](luks2-recovery.md). Do not attempt a PAM repair by modifying
an unidentified mounted filesystem.

### D. Mapping is missing or corrupt

A package containing a mapping is usable only if it is an authenticated,
schema-compatible `sensitive-machine-recovery` backup that matches this host
and passed strict archive validation. Restore it only to private staging first.

Before a deliberate replacement, compare redacted credential counts and user
coverage, preserve the current file, and verify that the staged mapping will not
remove unrelated users. A restored mapping does not restore an authenticator
private key and does not prove either token works. If authenticators were lost,
restore availability through Unix password or another independently established
administrator route and perform fresh enrollments instead.

## Verification matrix

For every affected service, record:

| Test | Primary only | Backup only | Expected password behavior | Result |
|---|---|---|---|---|
| TTY `login` | Manual | Manual | Explicit policy | Pending |
| SDDM | Manual | Manual | Explicit policy | Pending |
| Screen locker | Manual | Manual | Explicit policy | Pending |
| `sudo` | Only if changed | Only if changed | Explicit policy | Pending |
| polkit | Only if changed | Only if changed | Explicit policy | Pending |
| `su` | Only if changed | Only if changed | Explicit policy | Pending |
| SSH-PAM | Only if changed | Only if changed | Explicit policy | Pending |

Do not fill a cell from another service's result. Keep the privileged session
open, test one role at a time, and remove the token after each test. Use
[manual-hardware-tests.md](manual-hardware-tests.md) for evidence rules.

## Exit criteria

PAM recovery is complete only when:

- the known-good declarative source is identified;
- generated changes match the reviewed service-specific plan;
- Primary and Backup each pass every affected service's manual test;
- password fallback behaves exactly as intended;
- mapping type, ownership, mode, count, and unrelated-user preservation pass;
- no credential content appears in logs or stored plans;
- the independent disk recovery route remains valid; and
- the known-good generation is retained until later boot verification.

Any untested or ambiguous cell keeps the state degraded. It must not be reported
as `dual-token-ready`.

## Primary references

Interpret options and mapping grammar using the installed version and the
upstream [`pam_u2f(8)`
manual](https://developers.yubico.com/pam-u2f/Manuals/pam_u2f.8.html) and
[`pamu2fcfg(1)`
manual](https://developers.yubico.com/pam-u2f/Manuals/pamu2fcfg.1.html).
NixOS PAM option semantics must additionally be checked against the repository's
pinned Nixpkgs revision; an upstream example is not a NixOS activation plan.
