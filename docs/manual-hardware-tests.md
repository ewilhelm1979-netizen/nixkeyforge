# Manual hardware tests

## Purpose

Real PAM services, authenticators, firmware, initrd prompts, and LUKS2 boot
behavior cannot be proven by unit tests or a NixOS VM. This procedure supplies
the manual evidence required before a configuration can be reported as
`dual-token-ready`.

These tests are never run automatically. Repository test suites must mark real
hardware tests ignored and must not modify the host's PAM, SSH, LUKS, initrd, or
boot configuration. NixKeyforge does not reboot the machine.

## Evidence hygiene

Use role labels `Primary` and `Backup`, never raw credential handles, public
keys, serial numbers, AAGUIDs, LUKS UUIDs, recovery values, PINs, host names, or
user names in a shareable report. A local protected record may contain a
domain-separated redacted identifier and the exact UUID needed for recovery,
but public logs and issue reports must not.

For each test record:

- date and operator;
- NixOS generation and redacted configuration revision;
- systemd, cryptsetup, pam-u2f, and OpenSSH versions as applicable;
- service or protection domain;
- authenticator role;
- expected password, PIN/UV, and touch behavior;
- observed prompt count and result;
- redacted before/after enrollment association;
- rollback route retained; and
- `pass`, `fail`, `blocked`, or `not tested`.

Never mark an expected prompt as passed merely because login or boot eventually
succeeded through a fallback method.

## Entry gates

Do not start until all are true:

- the exact generated module and plan were reviewed;
- a build completed without activating it;
- the target NixOS generation and external-tool versions are recorded;
- Primary and Backup are physically labeled and known to be different devices;
- only the intended token will be attached at each step;
- each token's required capability, including LUKS2 `hmac-secret`, was detected
  without exposing identifiers;
- two distinct PAM credentials and two distinct LUKS2 token/keyslot
  associations are present in redacted inventory;
- an independent LUKS2 recovery key or strong passphrase was prepared and
  stored separately;
- an encrypted LUKS2 header backup was created and verified;
- current configuration and important data are backed up;
- a tested rescue medium and known-good NixOS generation are immediately
  available;
- a privileged session can remain open during PAM tests; and
- the operator has enough uninterrupted time to recover rather than improvising.

If token distinctness, device identity, recovery, or header-backup status is
uncertain, stop.

## Enrollment evidence review

Before functional testing, check the recorded ceremony:

1. all authenticators were removed;
2. Primary alone was inserted, identified by physical custody, and enrolled;
3. one new PAM credential and one new LUKS2 token/keyslot association appeared;
4. Primary was removed;
5. Backup alone was inserted and independently enrolled; and
6. another new PAM credential and LUKS2 association appeared.

If automatic enrollment occurred with both tokens attached, if enumeration order
was treated as identity, if no new record appeared, or if the same physical
token may have been used twice, invalidate enrollment evidence and return to a
reviewed plan. Do not delete keyslots while resolving ambiguity.

## PAM service tests

PAM services are tested independently. Populate only rows for services the plan
actually changes.

### Safety setup

1. Open and verify one privileged session before changing or testing PAM.
2. Keep that session unlocked and open until all intended services and recovery
   behavior pass.
3. Open a separate TTY/session as the test surface.
4. Confirm the reviewed policy states whether Unix password is required,
   alternative, or deliberately disabled. Version 0.1 does not apply a
   passwordless policy.
5. Remove all tokens.

### Primary

1. Attach Primary only.
2. Test one service from a new session.
3. Observe the exact password, PIN/UV, and touch sequence without recording
   entered values.
4. Confirm authentication reached the expected account through the expected
   factors, not a cached or fallback route.
5. Log out only the test session.
6. Repeat for each affected service, one at a time.
7. Remove Primary.

### Backup

Repeat the same steps with Backup as the only attached token. Success with
Primary cannot fill a Backup result.

### Password and failure behavior

Where the reviewed policy retains Unix password, verify it through a separate,
deliberate test that does not jeopardize the privileged session. For
password-plus-FIDO2, confirm both factors are actually required. Do not infer
control-flag behavior from prompt order alone.

Negative tests—no token, wrong token, cancelled touch, wrong PIN—can trigger
rate limits or lockout. Run only those explicitly present in the reviewed test
plan, stop at the defined attempt limit, and preserve the working session.

### PAM matrix

| Service | Policy | Primary only | Backup only | Password behavior | Result |
|---|---|---|---|---|---|
| TTY `login` | Record exact reviewed mode | Pending | Pending | Pending | Not tested |
| SDDM | Record exact reviewed mode | Pending | Pending | Pending | Not tested |
| KDE/Plasma screen locker | Record exact service name/mode | Pending | Pending | Pending | Not tested |
| `sudo` | Unchanged unless explicitly planned | N/A | N/A | N/A | Not tested |
| polkit | Unchanged unless explicitly planned | N/A | N/A | N/A | Not tested |
| `su` | Unchanged unless explicitly planned | N/A | N/A | N/A | Not tested |
| SSH-PAM | Unchanged unless explicitly planned | N/A | N/A | N/A | Not tested |

Do not globally enable FIDO2 for an untested service. A screen locker is not
verified by SDDM login.

## LUKS2 boot tests

These are three distinct boots. Do not combine them and do not leave both tokens
attached. Keep rescue media and independent recovery material accessible
throughout.

### Primary-only boot

1. Confirm the known-good generation is still selectable and no old generation
   has been removed.
2. Completely shut down.
3. Disconnect Backup and every other FIDO2 authenticator.
4. Attach Primary only.
5. Boot the intended test generation.
6. Confirm the prompt applies to the intended root LUKS2 volume.
7. Observe PIN/UV and user-presence/touch prompts. Multiple prompts are recorded,
   not hidden.
8. Confirm the volume unlocks through Primary and the expected system reaches a
   usable login.
9. Record redacted evidence.
10. Completely shut down and remove Primary.

If recovery or another credential was used, record failure for Primary.

### Backup-only boot

1. Verify Primary is disconnected.
2. Attach Backup only.
3. Repeat the complete boot and observation sequence.
4. Confirm unlock was through Backup, not cached state or recovery.
5. Record evidence.
6. Completely shut down and remove Backup.

### Independent recovery boot

1. Disconnect both authenticators and other FIDO2 devices.
2. Boot with rescue media available.
3. Select the recovery route deliberately.
4. Enter the systemd recovery key or strong LUKS passphrase through the trusted
   prompt.
5. Confirm the intended volume and generation boot successfully.
6. Do not record, photograph, echo, or paste the secret.
7. Completely shut down and return recovery material to separate secure
   storage.

A token fallback during this test is a failure. A second token is not the
independent recovery path.

## Optional OpenSSH security-key tests

Run only if SSH user access is in the reviewed plan. The reference OpenSSH
server must not be enabled merely for testing.

- Confirm Primary and Backup have separate `ed25519-sk` credentials and distinct
  authorized public keys.
- Keep an existing administrative SSH connection open.
- Open a second connection with Primary only and verify required touch and, when
  configured and supported, user verification.
- Close only the test connection, remove Primary, and repeat with Backup.
- Never set `no-touch-required`.
- Do not disable password or keyboard-interactive authentication until the
  intended public-key policy has succeeded in a second connection and a
  recovery route remains.

No FIDO2 authenticator is used for SSH host keys. Authenticator-internal private
keys are not backed up.

## Post-test inventory

After all functional tests, perform a redacted read-only inventory:

- two distinct PAM credential entries remain for the intended user;
- two distinct LUKS2 token/keyslot associations remain;
- no existing recovery key/passphrase access was removed;
- mapping file is regular, not linked, correctly owned, and `0600`;
- no unexpected PAM service changed;
- plan fingerprint and target observations still match; and
- encrypted backup and header backup still verify.

Return Backup and recovery material to different secure locations, separate
from the computer and from each other.

## Failure handling

On the first unexpected prompt, target, credential route, or result:

1. stop the current test;
2. keep the working privileged session or return to the known-good generation;
3. do not improvise a PAM edit, keyslot deletion, header restore, or another
   enrollment;
4. record only redacted evidence;
5. use [PAM lockout recovery](pam-lockout-recovery.md) or [LUKS2
   recovery](luks2-recovery.md); and
6. mark the affected state `failed`, `recovery-unverified`,
   `configuration-drift`, `lockout-risk`, or `unsupported`.

## Readiness decision

`dual-token-ready` is allowed only when:

- every intended PAM service has both Primary-only and Backup-only passes;
- Primary-only and Backup-only LUKS2 boots pass in separate boot cycles;
- independent recovery passes with neither token attached;
- distinct PAM and LUKS2 associations are confirmed redacted;
- no recovery access was removed;
- a privileged session remained open for PAM testing;
- backups verify; and
- no applicable result is stale after a configuration, generation, systemd,
  cryptsetup, pam-u2f, OpenSSH, authenticator firmware, or policy change.

Enrollment metadata, a successful capability query, or one successful token does
not satisfy readiness.
