# LUKS2 recovery

## Scope and hard stop

This runbook covers failure of FIDO2 unlock, initrd integration, LUKS2 token
metadata, or the LUKS2 header. NixKeyforge 0.1 does not unlock real volumes,
remove keyslots, restore headers, reboot, or run live enrollment during project
development.

A mistaken header operation can make all data permanently inaccessible. If the
exact target or recovery route is uncertain, stop. Never use formatting,
reencryption, repair, keyslot deletion, or header restore as a diagnostic step.

## Recovery model

The intended volume has three independent access routes:

1. Primary authenticator enrollment;
2. Backup authenticator enrollment; and
3. one tested systemd recovery key or strong LUKS passphrase.

Primary and Backup are separate physical devices and separate LUKS2
token/keyslot associations. Either token suffices; this is not 2-of-2. The
recovery key/passphrase is a third route, not a substitute for Backup.

FIDO2 private credential material remains in each authenticator and cannot be
cloned or restored from a backup. A LUKS2 header backup contains metadata and
keyslots, not an export of those authenticator private keys.

## Preconditions for any write

Do not plan a write until a human has established:

- the device is LUKS2, never LUKS1 requiring an automatic conversion;
- exact on-device LUKS UUID;
- stable by-UUID path plus current major/minor;
- expected system role and relationship to the running/rescue system;
- current open, mount, and dependent-device state;
- redacted keyslot and token inventory;
- an independently working recovery key/passphrase;
- a current encrypted header-backup plan and a separate data backup;
- compatible pinned NixOS, systemd, cryptsetup, and initrd behavior;
- the intended single authenticator and its `hmac-secret`, PIN, user-presence,
  and user-verification capabilities; and
- a reviewed rollback/recovery path.

Immediately before an authorized write, repeat target, UUID, major/minor, role,
keyslot, token, host, revision, and plan-fingerprint checks. Any drift is a
blocker.

Secrets are entered through the external tool's protected terminal or standard
input interface only. They never enter arguments, environment variables,
plans, shell history, logs, or JSON.

## Diagnose by symptom

### FIDO2 prompt is absent

Likely causes include a generation or initrd regression, missing crypttab
configuration, a systemd compatibility change, or a volume that is not using
the expected token metadata.

Use the independent recovery method. If it succeeds, keep the header and all
keyslots unchanged. Boot a retained known-good generation or inspect the built
initrd and pinned options from a trusted session. Build a corrected generation
before selecting it for a manual test boot.

### Prompt appears but Primary fails

Shut down before changing attached hardware. Retry through a separately known
route rather than repeatedly entering a PIN. Test Backup as the only attached
token only if it was previously verified. If Backup succeeds, treat Primary as
lost, damaged, or drifted and protect Backup from becoming the new daily
single point of failure.

Stabilize access with independent recovery before enrolling a replacement.
Never delete the old slot as part of diagnosis.

### Both authenticators fail, recovery succeeds

This points to a common configuration/initrd/version issue, two stale or damaged
enrollments, or use of the wrong volume. Preserve a redacted inventory and
current encrypted header backup. Compare the known-good generation and exact
systemd/cryptsetup behavior. Do not enroll more tokens until the target and root
cause are unambiguous.

After stable access, replacement enrollment is sequential: remove all tokens,
attach and enroll one intended physical role, inventory the new redacted
token/keyslot association, remove it, then repeat with the other device. Abort
if no new association appears or the devices might be the same. No keyslots are
removed in version 0.1.

### Neither authenticators nor recovery unlock

Stop. Confirm keyboard layout and exact device identity without further
mutation. Do not assume that a similarly named by-UUID path or cloned UUID is
the intended disk. Do not restore a header merely because a backup file exists.

If no separately tested access route can be established, seek expert data
recovery help. NixKeyforge cannot derive a LUKS passphrase, recovery key, or
authenticator secret.

### Header is unreadable or visibly damaged

Keep the target closed and unmounted. Prevent automount and avoid writes.
Acquire a separate block-level image when incident and storage policy permit.
Use a trusted rescue environment and obtain second-person review.

Proceed to the header-restoration gates below only if normal access has failed
and the alternative is accepted data loss.

## Manual header-restoration gates

NixKeyforge intentionally supplies no automatic header-restore action or
copy-paste command. The human operator uses the pinned upstream cryptsetup
documentation and tool directly only after all gates pass:

1. The target has been independently identified by physical device, exact LUKS
   UUID, major/minor, size, and expected role.
2. The target is closed, unmounted, and not a dependency of the rescue system.
3. Current damaged media has a separate forensic/block-level copy where
   feasible.
4. The encrypted NKFB package authenticated fully and passed schema, archive,
   length, and checksum validation in unprivileged staging.
5. The header member's manifest UUID and role exactly match the target.
6. Backup creation time and provenance are known and appropriate.
7. The operator understands that restoring an older header rolls keyslots and
   token metadata back to that time. Credentials enrolled later may disappear;
   credentials revoked later may return.
8. At least one credential represented by that historical header is still
   available and expected to work.
9. A second qualified person reviews the identity evidence, package, selected
   destination, and upstream command.
10. The organization accepts the remaining risk and records a manual recovery
    decision without recording secrets.

No mismatch has an override. A successful write is not successful recovery:
the operator must first perform a non-destructive unlock test using a credential
expected by the restored header, then mount read-only where appropriate, verify
data, and create a fresh recovery plan.

Consult the exact installed version and the upstream
[`cryptsetup(8)` source
manual](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc).
Do not copy a command from a different version or run it through a shell
wrapper.

## Token loss and replacement

If one token is lost:

1. record it as a security incident without recording credential contents;
2. regain stable access with the remaining tested route;
3. preserve recovery and a fresh encrypted header backup;
4. obtain a new, physically distinct authenticator and verify capabilities;
5. enroll it once for its intended role with no other token attached;
6. inventory the new token/keyslot association redacted;
7. enroll new independent PAM and SSH security-key credentials as applicable;
8. perform the complete manual hardware tests; and
9. only outside NixKeyforge 0.1 and under separate reviewed policy consider
   revoking obsolete LUKS or service credentials.

If both tokens are lost, the same process starts only from the independent
recovery key/passphrase. A backup archive cannot manufacture replacement
credentials.

## Verification after repair

Follow [manual-hardware-tests.md](manual-hardware-tests.md):

1. retain rescue media, recovery material, encrypted header backup, and
   known-good generation;
2. attach Primary only, boot, unlock, and verify the intended volume;
3. completely shut down and remove Primary;
4. attach Backup only, boot, unlock, and verify;
5. completely shut down and remove all tokens;
6. test the independent recovery key/passphrase; and
7. confirm separate redacted LUKS2 token/keyslot associations and that no
   recovery access was removed.

Metadata inspection alone cannot satisfy these tests. Multiple-token prompt
behavior and repeated PIN/UV/touch prompts are hardware-, firmware-, and
systemd-dependent.

## Exit criteria

Recovery remains degraded unless:

- exact target identity is recorded and unchanged;
- the intended generation boots;
- Primary and Backup pass separate token-only boot tests;
- independent recovery passes with neither token attached;
- current encrypted header and configuration backups verify;
- all existing recovery access remains; and
- test evidence contains no UUID published outside protected records, recovery
  value, PIN, credential handle, raw public key, or header metadata dump.

If any item is pending, use `dual-token-incomplete`, `recovery-unverified`,
`configuration-drift`, `lockout-risk`, or `unsupported` as applicable—never
`dual-token-ready`.

## Primary references

Validate behavior against the installed versions of
[`systemd-cryptenroll(1)`](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html),
[`crypttab(5)`](https://www.freedesktop.org/software/systemd/man/latest/crypttab.html),
and cryptsetup's own manual sources. The `latest` systemd pages are orientation
only: an operation plan must use the semantics of the pinned NixOS/systemd
revision.
