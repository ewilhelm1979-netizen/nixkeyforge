# Recovery runbook

## Safety boundary

This runbook is for a human operator recovering a NixOS system. NixKeyforge 0.1
does not automatically reboot, switch generations, edit live PAM or SSH files,
remove LUKS keyslots, feed recovery secrets to commands, unlock a volume, or
restore a LUKS2 header. It may collect redacted read-only observations and
produce a plan.

Do not start a write operation merely because a backup decrypts or a device path
exists. Stop if the host, LUKS UUID, device major/minor, expected volume role,
backup provenance, or current recovery route is uncertain.

## Prepared state

Recovery is credible only when the following were prepared before the incident:

- a tested rescue medium compatible with the machine;
- a retained known-good NixOS generation;
- an independent LUKS2 recovery key or strong passphrase stored away from the
  machine and both tokens;
- an encrypted, verified backup appropriate to the recovery scenario;
- an encrypted LUKS2 header backup identified by exact UUID and creation time;
- Primary and Backup authenticators enrolled independently, with Backup stored
  separately; and
- a paper or offline record of the redacted inventory and last manual test
  results.

The second authenticator is an availability spare, not a clone and not an
independent disk-recovery method. Its internal credentials are not present in
any backup.

## First response

1. **Preserve access.** If any authenticated or privileged session is open, do
   not close it. Do not reboot a running machine solely to test a theory.
2. **Stop repeated attempts.** Repeated PIN, password, or recovery-entry
   failures can create additional lockout or obscure the original symptom.
3. **Record facts without secrets.** Record time, boot generation, tool and
   system versions, affected service, redacted token role, redacted disk
   identity, and exact non-secret error text. Do not photograph or copy recovery
   material, PAM mappings, private keys, or full LUKS metadata.
4. **Consider compromise.** Unexpected mapping, keyslot, initrd, package, or
   authentication changes may be malicious. If compromise is plausible, stop
   trusting the installed operating system, disconnect unnecessary networks,
   preserve evidence, and use known-good offline media. Recovery and incident
   investigation are then separate activities.
5. **Choose the least destructive branch below.** Do not combine PAM and LUKS
   changes in one recovery attempt.

## Triage

| Observation | Likely branch | Immediate safe action |
|---|---|---|
| Disk unlocked and at least one privileged session remains | PAM or service configuration | Keep that session open and follow [PAM lockout recovery](pam-lockout-recovery.md). |
| One login service fails but another works | Service-specific PAM policy | Do not apply a global PAM change; compare only the affected service with the known-good generation. |
| FIDO2 early-boot prompt fails but independent recovery works | Token enrollment, initrd, or version drift | Unlock through recovery, retain current header/keyslots, and follow [LUKS2 recovery](luks2-recovery.md). |
| Primary is unavailable but Backup works | Token-loss incident | Use Backup only as needed, protect it, and schedule fresh replacement enrollment after stable access. |
| Neither token is available | Common-cause token loss | Use only the independent recovery path; a backup package cannot reconstruct the tokens. |
| No token and no recovery secret unlocks | Possible wrong device, wrong UUID, damaged header, or lost credentials | Stop. Do not format, repair, enroll, restore a header, or try another disk by guesswork. |
| Backup decrypts but host or LUKS identity differs | Foreign/stale backup | Inspect only in private staging; do not produce a live restore. |
| Header metadata is damaged or unreadable | Destructive-recovery scenario | Keep the device closed and unmounted; follow the manual header section of the LUKS2 runbook with expert review. |
| System boots a prior generation successfully | Configuration regression | Stay on the known-good generation; investigate and rebuild before any activation. |

## Recovery sequence

### 1. Establish a trusted environment

Prefer the still-open trusted session. If none exists, select a retained
known-good generation at the bootloader. If disk unlock or the installed system
cannot be trusted, use the pre-tested rescue medium.

Confirm the keyboard layout before entering a recovery key or passphrase. Attach
only the device needed for the selected branch. Do not attach both
authenticators during automatic FIDO2 discovery.

### 2. Re-identify the target

Read current state without mutation. Establish all of:

- LUKS format is LUKS2;
- the exact on-device LUKS UUID;
- current device major/minor and stable by-UUID path;
- expected system role, such as the root volume;
- whether it is open, mounted, or in use;
- current keyslot and token inventory, recorded only in redacted form;
- booted and configured NixOS generations and pinned Nixpkgs/systemd versions;
- affected PAM services and whether Unix-password authentication remains
  configured; and
- which single physical authenticator, if any, is attached.

Mismatch or ambiguity is a blocker. A filesystem label, path name, device
enumeration order, or backup filename is not sufficient identity.

### 3. Restore availability before changing policy

Prefer, in order:

1. an already open session;
2. a known-good NixOS generation;
3. the independently tested recovery key/passphrase from trusted media; and
4. the separately stored, previously tested Backup authenticator.

The order can vary with the incident, but none of these routes authorizes a
destructive header or keyslot change. If a route succeeds, first preserve a
fresh redacted inventory and an encrypted backup plan. Do not "clean up" old
keyslots or recovery paths.

### 4. Repair one layer

- For a PAM regression, restore the declarative source or known-good generation;
  do not hand-edit generated PAM stacks as a routine fix.
- For a mapping issue, compare the intended user entry without printing raw
  handles or public keys; preserve unrelated user lines; verify regular-file
  type, no links, root ownership, and `0600` before any deliberate replacement.
- For an initrd or NixOS module regression, build and inspect a corrected
  generation before selecting it for a test boot. Retain the old generation.
- For a lost token, stabilize access first, then enroll a new physical device
  separately in each required credential domain.
- For a damaged LUKS2 header, do not proceed from this general runbook. Header
  restoration requires the additional gates in
  [luks2-recovery.md](luks2-recovery.md).

Never repair multiple layers in one plan. A successful file restore is not PAM
verification, and restored LUKS metadata is not boot verification.

### 5. Verify and return to service

Verification is manual:

- test each affected PAM service in a second session while a privileged session
  stays open;
- verify Unix-password behavior exactly matches the reviewed policy;
- test Primary and Backup separately;
- perform LUKS2 Primary-only and Backup-only boots separated by a complete
  shutdown;
- test the independent recovery method with neither token attached; and
- review that all pre-existing recovery access remains.

Use [manual-hardware-tests.md](manual-hardware-tests.md) and retain redacted
evidence. Do not report `dual-token-ready` until every required test passes.

## Backup use during recovery

Follow [backup-format.md](backup-format.md). A package must authenticate through
end-of-file, pass strict schema and archive validation, and match freshly
observed host and LUKS identity. Decrypt and validate only into a new private,
unprivileged staging area.

No archive path maps directly to `/etc`, `/etc/nixos`, a home SSH directory, or
a block device. Back up the current state before any later manual replacement
and review a diff. A restored PAM mapping or public key still requires service
testing. A restored LUKS header remains outside automatic restore.

## Escalation and stop conditions

Stop and seek an experienced NixOS/LUKS administrator or professional data
recovery assistance when:

- no independent recovery path works;
- device identity or LUKS UUID is uncertain or duplicated;
- the target is not LUKS2;
- header backup identity, age, or provenance is uncertain;
- a header write would be required;
- current data has no separate backup;
- token distinctness or capability is uncertain;
- PAM semantics cannot be derived from the pinned Nixpkgs revision;
- unexpected root-owned changes suggest compromise; or
- a write failed and current on-device state is no longer understood.

Do not run filesystem repair, `luksFormat`, keyslot deletion, reencryption, or
header restore as an experiment.

## Incident closure

After stable access and successful manual tests:

- rotate any recovery material or SSH private key that may have been exposed;
- revoke and replace credentials associated with a lost token in every domain;
- return Backup and recovery material to separate secure storage;
- update the encrypted backup and verify it;
- record only redacted evidence, versions, dates, and the root cause;
- invalidate stale plans and old recovery inventories; and
- update this runbook or tests if the incident exposed a missing control.
