# Threat model

## Purpose and status

This document defines the security boundaries and required controls for
NixKeyforge 0.1. NixKeyforge plans changes to local authentication, LUKS2
enrollment, SSH configuration, and encrypted recovery backups on NixOS. A defect
can therefore disclose credentials, grant root-level effects, lock out every
local login, or make the machine unbootable.

This is a design-time threat model, not a claim that every control is already
implemented or independently audited. A control is complete only when its code,
tests, and operator documentation provide evidence. Hardware-dependent claims
remain unverified until the manual tests in
[manual-hardware-tests.md](manual-hardware-tests.md) are recorded.

Version 0.1 performs no automatic reboot, passwordless-PAM activation, LUKS
keyslot removal, or LUKS2-header restore. Work on this repository must not
perform live PAM, SSH, LUKS, initrd, or boot changes.

The foundation release also has no production Age/tar reader, backup writer, or
restore-staging writer. Its in-memory archive model exercises schema and policy
rules but is not evidence that ciphertext authentication, tar parsing, or
exclusive staging is complete. Related CLI operations fail closed as
`unsupported`.

## Scope and security invariants

In scope are local inputs, generated plans and Nix modules, external system-tool
adapters, PAM-U2F mappings, LUKS2 metadata and enrollment planning, OpenSSH
planning, backup creation/inspection/verification, restore planning, and the
build and release pipeline.

The following invariants take precedence over convenience:

1. **Two tokens mean one-of-two redundancy.** Primary and Backup are different
   physical authenticators with independent PAM, LUKS2, and optional SSH
   credentials. They are not a 2-of-2 scheme.
2. **Recovery is independent.** A tested LUKS2 recovery key or strong passphrase
   is retained separately from the computer and both tokens. A rescue medium and
   known-good NixOS generation are also required.
3. **No cloning claim.** Authenticator-internal private keys cannot be exported,
   backed up, cloned, or restored by NixKeyforge.
4. **No inferred verification.** Configuration and token metadata do not prove
   PAM login or boot unlock. Primary and Backup require separate manual tests;
   each LUKS2 test boots with only the token under test attached.
5. **No secret-bearing plans or output.** Secrets never enter command
   arguments, environment variables, Git, the Nix store, plans, status files,
   logs, JSON, diagnostics, or telemetry. NixKeyforge has no telemetry.
6. **No implicit privilege.** There is no setuid binary, privileged daemon, or
   internal `sudo` invocation. An administrator explicitly elevates a reviewed,
   narrowly scoped apply operation.
7. **No shell interpretation.** Fixed executables are invoked with separated,
   typed arguments. There is no `sh -c`, `bash -c`, `eval`, generic executable,
   or generic command option.
8. **Plan and apply are separate.** A future enabled apply revalidates the actor, host, source
   revision, file hashes, device identity, LUKS UUID, mount role, keyslots,
   authenticator and role, and plan fingerprint. Drift fails closed before
   mutation. The foundation release refuses live apply because those fresh
   typed evidence checks are not complete.
9. **Fail closed without manufacturing lockout.** Ambiguous targets, devices,
   tokens, archive entries, versions, and PAM semantics are blockers. Existing
   recovery access is never silently disabled.

## Assumptions and non-goals

- The kernel, firmware, root account, rescue environment, and external tools may
  be compromised; NixKeyforge can reduce exposure but cannot establish trust on
  an already compromised host.
- Physical theft is in scope. Destructive hardware attacks, authenticator
  firmware extraction, evil-maid attacks against an untrusted boot chain, and
  coercion are not fully mitigated by this project.
- Denial of service by an existing root administrator cannot be prevented.
- NixKeyforge validates observed target state but does not prove that a device
  path has the operator's intended business meaning. Human review remains
  necessary.
- Availability depends on NixOS, systemd, cryptsetup, pam-u2f, OpenSSH, hardware
  firmware, and correct operator custody.
- The generated Nix module is inert until the operator deliberately imports and
  activates it. NixKeyforge never rewrites a foreign flake.
- Redacted identifiers are pseudonyms, not anonymization. Domain separation
  prevents accidental cross-domain equality, but low-entropy source values may
  still be guessed and stable digests may permit correlation. They remain
  sensitive and backups containing them remain encrypted.

## Actors and trust boundaries

### Threat actors

- an unprivileged local user controlling CLI values, files, paths, the working
  directory, or selected backup input;
- malware running as the invoking user and racing filesystem operations;
- a malicious or mistaken administrator;
- a thief holding the computer, one token, a backup package, or recovery
  material;
- a backup sender supplying a package from another host;
- a dependency, build-tool, repository, maintainer-account, or CI compromise;
- accidental operator error, including selecting the wrong disk or token.

### Trust boundaries

1. **CLI/input to domain model:** all strings and paths are untrusted.
2. **Unprivileged process to privileged apply:** a plan is a request, not
   authority; all relevant facts are rechecked.
3. **Filesystem names to filesystem objects:** names can be replaced, linked, or
   raced.
4. **NixKeyforge to external binaries:** stdout, stderr, exit status, version,
   and parsed metadata are untrusted and version-dependent.
5. **Host to removable authenticator:** device order and prompts may be
   ambiguous; user presence is not necessarily user verification.
6. **Encrypted backup to restore staging:** encryption authenticates bytes from
   the holder of an encryption identity; it does not establish that the package
   belongs to this host or is safe to extract.
7. **Source to CI/release:** dependencies, actions, runners, artifacts, and
   credentials may be compromised.

## Assets and CIA requirements

`H`, `M`, and `L` express the impact if the property is lost; `—` means the
property is not normally a security objective for that asset.

| Asset | C | I | A | Security requirement |
|---|:---:|:---:|:---:|---|
| LUKS2 header and keyslots | H | H | H | Encrypt backups; bind every operation to UUID and device identity; never remove slots or automatically restore a header in 0.1. |
| LUKS2 token metadata | M | H | H | Treat associations and salts as sensitive; inventory redacted; require distinct, verified enrollment records. |
| Recovery keys and passphrases | H | H | H | Never persist or log plaintext; accept only through protected interactive input; store independently and test manually. |
| Primary authenticator | M | H | H | Require custody, PIN/UV policy where supported, independent enrollment, and prompt loss-response. |
| Backup authenticator | M | H | H | Keep physically separate; enroll independently; periodically test; never describe it as a clone. |
| PAM-U2F mapping | M | H | H | Do not place in the Nix store; default root ownership and `0600`; atomically preserve unrelated users; redact raw handles and public keys. |
| Local login availability | — | H | H | Preserve Unix-password fallback by default; keep a privileged session open during tests; test each service separately. |
| Boot availability | — | H | H | Retain recovery and known-good generation; use separate token-only boot tests; never reboot automatically. |
| SSH user and host keys | H for private; L for public | H | M | Distinguish key classes; never use FIDO2 host keys; exclude private keys from backups by default. |
| Backup packages | H | H | H | Encrypt and authenticate; validate schema, manifest, identity, limits, and allowlist before restore planning. |
| Root privileges | H | H | H | No persistent privilege; typed, reviewed, least-privilege apply only; no arbitrary executable or shell. |
| Generated Nix modules | L | H | H | Generate only into an explicit output directory; validate and review diffs; never activate automatically. |
| Plan and status files | M | H | M | Contain no secrets; bind to host and observed state through redacted identifiers and fingerprints; reject stale plans. |
| Audit and diagnostic output | M | H | M | Redact by construction, avoid raw external-tool output, record meaningful state without credentials. |

## Risk method

Risk is qualitative: impact considers the worst credible CIA consequence and
likelihood considers required access and expected exposure. **Critical** means
credible root compromise, irreversible data loss, or total lockout without a
reliable compensating control. **High** requires remediation before apply;
**Moderate** requires explicit operator awareness and verification; **Low** is
accepted with routine tests. Residual risk assumes every listed control works.
If a control is missing or unverified, use the higher inherent rating.

## Threat register

The framework references are informative mappings, not certifications. Short
names are expanded in [Control-framework mapping](#control-framework-mapping).

| ID and threat | CIA | Inherent | Required controls | Residual risk | Framework references |
|---|:---:|:---:|---|---|---|
| T01 **Command injection** through paths, labels, configuration, or parsed tool output | C/I/A | Critical | Never invoke a shell; use fixed absolute executables, typed operations, separated arguments, strict parsing, and adversarial tests. | Low; a defect in an invoked tool or validation layer remains possible. | SSDF PW.5/PW.7; CSF PR.PS; OWASP A05; ATT&CK T1059.004; ISO 8.28/8.29 |
| T02 **Argument injection**, including values beginning with `-` or changing external-tool mode | I/A | High | Each adapter owns its argument grammar; reject unexpected option-like values, use `--` where supported, validate enums/identifiers, and provide no pass-through argument list. | Low; upstream option semantics can change across versions. | SSDF PW.5/PW.8; CSF PR.PS; OWASP A05/A06; ATT&CK T1059; ISO 8.28/8.29 |
| T03 **Path traversal** from CLI, manifest, archive, or generated output paths | C/I/A | High | Reject absolute, empty, `.` and `..` components; normalize exactly once; require a fixed allowlisted root; reject prefix collisions and platform-specific alternate separators; never use generic archive extraction. | Low; filesystem and parser edge cases require property tests. | SSDF PW.5/PW.8; CSF PR.DS/PR.PS; OWASP A01/A05; ATT&CK T1565.001; ISO 8.3/8.28/8.29 |
| T04 **Symlink and hardlink attacks** against mappings, backup staging, outputs, or restore targets | C/I/A | Critical | Walk trusted directories without following links; reject archive link types; verify type, owner, mode, link count and opened-object identity; create exclusive temporary files in the target directory; `fsync` then atomic rename; recheck after open. | Moderate; a compromised root/kernel can bypass userspace checks, and platform primitives differ. | SSDF PW.5/PW.8; CSF PR.DS/PR.PS; OWASP A01/A08; ATT&CK T1565.001; ISO 8.3/8.9/8.28 |
| T05 **TOCTOU between plan and apply** after a file, device, authenticator, or configuration changes | I/A | Critical | Fingerprint the secret-free plan; immediately before mutation revalidate actor, host, revision, hashes, device major/minor, UUID, mount role, keyslots, token role and inventory; bind writes to opened objects; abort on any drift. | Moderate; hotplug and malicious local races cannot be eliminated entirely. | SSDF PW.1/PW.2/PW.8; CSF ID.RA/PR.PS; OWASP A06/A08/A10; ATT&CK T1565.001; ISO 8.9/8.29/8.32 |
| T06 **Manipulated or foreign backup** is decrypted and trusted as local recovery state | C/I/A | Critical | Age/AEAD authentication; full authentication before use; one canonical manifest; component hashes for diagnosis; schema/profile/version checks; redacted host and exact LUKS identity match; explicit foreign-backup override only at plan time; fixed restore allowlist and staging. | Moderate; possession of a valid age identity does not authenticate the package's operational origin, and an old but valid package may be unsafe. | SSDF PW.4/PW.8; CSF PR.DS/DE.AE/RC.RP; OWASP A04/A08; ATT&CK T1565.001; ISO 8.13/8.24/8.29 |
| T07 **Disk confusion** causes an operation on the wrong block device | I/A | Critical | Prefer `/dev/disk/by-uuid`; record and recheck LUKS UUID, major/minor, expected mount/system role, LUKS version, keyslots and observed path; show a redacted plan; stop on ambiguity. | Moderate; an operator can still approve the wrong but internally consistent target. | SSDF PW.1/PW.8; CSF ID.AM/PR.PS; OWASP A06/A10; ATT&CK T1485; ISO 8.9/8.32 |
| T08 **False or stale LUKS UUID** targets a different container | I/A | Critical | Read the UUID from the opened device through a typed cryptsetup adapter, compare it with the plan and configured role immediately before apply, and reject missing, duplicate, or changed UUIDs. Never trust a path name alone. | Moderate; storage cloning can duplicate UUIDs, so major/minor and role checks are also necessary. | SSDF PW.5/PW.8; CSF ID.AM/PR.PS; OWASP A06/A08; ATT&CK T1565.001; ISO 8.9/8.29 |
| T09 **Overwrite of the wrong LUKS2 header** destroys access or exposes metadata | C/I/A | Critical | No automatic header restore in 0.1; recovery documentation requires offline media, unmounted/closed target, exact UUID and device identity, authenticated backup, second-person review, and direct use of upstream tools by the operator. | High; a header restore is intrinsically destructive and a mistaken but confirmed target can still cause irreversible loss. | SSDF PW.1/PW.9; CSF PR.IR/RC.RP; OWASP A06/A10; ATT&CK T1485/T1490; ISO 5.29/5.30/8.13/8.32 |
| T10 **PAM lockout** from wrong service semantics, mapping, control flags, or disabled Unix authentication | I/A | Critical | Treat `login`, SDDM, screen locker, `sudo`, polkit, `su`, and SSH-PAM independently; derive options from the pinned Nixpkgs revision; keep Unix password enabled by default; forbid `nouserok`/`alwaysok`; keep a privileged session open; test a second session; never auto-enable passwordless PAM. | Moderate; PAM composition and display-manager behavior remain host-specific. | SSDF PW.1/PW.2/PW.8/PW.9; CSF PR.AA/PR.IR; OWASP A02/A06/A07/A10; ATT&CK T1098; ISO 5.15/5.17/8.9/8.29 |
| T11 **Unbootable system** from initrd, crypttab, module, or enrollment incompatibility | I/A | Critical | Verify systemd initrd, LUKS2, `hmac-secret`, and pinned-version support; build before test; retain known-good generation, rescue medium, header backup plan, and independent recovery; never reboot or switch automatically; require separate manual boots. | Moderate; real firmware, initrd, token, and prompt behavior cannot be fully reproduced in a VM. | SSDF PW.4/PW.8/PW.9; CSF PR.IR/RC.RP; OWASP A02/A06/A10; ATT&CK T1490; ISO 5.29/5.30/8.13/8.32 |
| T12 **Loss or theft of Primary** removes daily access or lets a thief attempt authentication | C/A | High | Independently enrolled and tested Backup; independent recovery; prompt incident response; PIN/UV policy where supported; never weaken touch/PIN for convenience; do not treat user presence as identity verification. | Moderate; token policy and retry behavior vary, and theft plus a known PIN can enable use. | SSDF PW.1/PW.9; CSF PR.AA/RS.MA/RC.RP; OWASP A07; ATT&CK T1552 (only where another credential is exposed); ISO 5.17/5.24/8.5 |
| T13 **Simultaneous loss of both tokens** causes lockout | A | High | Independent, separately stored and tested recovery key/passphrase; rescue medium; replacement-token re-enrollment runbook; geographically separate Backup custody. | Moderate to High; common-cause loss can also affect recovery media or material. | SSDF PW.1; CSF PR.IR/RC.RP; OWASP A06/A10; ATT&CK T1490; ISO 5.29/5.30/8.13 |
| T14 **Untested Backup token** creates false redundancy | I/A | High | Status cannot be ready from enrollment metadata; separately test every PAM service and perform a Backup-only boot; record date and redacted evidence; periodically retest after relevant upgrades. | Moderate; later drift, token failure, battery-free contact wear, or firmware behavior can invalidate old evidence. | SSDF PW.8; CSF ID.IM/PR.IR; OWASP A06/A10; ISO 5.30/8.29 |
| T15 **The same token is enrolled twice** as Primary and Backup | I/A | High | Sequential single-token ceremony; compare redacted stable observations and before/after credentials/keyslots; require a new mapping entry and LUKS token/keyslot association; abort if physical distinctness is uncertain. | Moderate; privacy-preserving authenticators may not expose a reliable global device identity, so human custody evidence remains necessary. | SSDF PW.1/PW.8; CSF PR.AA/DE.AE; OWASP A06/A07; ISO 5.17/8.29 |
| T16 **PAM mapping tampering** adds, replaces, duplicates, or removes credentials | C/I/A | Critical | Root-owned `0600` target by default; no Nix-store copy; parse per-user records; preserve other users; reject malformed/duplicate credentials; link-safe atomic update; hash precondition; create protected rollback copy; redact content. | Moderate; root compromise can alter both mapping and evidence, and a syntactically valid malicious credential may be hard to attribute. | SSDF PW.5/PW.8; CSF PR.AA/PR.DS/DE.CM; OWASP A01/A07/A08; ATT&CK T1098/T1565.001; ISO 5.15/8.3/8.9/8.15 |
| T17 **Credential-handle, public-key, or redacted-identifier disclosure** reveals user/token relationships and aids targeting | C | Moderate | Treat raw PAM handles, public keys, salts, token metadata, and stable redacted IDs as sensitive; use domain-separated labels; never print complete mappings or raw tool output; encrypt backups. | Moderate; public SSH keys may be intentionally published, host metadata exists by design, and low-entropy values behind an unkeyed digest may be guessed or correlated. | SSDF PW.5/PW.9; CSF PR.DS; OWASP A02/A09; ATT&CK T1552; ISO 5.12/8.12/8.24 |
| T18 **Secret leakage through debug, JSON, errors, panic, child output, arguments, or environment** | C | Critical | Secret types without raw `Debug`; centralized structured redaction; allowlisted fields; suppress/sanitize external stdout/stderr; no telemetry; no arguments/environment/plans for secrets; tests with canary secrets; fail safely on serialization errors. | Low to Moderate; upstream programs and crash facilities may expose data outside NixKeyforge's control. | SSDF PW.5/PW.7/PW.8/PW.9; CSF PR.DS/DE.AE; OWASP A02/A09/A10; ATT&CK T1552.001/T1552.007; ISO 8.12/8.15/8.28 |
| T19 **Wrong file ownership or permissions** exposes secrets or permits tampering | C/I/A | High | Verify parent and target owner, mode, type, and link count; default backup directory `0700`, backup files and PAM mapping `0600`; restrictive umask; create-then-verify; abort rather than silently broaden access. | Moderate; ACLs, mount options, and network filesystems can alter effective protection. | SSDF PW.9; CSF PR.AA/PR.DS; OWASP A01/A02; ATT&CK T1222.002; ISO 5.15/8.3/8.9 |
| T20 **Privilege escalation or confused deputy** turns NixKeyforge into a root command/file primitive | C/I/A | Critical | No setuid/daemon/internal sudo; elevate only explicit apply; typed allowlisted operations and executable paths; drop unneeded environment; safe paths; revalidate plan; least privilege; security review of every privileged adapter. | Moderate; administrator-approved root operations remain powerful, and an external privileged tool may contain vulnerabilities. | SSDF PO.5/PW.5/PW.7; CSF PR.AA/PR.PS; OWASP A01/A05/A06; ATT&CK T1548.003; ISO 8.2/8.18/8.28 |
| T21 **Malicious configuration paths** redirect discovery, generation, mapping, key, or backup access | C/I/A | Critical | Canonical typed path roles; explicit output root; no automatic foreign-flake editing; reject unsafe components and non-regular inputs; enforce per-operation allowlists; display resolved redacted target; test hostile Unicode and option-like names. | Moderate; bind mounts and namespace changes can preserve a valid path while changing its meaning. | SSDF PW.5/PW.8; CSF PR.DS/PR.PS; OWASP A01/A05; ATT&CK T1565.001; ISO 8.3/8.9/8.28 |
| T22 **Software supply-chain compromise** changes dependencies, Nix inputs, build tools, or releases | C/I/A | Critical | Pin Cargo and Nix dependencies; minimize crates; review lockfile changes; `cargo audit`, `cargo deny`, SBOM, reproducible builds, protected releases, signed/provenanced artifacts when available, and documented update review. | Moderate; trusted upstream, compiler, registry, and maintainer compromise remain possible. | SSDF PO.3/PO.5/PS.1/PS.2/PW.4/RV.1; CSF GV.SC/ID.RA/PR.PS; OWASP A03; ATT&CK T1195.001/T1195.002; ISO 5.19/5.21/8.25/8.30 |
| T23 **Compromised GitHub Actions** exfiltrate CI secrets or publish malicious artifacts | C/I/A | Critical | Minimal workflow `permissions`; full-SHA action pins; no secrets for untrusted PRs; no unsafe `pull_request_target`; isolated build/release roles; environment approval; artifact verification; review workflow changes as security-critical. | Moderate; GitHub, runner images, pinned action commits, or maintainer accounts can still be compromised. | SSDF PO.3/PO.5/PS.1/PS.2; CSF GV.SC/PR.AA/PR.PS; OWASP A03/A08; ATT&CK T1195.002; ISO 5.18/5.23/8.25/8.31 |
| T24 **Dependency confusion** selects an attacker-controlled crate, package, or build input | C/I/A | High | Exact package identities and sources; committed lockfiles; no undeclared private-name fallback to public registries; source/checksum review; dependency allowlist and license/advisory policy; offline/restricted release build where practical. | Moderate; registry account takeover and malicious accepted updates remain possible. | SSDF PW.4/RV.1; CSF GV.SC/ID.RA; OWASP A03; ATT&CK T1195.001; ISO 5.21/8.25/8.30 |
| T25 **Rollback to an incompatible systemd/NixOS version** leaves FIDO2 enrollment or initrd behavior unusable | I/A | High | Bind plans to observed tool/Nixpkgs versions; check required options and capabilities against the pinned revision; invalidate on revision drift; build before activation; retain old generation and independent recovery; repeat manual boots after rollback/upgrade. | Moderate; downgrade semantics and firmware interactions may only emerge at real boot. | SSDF PW.4/PW.8/PW.9; CSF ID.RA/PR.PS/RC.RP; OWASP A02/A06/A10; ATT&CK T1490; ISO 8.9/8.19/8.29/8.32 |
| T26 **Multiple attached FIDO2 tokens and ambiguous boot prompts** select the wrong device or create repeated PIN/UV/touch prompts | I/A | High | One-token-at-a-time enrollment; explicit removal/insertion ceremony; document systemd `auto` limitations; each boot test has exactly one attached token; abort automated enrollment if device selection is ambiguous; never infer role from enumeration order. | Moderate; firmware and systemd prompt behavior varies and cannot be made fully unambiguous by metadata. | SSDF PW.1/PW.8; CSF PR.AA/PR.IR; OWASP A06/A07/A10; ISO 5.17/8.29 |
| T27 **Recovery material theft, corruption, or co-location** defeats confidentiality or all recovery | C/A | Critical | Generate/enter through a protected interactive channel; never persist plaintext; encrypt selected backup material; store recovery separately from host and both tokens; maintain more than one controlled copy where policy permits; test and inventory without recording secret values. | High; recovery material intentionally unlocks the volume, and physical custody remains outside software control. | SSDF PW.9; CSF PR.DS/PR.IR/RC.RP; OWASP A04/A07; ATT&CK T1552; ISO 5.17/5.29/8.13/8.24 |
| T28 **Tampered or stale plan/status file** authorizes a different operation or reports false readiness | I/A | High | Canonical serialization; domain separation and fingerprint; no secrets; bind observed facts and intended role; re-discover before apply; ignore claimed verification unless backed by manual evidence; explicit expiry/drift state. | Moderate; a malicious administrator can replace both plan and binary, and fingerprinting is not a signature. | SSDF PW.5/PW.8; CSF PR.DS/DE.AE; OWASP A08; ATT&CK T1565.001; ISO 8.9/8.15/8.24 |
| T29 **Audit suppression or misleading diagnostics** hides failure, exposes secrets, or yields a false green state | C/I/A | High | State-machine outcomes distinguish warning, blocker, drift and failed verification; redacted structured records; record tool version and evidence source; never convert unknown hardware state to success; test exceptional paths; no raw credential output. | Moderate; local users can delete their own records and root can falsify system evidence. | SSDF PW.7/PW.8/RV.1; CSF DE.AE/RS.MA; OWASP A09/A10; ATT&CK T1070; ISO 8.15/8.16/8.29 |

## Control-framework mapping

The mappings below explain the abbreviated references in the threat register.
They are selected because they fit this local privileged application; OWASP Top
10 categories are used as secure-design analogies and do not imply that
NixKeyforge is a web application.

### NIST Secure Software Development Framework

[NIST SP 800-218, SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
is the current final baseline used here. The relevant practices are:

- **PO.3/PO.5:** implement supporting toolchains and protect development
  environments;
- **PS.1/PS.2:** protect code from tampering and provide release-integrity
  verification;
- **PW.1/PW.2:** define security requirements, threat-model, and review design;
- **PW.4:** acquire and reuse well-secured components;
- **PW.5/PW.7:** secure coding and human/tool-assisted code review;
- **PW.8/PW.9:** executable security testing and secure-by-default
  configuration; and
- **RV.1:** continuously identify and confirm vulnerabilities.

### NIST Cybersecurity Framework

[NIST CSF 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20)
is referenced at category level:

- **GV.SC** supply-chain governance;
- **ID.AM/ID.RA/ID.IM** asset identity, risk assessment, and improvement;
- **PR.AA/PR.DS/PR.PS/PR.IR** identity and access, data security, platform
  security, and infrastructure resilience;
- **DE.CM/DE.AE** monitoring and adverse-event analysis;
- **RS.MA** incident management; and
- **RC.RP** recovery-plan execution.

### OWASP

The threat register references the [OWASP Top
10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/): A01 Broken
Access Control, A02 Security Misconfiguration, A03 Software Supply Chain
Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07
Authentication Failures, A08 Software or Data Integrity Failures, A09 Security
Logging and Alerting Failures, and A10 Mishandling of Exceptional Conditions.
The dedicated [OWASP Command Injection
description](https://owasp.org/www-community/attacks/Command_Injection) also
supports the no-shell invariant.

### MITRE ATT&CK

ATT&CK is used only where an adversary behavior has a useful match, especially
[T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/),
[T1548.003 Sudo and Sudo
Caching](https://attack.mitre.org/techniques/T1548/003/), T1098 Account
Manipulation, T1195.001/T1195.002 Supply Chain Compromise, T1222.002 Linux and
Mac File and Directory Permissions Modification, T1485 Data Destruction, T1490
Inhibit System Recovery, T1552 Unsecured Credentials, T1565.001 Stored Data
Manipulation, and T1070 Indicator Removal. The mapping describes attacker
behavior, not detection coverage.

### ISO/IEC 27001 and 27002

[ISO/IEC 27001:2022](https://www.iso.org/standard/27001) supplies the
risk-management and CIA context. Control references use
[ISO/IEC 27002:2022](https://www.iso.org/standard/75652.html), notably 5.12
classification, 5.15 access control, 5.17 authentication information, 5.18
access rights, 5.19/5.21 supplier and ICT supply-chain security, 5.24 incident
preparation, 5.29 security during disruption, 5.30 ICT readiness, 8.2
privileged access, 8.3 access restriction, 8.5 secure authentication, 8.9
configuration management, 8.12 data-leakage prevention, 8.13 backup, 8.15/8.16
logging and monitoring, 8.18 privileged utilities, 8.19 software installation,
8.24 cryptography, 8.25 secure development lifecycle, 8.28 secure coding, 8.29
security testing, 8.30 outsourced development, 8.31 environment separation, and
8.32 change management.

These references guide engineering and review; this project does not claim
formal NIST or ISO conformity.

## Required verification evidence

Automated evidence must include unit and integration tests for typed commands,
argument rejection, redaction, parsers, state transitions, plan drift, target
identity, atomic file handling, archive limits, link and traversal rejection,
AEAD failure, manifest duplication, UUID mismatch, and schema incompatibility.
Dependency policy, lockfiles, CI permissions, and action pins require review.

Hardware evidence is separate and manual:

- Primary-only and Backup-only PAM tests for each configured service;
- Primary-only and Backup-only LUKS2 boot tests, separated by a complete
  shutdown;
- a token-independent recovery test;
- proof that separate PAM credentials and separate LUKS2 token/keyslot
  associations remain; and
- confirmation that a privileged session and known-good recovery path were
  retained throughout testing.

No status may be promoted to `dual-token-ready` while any of this evidence is
missing, stale after a relevant configuration/tool change, or ambiguous.

## Review triggers

Revisit this model whenever NixKeyforge adds an apply operation, changes archive
or manifest schemas, supports a new PAM service, changes privilege separation,
adds a dependency or CI permission, changes external-tool version support, or
receives evidence of different authenticator/firmware behavior. A NixOS,
systemd, cryptsetup, pam-u2f, OpenSSH, or token-firmware upgrade invalidates the
relevant hardware verification until retested.
