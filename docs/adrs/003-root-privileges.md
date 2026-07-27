# ADR 003: Constrain root privileges to reviewed apply operations

- Status: Accepted
- Date: 2026-07-27

## Context

Reading system configuration normally needs no privilege, while updating a
root-owned PAM mapping or enrolling a LUKS2 token may require root. Combining
discovery, policy, user interaction, and privileged mutation in one elevated
process unnecessarily expands the attack surface. A setuid program, privileged
daemon, or implicit `sudo` call would also make the elevation boundary difficult
to inspect and test.

## Decision

NixKeyforge is not setuid, runs no permanently privileged daemon, and never
invokes `sudo` itself.

Discovery and plan generation run without elevation wherever the operating
system permits. A human administrator reviews the plan and plan fingerprint,
then explicitly starts the narrowly scoped apply operation with the required
privilege. Elevation is therefore outside NixKeyforge's control.

Every privileged operation must:

1. accept a typed operation rather than an arbitrary command;
2. use a compile-time allowlist of absolute executable paths and separated
   arguments, without a shell;
3. reject user-selected executables and environment-dependent executable
   lookup;
4. revalidate user, host, configuration revision, file hashes, target
   major/minor, LUKS UUID, expected mount role, keyslot inventory,
   authenticator role, and plan fingerprint as applicable;
5. abort on drift, ambiguity, unsafe path components, or missing recovery
   prerequisites;
6. limit filesystem access to the declared target and use safe atomic update
   primitives;
7. receive secrets from a protected terminal or child-process standard input,
   never from arguments, environment variables, plans, or logs; and
8. return redacted evidence and a manual recovery instruction.

These are enablement requirements, not a claim that a privileged process
exists in the foundation release. Live apply is disabled until every applicable
item has executable evidence and adversarial tests.

The future privileged process must not change `/etc/nixos`, activate a NixOS
generation, reboot, remove LUKS keyslots, restore a LUKS2 header, enable
passwordless PAM, or perform an operation that was not present in the reviewed
plan. The current version 0.1 foundation is dry-run-only for host and hardware
mutation.

Privilege is not evidence of authorization: the plan, explicit interactive
confirmation, and fresh precondition checks are all still required.

## Consequences

- The root attack surface is small and short-lived.
- Plans can be reviewed and tested without privilege.
- Calling applications cannot silently gain elevation; operators must arrange
  it explicitly.
- Apply may be less convenient and packaging must preserve the trusted
  executable-path allowlist.
- Root can still subvert the process or its inputs. NixKeyforge does not defend
  against an already-compromised kernel or administrator.
- A privileged failure can still cause lockout or boot failure, so manual
  verification and recovery preparation remain mandatory.

## Rejected alternatives

- **Setuid executable:** makes parsing and orchestration reachable across a
  durable privilege boundary.
- **Privileged daemon:** adds lifecycle, IPC authentication, and confused-deputy
  risks without a version 0.1 need.
- **Calling `sudo` automatically:** obscures operator intent and makes prompts
  and policy environment-dependent.
- **Arbitrary helper command:** defeats executable and argument validation.
- **Running the entire workflow as root:** grants discovery, parsing, rendering,
  and confirmation code privileges they do not need.
