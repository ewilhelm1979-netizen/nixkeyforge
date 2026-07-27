# ADR 001: Separate plan from apply

- Status: Accepted
- Date: 2026-07-27

## Context

PAM, LUKS2, initrd, SSH, and restore changes can cause lockout, an unbootable
host, data loss, or privilege escalation. Discovery facts can change between a
review and execution.

## Decision

Every operation follows discovery, preconditions, plan, plan fingerprint,
explicit confirmation, apply, verification, and recovery guidance. Plans
contain no secrets. High-risk apply requires a saved plan and matching
fingerprint. Immediately before apply, all security-relevant identity and
device facts are revalidated. Drift aborts.

The CLI has no global `--yes`. Version 0.1's development build and public
orchestration adapters block live apply while fresh typed evidence collectors
and verification rules mature. A caller-supplied boolean is not accepted as
proof that revalidation occurred.

## Consequences

Operations take more steps and cannot be conveniently scripted through a
single confirmation bypass. Users receive an auditable preview and TOCTOU
changes are detected at the last practical boundary. Fingerprints protect plan
integrity, not confidentiality or host identity; those are separate checks.
