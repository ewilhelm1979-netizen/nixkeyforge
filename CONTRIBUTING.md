# Contributing to NixKeyforge

NixKeyforge is security-critical software. Contributions must preserve local
login and boot availability as carefully as confidentiality and integrity.

## Ground rules

- Work on a topic branch and use Conventional Commits.
- Never commit credentials, private keys, PINs, passwords, recovery keys,
  real UUIDs, hardware identifiers, hostnames, or personal paths.
- Keep discovery, plan, apply, verification, and recovery separate.
- Do not add `unsafe`, setuid programs, privileged daemons, telemetry, shell
  command composition, or freely selectable executable paths.
- Pass secrets only through an appropriate interactive file descriptor or a
  library API designed for secret input, never arguments or environment.
- External commands use fixed executables and separate `std::process::Command`
  arguments.
- Tests must use fixtures, temporary directories, and mock executors. They
  must not alter real PAM, SSH, LUKS, initrd, or boot state.

## Required checks

Run the complete gate from the repository root:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit
cargo deny check
nix flake check
git diff --check
```

Hardware tests are ignored/manual and require two independently enrolled
authenticators, independent recovery material, rescue media, and explicit
authorization. Record each token test separately without publishing raw
credential or LUKS metadata.

## Security review

Changes touching command execution, path handling, PAM mapping updates, LUKS2
metadata, backups, restore, permissions, or plan fingerprints require a second
security review. Reviewers should test injection, traversal, symlink/hardlink,
TOCTOU, wrong-device, stale-plan, duplicate-token, secret-redaction, and
lockout cases.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
