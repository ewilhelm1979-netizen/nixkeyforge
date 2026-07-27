# NixKeyforge

**NixKeyforge is a secure access and recovery manager for NixOS.**

NixKeyforge helps users discover, plan, generate, and verify a recoverable
configuration for PAM, FIDO2 hardware security keys, LUKS2, and OpenSSH. It
uses two independently enrolled authenticators by default: a daily primary
device and a separately stored backup device. Either device can authenticate
on its own; this is redundancy, not a two-of-two scheme.

> [!CAUTION]
> A PAM error can block every local login. A LUKS2 or initrd error can prevent
> the system from booting. Keep a privileged session open while testing PAM,
> retain a known-good NixOS generation, and have tested rescue media available.

> [!IMPORTANT]
> A second FIDO2 token does not replace an independent LUKS2 recovery key or
> strong passphrase. Backups cannot restore or clone private credential keys
> held inside an authenticator. The backup authenticator must be tested on real
> login and boot paths, then stored powered off, separate from the primary.

## Project status

Version 0.1 is a security-focused foundation. Discovery, plans, typed external
commands, redacted status output, Nix module generation boundaries, archive
validation, and test doubles are implemented without changing the host. Live
PAM, SSH, LUKS2, initrd, and boot changes are intentionally disabled in this
development build. Hardware-dependent verification remains manual.

The NKFB policy rejects packages that lack age-compatible authenticated
encryption, including the secret-free portable profile. The production backup
writer remains disabled in this foundation release. NixKeyforge has no daemon,
web API, GUI, telemetry, setuid helper, or automatic reboot path. It never
invokes `sudo`. Version 0.1 never deletes LUKS keyslots and never restores a
LUKS header automatically.

## Authentication terminology

- A **FIDO2 authenticator** or **hardware security key** is the physical token.
- A **PAM-U2F/FIDO2 credential** is independently enrolled for local PAM use.
- A **LUKS2 FIDO2 enrollment** uses the authenticator's `hmac-secret`
  capability and LUKS2 token metadata.
- An **OpenSSH security-key credential** is an `ed25519-sk` user key.
- A **WebAuthn passkey** is a separate web authentication concept.

The UI may use “passkey” informally, but the code and plans keep these domains
separate. Private keys held by an authenticator are not exported or backed up.

## Recommended recovery model

| Role | Use | Storage |
| --- | --- | --- |
| Primary authenticator | Daily login and LUKS2 boot unlock | With the user |
| Backup authenticator | Independent login and LUKS2 replacement | Tested, powered off, and stored separately |
| Recovery key/passphrase | Independent LUKS2 emergency access | Separate from the computer and both tokens |
| Rescue media | Repair a broken boot or PAM configuration | Tested and secured |

NixKeyforge reports `dual-token-ready` only after separate PAM and LUKS2 proofs
for both tokens plus an independent recovery proof. Metadata alone is not
proof. Other states include `unconfigured`, `single-token`,
`dual-token-incomplete`, `recovery-unverified`, `lockout-risk`,
`configuration-drift`, and `unsupported`.

## Command-line interface

Dry-run planning is the default. Human and secret-redacted JSON output are
available with `--format human` and `--format json`.

```text
nixkeyforge doctor
nixkeyforge status
nixkeyforge plan
nixkeyforge generate --output-dir ./generated

nixkeyforge fido detect
nixkeyforge fido inventory
nixkeyforge fido capabilities
nixkeyforge fido login status
nixkeyforge fido login plan
nixkeyforge fido login enroll --role primary
nixkeyforge fido login enroll --role backup
nixkeyforge fido login verify --role primary
nixkeyforge fido login verify --role backup

nixkeyforge luks inspect
nixkeyforge luks status
nixkeyforge luks plan
nixkeyforge luks enroll --role primary
nixkeyforge luks enroll --role backup
nixkeyforge luks verify --role primary
nixkeyforge luks verify --role backup
nixkeyforge luks recovery plan

nixkeyforge ssh inspect
nixkeyforge ssh plan
nixkeyforge backup create --output ./backup.age --recipient age1...
nixkeyforge backup inspect --backup ./backup.age
nixkeyforge backup verify --backup ./backup.age
nixkeyforge restore plan --backup ./backup.age
```

Exit code `0` is success, `10` is a warning, `20` is a blocker or lockout risk,
`30` is configuration drift, and `40` is failed verification. A high-risk
apply design requires a saved plan, its fingerprint, fresh precondition
checks, and interactive confirmation. There is no global `--yes`.
Backup create/inspect/verify and restore planning currently return the blocker
state `unsupported`; the in-memory NKFB model is not presented as a production
Age/tar verifier.

## Build and test

The workspace uses Rust 2024 with MSRV 1.85. The pinned NixOS 26.05 package set
currently supplies Rust 1.95.

```bash
nix develop
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit
cargo deny check
nix flake check
git diff --check
```

The flake exports the `nixkeyforge` package, default app, development shell,
NixOS module, module-evaluation check, and a hardware-free NixOS VM test.

## NixOS integration

Import `nixosModules.default`, then opt in to exact PAM services. The supported
profile keeps Unix password authentication and makes FIDO2 an additional
required factor. It never uses `nouserok` or `alwaysok`.

```nix
{
  inputs.nixkeyforge.url = "github:ewilhelm1979-netizen/nixkeyforge";

  outputs = { nixpkgs, nixkeyforge, ... }: {
    nixosConfigurations.workstation = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        nixkeyforge.nixosModules.default
        {
          services.nixkeyforge = {
            enable = true;
            pam = {
              enable = true;
              services = [ "login" "sddm" "kde" ];
              authFile = "/etc/u2f_mappings";
            };
          };
        }
      ];
    };
  };
}
```

The mapping path is a runtime string rather than a Nix path; credential
material must remain outside the Nix store. NixKeyforge generates new
fragments only in an explicit output directory and never rewrites another
flake.

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Dual-authenticator model](docs/dual-authenticator-model.md)
- [NixOS reference migration](docs/nixos-reference-migration.md)
- [Backup format](docs/backup-format.md)
- [Recovery runbook](docs/recovery-runbook.md)
- [Manual hardware tests](docs/manual-hardware-tests.md)
- [Security policy](SECURITY.md)

Technical choices are checked against the pinned Nixpkgs modules and the
official manuals for
[systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html),
[crypttab](https://www.freedesktop.org/software/systemd/man/latest/crypttab.html),
[cryptsetup](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/home),
[pam_u2f](https://developers.yubico.com/pam-u2f/Manuals/pam_u2f.8.html),
[pamu2fcfg](https://developers.yubico.com/pam-u2f/Manuals/pamu2fcfg.1.html),
and [OpenSSH](https://man.openbsd.org/ssh-keygen).

## License

NixKeyforge is licensed under GPL-3.0-only.
