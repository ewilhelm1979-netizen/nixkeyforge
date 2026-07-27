# NixOS reference assessment and migration

## Read-only assessment

The reference checkout was inspected read-only at commit
`3008ec1e540ec13e358ce53974f0a643eb67d2f0`, matching its GitHub `main`.
The local checkout has an unrelated uncommitted `flake.lock` update; it was not
modified, staged, reset, or pulled.

The system host input remains `nixpkgs_3`, branch `nixos-26.05`, revision
`597283ad8aa0b331c788e97c4c262d58877074ef`. Direct evaluation against that
revision reported:

- NixOS `26.05.20260724.597283a`;
- systemd `260.2`;
- systemd initrd enabled;
- a LUKS device reached through an anonymized by-UUID path;
- `fido2-device=auto` in the initrd crypttab options;
- SDDM and Plasma 6;
- OpenSSH server disabled;
- a hardened Home Manager OpenSSH client;
- password-based `sudo`;
- a global `/etc/u2f_mappings`;
- TTY `login` and SDDM with U2F enabled and `unixAuth = false`.

No real UUID, username, credential, key handle, public key, or hardware ID is
stored in this repository.

## Additional finding: global PAM scope

At the pinned Nixpkgs revision, the legacy per-service option `u2fAuth` is a
renamed alias for `security.pam.services.<name>.u2f.enable`. More importantly,
each service defaults its U2F setting from global
`security.pam.u2f.enable`.

The evaluated reference therefore enables U2F not only for `login` and SDDM,
but also for existing services such as KDE locker, Polkit, `su`, i3lock
variants, and `systemd-run0`, unless explicitly overridden. Unix password
remains enabled on those inherited services. `sudo` is explicitly U2F-disabled
and password-enabled.

NixKeyforge must report the effective service set rather than infer intent from
the two explicit service blocks.

## Lockout assessment

The mapping file exists as a regular file with mode `0600`, owner/group
`root:root`, and one link. An unprivileged assessment cannot read it, so it
cannot safely count credentials or prove that two physical authenticators
work. NixKeyforge must not elevate merely to obtain a reassuring status.

Because `login` and SDDM have no Unix password path and two independent working
credentials cannot be proved, the correct diagnosis is `lockout-risk`.
Existing configuration remains untouched. NixKeyforge must not automatically
toggle `unixAuth` in either direction.

## Difference between product policy and current host

The general product recommendation for a new migration is password plus FIDO2,
configured per service. The current host uses passwordless FIDO2 for two login
services and a global U2F switch that expands to other services.

The product must therefore:

1. discover the effective PAM service matrix;
2. treat existing passwordless settings as immutable input during planning;
3. request privileged mapping inspection only in a separately authorized,
   redacted operation;
4. record primary and backup proof independently;
5. preserve the current password-based `sudo` and disabled SSH server;
6. generate a separate Nix module and diff preview;
7. never rewrite or commit the reference flake.

## Controlled migration plan

### Stage 1: evidence only

- Preserve an open privileged session.
- Prepare tested rescue media, recovery material, and the current known-good
  NixOS generation.
- Run read-only doctor/status from NixKeyforge.
- With explicit privilege for metadata-only inspection, count mapping entries
  without printing them and record redacted hashes.
- Inventory LUKS2 metadata, UUID, major/minor, keyslots, and recovery presence
  without enrolling or deleting anything.

Stop if the target, LUKS2 format, recovery path, mapping integrity, or token
capabilities are uncertain.

### Stage 2: independent credential enrollment

- Remove all tokens and enroll primary alone for PAM.
- Atomically append only the target user's new credential.
- Enroll primary alone for the same LUKS2 volume.
- Remove primary and repeat with backup alone.
- Abort if backup matches primary or no distinct mapping/token association is
  created.
- Do not remove any existing mapping entry, LUKS keyslot, passphrase, or
  recovery key.

### Stage 3: additive PAM module preview

Generate a fragment in a separate output directory using exact services. The
safe target profile is:

```nix
security.pam = {
  u2f = {
    enable = false;
    settings.authfile = "/etc/u2f_mappings";
  };
  services.login = {
    unixAuth = true;
    u2f = {
      enable = true;
      control = "required";
    };
  };
  services.sddm = {
    unixAuth = true;
    u2f = {
      enable = true;
      control = "required";
    };
  };
  services.kde = {
    unixAuth = true;
    u2f = {
      enable = true;
      control = "required";
    };
  };
};
```

This is a proposed target, not an automatic edit. It removes accidental global
scope and preserves the password as one factor. Review the generated diff
against current configuration.

### Stage 4: NixOS build/test sequence

1. Import the reviewed generated module manually.
2. Run `nixos-rebuild build`.
3. Inspect the resulting PAM and initrd configuration.
4. After confirmation, run `nixos-rebuild test`.
5. Test PAM in a second TTY/session with primary and backup separately while
   the privileged session remains open.
6. Test SSH client behavior; do not enable the SSH server.
7. Only after another explicit confirmation choose `boot` or `switch`.
8. Keep the previous generation.

### Stage 5: separate boot proofs

Power down fully between tests. Boot once with only primary, once with only
backup, and then conduct a controlled recovery test. Record results without raw
metadata. Only then can status become `dual-token-ready`.

## Verified Nixpkgs options

The pinned source declares:

- `boot.initrd.systemd.enable` in
  `nixos/modules/system/boot/systemd/initrd.nix`;
- `boot.initrd.luks.devices.<name>.crypttabExtraOpts` in
  `nixos/modules/system/boot/luksroot.nix`;
- global and per-service PAM U2F options plus `unixAuth` in
  `nixos/modules/security/pam.nix`.

`crypttabExtraOpts` is explicitly only used with systemd stage 1. The pinned
module recommends `systemd-cryptenroll(1)` and `systemd-cryptsetup(8)` for
hardware keys. These facts were evaluated rather than assumed.
