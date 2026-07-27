# NixKeyforge backup format

## Security goals

The NixKeyforge Backup Format (NKFB) stores selected configuration and recovery
artifacts without implying that authenticator-internal credentials can be
backed up. Version 1 has these properties:

> **Implementation status:** this is the normative format and security contract.
> The foundation release implements the canonical manifest and an in-memory
> policy validator, but not the production Age/tar reader, writer, or exclusive
> staging boundary. CLI backup and restore operations therefore fail closed as
> `unsupported`; the properties below are enablement requirements, not current
> ciphertext-processing claims.

- every package is encrypted and authenticated with an established `age`
  implementation; NixKeyforge does not implement cryptography;
- recipient encryption is preferred; passphrase mode is available only through
  protected interactive entry;
- no plaintext secret, passphrase, PIN, or recovery key appears in a filename,
  argument, environment variable, manifest, log, plan, JSON output, or temporary
  file;
- archive names cannot select arbitrary filesystem paths;
- restore validates into unprivileged staging and produces a plan; it does not
  write live PAM/SSH/NixOS paths or a block device; and
- checksums diagnose component corruption and bind the manifest to entries, but
  they are not a replacement for age's authenticated encryption.

An authenticator's private FIDO2 credential is non-exportable. An NKFB package
cannot clone Primary, recreate Backup, or restore a lost PAM, LUKS2, or
OpenSSH-security-key credential. A replacement token always requires fresh
enrollment and manual verification.

## Profiles

### `portable-configuration`

This is the default profile. Its allowlist contains:

- NixKeyforge configuration;
- generated Nix modules;
- redacted system information;
- redacted PAM credential metadata and Primary/Backup role labels;
- public SSH keys;
- verification states;
- the manifest and per-component diagnostic hashes.

It excludes raw PAM mapping records, every private SSH or host key, LUKS2
headers, plaintext recovery material, passwords, PINs, passphrases, raw debug
dumps, and authenticator-internal keys.

### `sensitive-machine-recovery`

This profile is optional and requires explicit per-component selection. It may
contain:

- a LUKS2 header;
- explicitly selected recovery material;
- explicitly selected SSH private or host keys; and
- the current PAM mapping.

All such content remains inside the age-encrypted payload. Selection is never
implicit, and a plan displays each selected component by category without
displaying its value. Private client and host keys are excluded by default.

A LUKS2 header is sensitive: it exposes volume metadata and enables offline
guessing against passphrase-protected keyslots. Restoring a header to a block
device is outside NKFB restore and outside NixKeyforge 0.1.

## On-disk encoding

The conventional suffix is `.nkfb.age`. A version 1 file is:

```text
age encrypted file
└── authenticated plaintext: uncompressed POSIX-compatible tar stream
    ├── manifest.json
    └── components/<component-id>/<logical-name>
```

There is no unencrypted sidecar manifest. File names should not contain a host
name, user name, UUID, or token identifier. The age header and ciphertext length
still expose format-level metadata such as recipient-stanza types and
approximate payload size. Operators must not treat the encrypted file as
anonymous.

The tar stream is intentionally uncompressed in version 1. This makes decoded
size limits enforceable without a separate decompression layer. It contains
exactly one `manifest.json` regular file and zero or more allowlisted component
regular files. Directory records are unnecessary and rejected. Extended/PAX
headers, GNU extensions, sparse files, links, devices, sockets, FIFOs, and other
special records are rejected.

The implementation must process the complete age stream into a newly created,
private staging object and reach authenticated end-of-file before parsing,
displaying, hashing, or acting on any plaintext. Streaming plaintext that has
not reached authenticated EOF must never affect restore state.

Use a maintained implementation of the [age file format
v1](https://age-encryption.org/v1). Do not compose a new encryption format or
wrap an unauthenticated cipher. Recipient mode uses explicit age recipients.
Passphrase mode obtains the passphrase twice from a protected terminal, with
echo disabled, and supplies it only through the library's secret input
interface. Passphrases are never accepted on the command line or through the
environment.

## Manifest schema version 1

`manifest.json` is UTF-8 JSON with no byte-order mark. The producer emits a
canonical field order, but readers must parse JSON structurally rather than
depending on presentation order. Readers reject duplicate JSON object keys,
duplicate archive names, duplicate component IDs, unknown enum values, invalid
UTF-8, trailing non-whitespace data, non-integer numeric values, and a manifest
larger than the configured limit.

Illustrative structure:

```json
{
  "format": "nixkeyforge-backup",
  "schema_version": 1,
  "tool_version": "0.1.0",
  "created_at": "2026-07-27T12:00:00Z",
  "profile": "portable-configuration",
  "host": {
    "redacted_id": "sha256:example-redacted-value"
  },
  "luks_volumes": [
    {
      "uuid": "00000000-0000-0000-0000-000000000000",
      "role": "root"
    }
  ],
  "authenticators": [
    {
      "role": "primary",
      "redacted_id": "sha256:example-redacted-value",
      "verification": "manual-test-pending"
    },
    {
      "role": "backup",
      "redacted_id": "sha256:example-redacted-value",
      "verification": "manual-test-pending"
    }
  ],
  "entries": [
    {
      "component": "generated-nix",
      "path": "components/generated-nix/nixkeyforge.nix",
      "media_type": "text/x-nix",
      "length": 1234,
      "sha256": "example-diagnostic-digest",
      "mode": "0600",
      "sensitivity": "configuration"
    }
  ]
}
```

The example values are deliberately synthetic. Real UUIDs, credential handles,
public keys, hardware serials, host names, and user names must not appear in
examples or test fixtures.

### Required top-level fields

| Field | Rule |
|---|---|
| `format` | Exactly `nixkeyforge-backup`. |
| `schema_version` | Integer `1`; any other value is incompatible and rejected before extraction. |
| `tool_version` | Informational semantic version; never used alone to authorize restore. |
| `created_at` | UTC RFC 3339 timestamp; future or unexpectedly old values cause a warning or policy blocker. |
| `profile` | Exactly one known profile. |
| `host.redacted_id` | Domain-separated digest suitable only for equality checking; it is not authentication. |
| `luks_volumes` | Possibly empty list of exact LUKS UUID plus declared role; UUID is required for a LUKS header. |
| `authenticators` | Redacted roles and verification status only; never private credential material. |
| `entries` | Complete, unique, lexicographically sorted list of every component file. |

Each entry declares an allowlisted component, normalized archive path, media
type, exact byte length, lowercase SHA-256 diagnostic digest, intended mode,
and sensitivity class. Archive members missing from `entries`, manifest entries
missing from the archive, or mismatched metadata reject the entire package.
Unknown fields are rejected in schema version 1; a future producer must advance
the schema rather than silently changing security semantics.

Redacted identifiers are pseudonymous, not anonymous. Stable identifiers can be
correlated across packages, and low-entropy input may be guessed. They must not
be used as authorization evidence and remain protected by package encryption.

## Creation

Creation is a plan-confirm-apply-verify operation even though it does not mutate
live authentication configuration.

1. Discover candidate components without following links.
2. Resolve the selected profile and per-component allowlist.
3. Reject non-regular files, unsafe ownership/modes, hardlinks, oversized input,
   and files that change during reading.
4. Produce a secret-free plan naming component categories, destination,
   recipient fingerprints in redacted form, limits, and omissions.
5. Confirm recipients and any sensitive component interactively.
6. Create the destination directory as `0700` if it is a dedicated new backup
   directory; otherwise require an equivalently protected existing directory.
7. Create an exclusive `0600` temporary output in that directory with a
   restrictive umask. Never follow a destination symlink.
8. Read each source from a validated open file descriptor, hash the exact bytes,
   construct the manifest, and stream the tar plaintext into the age writer.
9. Finalize the age writer, flush and `fsync` the file, verify mode and owner,
   atomically rename without clobbering an unexpected destination, then `fsync`
   the parent directory.
10. Reopen and fully verify the completed package using an appropriate identity
    before reporting success.

Source changes, short reads, destination conflicts, failed `fsync`, encryption
finalization failure, or verification failure leave no successful result.
Temporary plaintext, if a particular age library requires it, must live only in
a private `0700` staging directory on an explicitly accepted filesystem, use
`0600`, and be removed on both success and failure. Prefer a pipeline that never
writes plaintext archive bytes to persistent storage. Deletion is not a secure
erase guarantee on SSD, copy-on-write, journaled, or snapshotting filesystems.

## Inspection and verification

`backup inspect` and `backup verify` are read-only with respect to live system
configuration:

1. open the package without following links and enforce package-size policy;
2. decrypt to private, unprivileged staging and authenticate through EOF;
3. parse the archive with strict count, per-entry, total-size, and path-length
   limits;
4. find exactly one manifest and validate its schema before accepting component
   records;
5. compare the archive and manifest bijectively;
6. calculate each hash and length from the authenticated plaintext;
7. validate profile/component/media-type/mode combinations;
8. compare redacted host identity and exact LUKS UUIDs with freshly discovered
   local state when requested; and
9. output only redacted metadata and a disposition: valid for inspection,
   foreign, incompatible, stale, tampered, or invalid.

Successful age decryption proves that the bytes were created by someone able to
encrypt to the recipient (or knowing the backup passphrase). It does **not**
prove the creator's identity, that the package is current, that its host or disk
matches, that the contained configuration is safe, or that restoration should
proceed.

## Restore allowlist

Version 1 has no generic "extract here" operation and never extracts as root.
Validation writes regular files into a new unprivileged `0700` staging
directory, using generated opaque staging names rather than archive paths.
Archive names are labels used for manifest matching only.

| Component | Permitted automatic destination | Live destination |
|---|---|---|
| NixKeyforge configuration | Private staging | Manual review and explicit copy only |
| Generated Nix module | Private staging or an explicitly empty generation output directory | Never auto-import or activate |
| Redacted system/PAM metadata, manifest, status | Private staging | None |
| Public SSH key | Private staging | Never auto-update `authorized_keys` |
| PAM mapping | Private staging, `0600` | Never auto-write `/etc/u2f_mappings` |
| SSH private or host key | Private staging, `0600`, only after separate confirmation | Never auto-write user or `/etc/ssh` key paths |
| Recovery material | Private staging, `0600`, only after separate confirmation and custody warning | Never auto-enroll or feed to a command |
| LUKS2 header | Private staging, `0600` | Never write a block device or call header restore |

Before any later manual overwrite, the operator must verify target identity,
back up the current state, compare a rendered diff or appropriate metadata,
preserve owner and mode, retain a rollback route, and follow the relevant
recovery runbook. A future enabled restore command will produce this plan; it
will not perform the live overwrite. The current CLI rejects restore operations
as unsupported.

## Archive rejection rules

The entire package is rejected, with no partial restore, for any of the
following:

- `../../etc/shadow`, any other `..` component, `.` or empty component;
- `/etc/shadow`, a drive-prefixed path, backslash-based alternate path, NUL,
  control character, or path exceeding configured length;
- symlink, hardlink, device node, FIFO, socket, sparse file, or unknown archive
  record;
- a symlink-like or hardlink-like target encoded through PAX/GNU metadata;
- extended headers, path override fields, or conflicting size/type metadata;
- duplicate `manifest.json`, duplicate member path, normalized-name collision,
  file/directory prefix collision, or duplicate manifest key/component entry;
- an archive member not in the manifest or a manifest entry not in the archive;
- manipulated checksum, length, media type, sensitivity, or mode;
- a LUKS header without exactly one declared matching UUID and expected role;
- wrong local LUKS UUID, host mismatch, or target identity drift;
- incompatible schema version, format identifier, profile, enum, or unknown
  schema-1 field;
- member count, individual size, total decoded size, manifest size, or path
  depth beyond fixed policy limits;
- truncated, trailing, unauthenticated, or otherwise invalid age data; or
- any attempt to overwrite an existing staging object.

A valid but foreign package may be inspected in redacted form. It cannot produce
a local restore plan unless the operator explicitly chooses a foreign-recovery
workflow and independently supplies and verifies the intended target facts.
There is no override for unsafe archive structure or failed authentication.

## Required malicious-package tests

Tests use synthetic data and disposable temporary directories. At minimum they
cover:

| Case | Expected result |
|---|---|
| `../../etc/shadow` | Reject before creating any member. |
| `/etc/shadow` | Reject as absolute. |
| Symlink to `/etc` | Reject link record. |
| Hardlink to another member or external name | Reject link record. |
| Character/block device node | Reject special record. |
| Two manifests | Reject duplicate reserved name. |
| Duplicate or normalized-colliding paths | Reject ambiguity. |
| Manipulated SHA-256 | Reject component verification; do not treat the checksum as the AEAD error. |
| Modified age ciphertext or tag, or truncation | Reject authentication; expose no partial output. |
| Wrong LUKS UUID | Mark target mismatch and block restore planning. |
| Incompatible schema version | Reject before component materialization. |
| Member absent from manifest or vice versa | Reject non-bijective package. |
| Oversized count, path, entry, manifest, or total | Reject at the applicable limit. |
| PAX/GNU path or type override | Reject unsupported archive feature. |
| Named pipe with a blocking source | Reject by metadata without opening it for content. |

Tests also assert that logs, human output, JSON, error chains, and panic messages
do not contain canary secrets, raw credential handles, private key bytes, or
decrypted component content.

## Operational limitations

- NKFB provides file confidentiality and integrity, not trusted host attestation
  or trusted package provenance.
- Losing every age identity and passphrase makes the package unrecoverable.
- Passphrase strength is an operator responsibility; recipient mode is
  preferred.
- File modes in the manifest are policy assertions, not permission-preserving
  archive instructions.
- A backup is not verified recovery until it has passed format verification and
  the relevant manual recovery exercise.
- LUKS2 header restoration and live PAM/SSH replacement remain deliberate,
  operator-controlled emergency procedures outside NixKeyforge 0.1.
