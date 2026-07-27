# NixKeyforge

**NixKeyforge ist ein sicherer Zugangs- und Recovery-Manager für NixOS.**

NixKeyforge unterstützt die lesende Erkennung, Planung, Generierung und
Verifikation einer wiederherstellbaren PAM-, FIDO2-, LUKS2- und
OpenSSH-Konfiguration. Das Standardmodell verwendet zwei unabhängig
eingerichtete Authenticatoren: einen Primary-Token für den Alltag und einen
räumlich getrennt verwahrten Backup-Token. Jeweils einer genügt; dies ist
Redundanz und kein 2-von-2-Verfahren.

> [!CAUTION]
> Ein PAM-Fehler kann jede lokale Anmeldung blockieren. Ein LUKS2- oder
> Initrd-Fehler kann den Systemstart verhindern. Während PAM-Tests muss eine
> privilegierte Sitzung geöffnet bleiben. Außerdem müssen eine funktionierende
> NixOS-Generation und ein geprüftes Rettungsmedium verfügbar sein.

> [!IMPORTANT]
> Ein zweiter FIDO2-Token ersetzt keinen unabhängigen LUKS2-Recovery-Key und
> keine starke Passphrase. Backups können interne private Schlüssel eines
> Authenticators weder sichern noch klonen. Der Backup-Token muss real für
> Login und Boot getestet und danach ausgeschaltet sowie räumlich getrennt
> aufbewahrt werden.

## Projektstatus

Version 0.1 ist eine sicherheitsorientierte Grundlage. Discovery, Pläne,
typisierte externe Befehle, redigierte Statusausgabe, Nix-Modulgrenzen,
Archivvalidierung und Testdoubles sind implementiert, ohne den Host zu ändern.
Reale PAM-, SSH-, LUKS2-, Initrd- oder Bootänderungen sind in diesem
Entwicklungsstand absichtlich deaktiviert. Hardwaretests bleiben manuell.

Die NKFB-Policy weist Pakete ohne age-kompatible authentisierte Verschlüsselung
zurück, auch beim geheimnisfreien portablen Profil. Der produktive
Backup-Writer bleibt in diesem Foundation-Release deaktiviert. NixKeyforge hat
keinen Daemon, Webserver, keine GUI, keine Telemetrie und keinen Setuid-Helfer.
Es ruft niemals selbst `sudo` auf, startet nicht neu, löscht in Version 0.1
keine LUKS-Keyslots und stellt keinen LUKS-Header automatisch wieder her.

## Fachbegriffe

- Der **FIDO2-Authenticator** oder **Hardware Security Key** ist das Gerät.
- Ein **PAM-U2F/FIDO2-Credential** wird eigenständig für PAM registriert.
- Ein **LUKS2-FIDO2-Enrollment** verwendet `hmac-secret` und
  LUKS2-Tokenmetadaten.
- Ein **OpenSSH-Security-Key-Credential** ist ein `ed25519-sk`-Benutzerschlüssel.
- Ein **WebAuthn-Passkey** gehört zu einem getrennten Webauthentifizierungsfall.

Die Oberfläche darf „Passkey“ als verständlichen Begriff verwenden. Code und
Pläne trennen diese Domänen technisch. Authenticator-interne private Schlüssel
sind nicht exportierbar und niemals Bestandteil eines Backups.

## Empfohlenes Recovery-Modell

| Rolle | Verwendung | Aufbewahrung |
| --- | --- | --- |
| Primary Authenticator | täglicher Login und LUKS2-Boot-Unlock | beim Benutzer |
| Backup Authenticator | unabhängiger Ersatz für Login und LUKS2 | getestet, ausgeschaltet und räumlich getrennt |
| Recovery-Key/Passphrase | unabhängiger LUKS2-Notfallzugang | getrennt von Rechner und beiden Token |
| Rettungsmedium | Reparatur von Boot oder PAM | geprüft und sicher verwahrt |

`dual-token-ready` ist erst nach getrennten PAM- und LUKS2-Tests beider Token
sowie einem unabhängigen Recovery-Test zulässig. Metadaten allein sind kein
Funktionsnachweis. Weitere Zustände sind `unconfigured`, `single-token`,
`dual-token-incomplete`, `recovery-unverified`, `lockout-risk`,
`configuration-drift` und `unsupported`.

## CLI und Qualitätsprüfung

Dry Run ist Standard. Ausgabe gibt es mit `--format human` oder redigiertem
`--format json`. Die vollständige Befehlsübersicht steht in der
[englischen README](README.md).

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

Exitcode `0` bedeutet Erfolg, `10` Warnung, `20` Blocker oder Lockout-Risiko,
`30` Konfigurationsdrift und `40` fehlgeschlagene Verifikation. Es gibt kein
globales `--yes`. Ein späteres Hochrisiko-Apply benötigt Plan-Datei,
Fingerprint, erneute Voraussetzungenprüfung und interaktive Bestätigung.
Backup-Erstellung, -Inspektion, -Verifikation und Restore-Planung liefern
derzeit den Blocker `unsupported`; das NKFB-In-Memory-Modell wird nicht als
produktiver Age-/Tar-Verifier dargestellt.

## NixOS-Integration

Das Flake exportiert Paket, App, Development Shell, NixOS-Modul,
Evaluationsprüfung und einen hardwarefreien NixOS-VM-Test. PAM-Services werden
einzeln ausgewählt. Das unterstützte Profil behält das Unix-Passwort und
verlangt FIDO2 als zusätzlichen Faktor; `nouserok` und `alwaysok` sind
verboten. Credential-Material bleibt außerhalb des Nix Stores.

NixKeyforge schreibt generierte Fragmente nur in ein ausdrücklich angegebenes
Ausgabeverzeichnis. Es schreibt keine bestehende fremde Nix-Datei syntaktisch
um und verändert insbesondere kein Referenz-Repository.

## Dokumentation

- [Architektur](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [Zwei-Authenticator-Modell](docs/dual-authenticator-model.md)
- [Migration der NixOS-Referenz](docs/nixos-reference-migration.md)
- [Backupformat](docs/backup-format.md)
- [Recovery-Runbook](docs/recovery-runbook.md)
- [Manuelle Hardwaretests](docs/manual-hardware-tests.md)
- [Security Policy](SECURITY.md)

## Lizenz

NixKeyforge steht unter GPL-3.0-only.
