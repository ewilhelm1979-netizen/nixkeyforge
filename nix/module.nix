{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.nixkeyforge;
  serviceConfig = lib.genAttrs cfg.pam.services (_: {
    unixAuth = true;
    u2f = {
      enable = true;
      control = "required";
    };
  });
in
{
  options.services.nixkeyforge = {
    enable = lib.mkEnableOption "NixKeyforge planning and verification tools";

    package = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "NixKeyforge package. The flake module supplies its own package by default.";
    };

    stateDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/nixkeyforge";
      description = "Mutable state directory. Plans stored here must never contain secrets.";
    };

    pam = {
      enable = lib.mkEnableOption "explicit password-and-FIDO2 PAM integration";

      services = lib.mkOption {
        type = lib.types.listOf (
          lib.types.enum [
            "login"
            "sddm"
            "kde"
            "i3lock"
            "i3lock-color"
          ]
        );
        default = [ ];
        example = [
          "login"
          "sddm"
          "kde"
        ];
        description = ''
          Exact PAM services to configure. Services not listed remain unchanged.
          Password authentication remains enabled and FIDO2 is required as an
          additional factor.
        '';
      };

      authFile = lib.mkOption {
        type = lib.types.str;
        default = "/etc/u2f_mappings";
        description = ''
          Absolute mutable PAM-U2F mapping path. This is deliberately a string,
          not a Nix path, so credential material is never copied to the Nix store.
        '';
      };

      origin = lib.mkOption {
        type = lib.types.str;
        default = "pam://nixos";
        description = "PAM-U2F relying-party origin used during enrollment and authentication.";
      };

      requirePinVerification = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Require a FIDO2 client PIN after token capability verification.";
      };

      requireUserVerification = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Require authenticator user verification after capability verification.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.package != null;
        message = "services.nixkeyforge.package must be set when NixKeyforge is enabled";
      }
      {
        assertion =
          (
            cfg.stateDirectory == "/var/lib/nixkeyforge"
            || lib.hasPrefix "/var/lib/nixkeyforge/" cfg.stateDirectory
          )
          && builtins.match "^/[A-Za-z0-9._/-]+$" cfg.stateDirectory != null
          && !(lib.hasInfix "/../" cfg.stateDirectory)
          && !(lib.hasSuffix "/.." cfg.stateDirectory)
          && !(lib.hasInfix "/./" cfg.stateDirectory);
        message = "services.nixkeyforge.stateDirectory must stay under /var/lib/nixkeyforge";
      }
      {
        assertion = cfg.pam.authFile == "/etc/u2f_mappings";
        message = "version 0.1 supports only the reviewed global /etc/u2f_mappings path";
      }
      {
        assertion = !(lib.hasPrefix "/nix/store/" cfg.pam.authFile);
        message = "PAM-U2F credentials must not be stored in the Nix store";
      }
      {
        assertion = !cfg.pam.enable || cfg.pam.services != [ ];
        message = "select at least one explicit PAM service when NixKeyforge PAM is enabled";
      }
      {
        assertion = builtins.length cfg.pam.services == builtins.length (lib.unique cfg.pam.services);
        message = "services.nixkeyforge.pam.services must not contain duplicates";
      }
      {
        assertion = builtins.match "^pam://[A-Za-z0-9._-]+$" cfg.pam.origin != null;
        message = "services.nixkeyforge.pam.origin has an unsafe format";
      }
    ];

    environment.systemPackages = [
      cfg.package
      pkgs.age
      pkgs.cryptsetup
      pkgs.libfido2
      pkgs.openssh
      pkgs.pam_u2f
      pkgs.systemd
      pkgs.util-linux
    ];

    systemd.tmpfiles.rules = [
      "d ${cfg.stateDirectory} 0700 root root - -"
      "d ${cfg.stateDirectory}/plans 0700 root root - -"
    ];

    security.pam = lib.mkIf cfg.pam.enable {
      u2f = {
        enable = false;
        control = "required";
        settings = {
          authfile = cfg.pam.authFile;
          cue = true;
          debug = false;
          interactive = false;
          userpresence = 1;
          origin = cfg.pam.origin;
          appid = cfg.pam.origin;
        }
        // lib.optionalAttrs cfg.pam.requirePinVerification { pinverification = 1; }
        // lib.optionalAttrs cfg.pam.requireUserVerification { userverification = 1; };
      };

      services = serviceConfig;
    };
  };
}
