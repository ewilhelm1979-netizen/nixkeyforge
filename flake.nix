{
  description = "NixKeyforge - secure access and recovery manager for NixOS";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/597283ad8aa0b331c788e97c4c262d58877074ef";

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

      package = pkgs.rustPlatform.buildRustPackage {
        pname = "nixkeyforge";
        version = "0.1.0";
        src = ./.;

        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [
          "-p"
          "nixkeyforge-cli"
        ];

        meta = {
          description = "Secure access and recovery manager for NixOS";
          homepage = "https://github.com/ewilhelm1979-netizen/nixkeyforge";
          license = pkgs.lib.licenses.gpl3Only;
          mainProgram = "nixkeyforge";
          platforms = pkgs.lib.platforms.linux;
        };
      };
    in
    {
      packages.${system} = {
        default = package;
        nixkeyforge = package;
      };

      apps.${system}.default = {
        type = "app";
        program = "${package}/bin/nixkeyforge";
        meta.description = "Secure access and recovery manager for NixOS";
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          age
          cargo
          cargo-audit
          cargo-cyclonedx
          cargo-deny
          clippy
          cryptsetup
          libfido2
          nixfmt
          openssh
          pam_u2f
          rustc
          rustfmt
          systemd
        ];

        NIXKEYFORGE_LIVE_APPLY = "disabled";
      };

      formatter.${system} = pkgs.nixfmt;

      nixosModules.default =
        {
          lib,
          pkgs,
          ...
        }:
        {
          imports = [ ./nix/module.nix ];
          services.nixkeyforge.package =
            lib.mkDefault
              self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };

      checks.${system} = {
        package = package;
        module-evaluation =
          let
            evaluated = nixpkgs.lib.nixosSystem {
              inherit system;
              modules = [
                self.nixosModules.default
                ./nix/tests/evaluation.nix
              ];
            };
            facts = builtins.toJSON {
              loginUnixAuth = evaluated.config.security.pam.services.login.unixAuth;
              loginU2f = evaluated.config.security.pam.services.login.u2f.enable;
              sddmUnixAuth = evaluated.config.security.pam.services.sddm.unixAuth;
              sddmU2f = evaluated.config.security.pam.services.sddm.u2f.enable;
              globalU2f = evaluated.config.security.pam.u2f.enable;
            };
          in
          assert evaluated.config.security.pam.services.login.unixAuth;
          assert evaluated.config.security.pam.services.login.u2f.enable;
          assert evaluated.config.security.pam.services.sddm.unixAuth;
          assert evaluated.config.security.pam.services.sddm.u2f.enable;
          assert !evaluated.config.security.pam.u2f.enable;
          pkgs.runCommand "nixkeyforge-module-evaluation" { } ''
            printf '%s\n' ${nixpkgs.lib.escapeShellArg facts} > "$out"
          '';
        nixos-vm = import ./nix/tests/nixos-vm.nix {
          inherit pkgs;
          nixkeyforgeModule = self.nixosModules.default;
        };
      };
    };
}
