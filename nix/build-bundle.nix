{ stork-app-module, system ? builtins.currentSystem }:

let stork-config = { config, pkgs, lib, ... }: {
      imports = [ ./stork.nix (builtins.toPath stork-app-module) ];

      config = with lib; {
        boot.isContainer = true;
        networking.firewall.enable = false;
        services.openssh.startWhenNeeded = false;
        environment.noXlibs = mkDefault true;

        environment.systemPackages = [ config.stork.app ];
      };

      options = with lib; {
        stork.app = lib.mkOption {
          type = lib.types.package;
          description = ''
          A nix derivation providing the package that is used to launch the stork application
          '';
        };
      };
    };

    eval = import <nixpkgs/nixos/lib/eval-config.nix> {
      inherit system;
      modules = [ ./modules/top-level.nix (builtins.toPath stork-app-module) ];
    };

in eval.config.stork.toplevel

