{ kite-app-module, system ? builtins.currentSystem, pkgs ? (import <nixpkgs> {})
, pure-build ? false }:

let kite-config = { config, pkgs, lib, ... }: {
      imports = [ ./kite.nix (builtins.toPath kite-app-module) ];

      config = with lib; {
        boot.isContainer = true;
        networking.firewall.enable = false;
        services.openssh.startWhenNeeded = false;
        environment.noXlibs = mkDefault true;

        environment.systemPackages = [ config.kite.app ];
      };

      options = with lib; {
        kite.app = lib.mkOption {
          type = lib.types.package;
          description = ''
          A nix derivation providing the package that is used to launch the kite application
          '';
        };
      };
    };

    eval = import <nixpkgs/nixos/lib/eval-config.nix> {
      inherit system pkgs;
      modules = [ ./modules/top-level.nix (builtins.toPath kite-app-module) ];
      extraArgs = { kite-lib = (import ./lib/kite.nix) pkgs; inherit pure-build; };
    };

    root = eval.config.kite.toplevel;
in eval.config.kite.manifest

