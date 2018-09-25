{ config, pkgs, lib, ... }: {
  imports = [ ] ; # ./activation.nix ];

  options = with lib; {
    stork.app-domain = mkOption {
      type = types.string;
      description = "App domain uri";
    };
    stork.app-name = mkOption {
      type = types.string;
      description = "A short alphanumeric name for this application";
    };

    stork.app = mkOption {
      type = types.package;
      description = "Nix derivation for main stork application";
    };

    stork.startHook = mkOption {
      type = types.string;
      description = "Script to run when stork wants to start this application";
    };

    stork.healthCheckHook = mkOption {
      type = types.string;
      description = "Script to run when stork wants to run a health check on this application";
    };

    stork.systemPackages = mkOption {
      type = types.listOf types.package;
      default = [];
      example = literalExample "[ pkgs.bind ]";
      description = ''
        The set of packages available under the root directory.

        These are automatically updated each time the application is built
      '';
    };

    stork.pathsToLink = mkOption {
      type = types.listOf types.str;
      default = [];
      example = [ "/" ];
      description = "The list of paths to link under the root directory";
    };

    stork.extraOutputsToInstall = mkOption {
      type = types.listOf types.str;
      default = [];
      example = [ "info" "dev" ];
      description = "List of additional derivation outputs to be linked to root directory";
    };

    stork.toplevel = mkOption {
      type = types.package;
      internal = true;
      description = "The top-level package";
    };

    stork.manifest = mkOption {
      type = types.package;
      internal = true;
      description = "Manifest build";
    };

    stork.meta = mkOption {
      type = types.submodule {
        options = {
          name = mkOption {
            type = types.str;
            default = config.stork.app-name;
            description = "Human-readable nme of package";
          };

          authors = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Names of package authors";
          };
        };
      };
      description = "Meta description about package";
    };
  };

  config = {
    stork.systemPackages = with pkgs; [
      utillinux
      coreutils
      glibc
      bash
      iproute

      config.stork.app
    ];

    stork.pathsToLink = [
      "/bin"
      "/etc/xdg"
      "/etc/gtk-2.0"
      "/etc/gtk-3.0"
      "/lib"
      "/sbin"
      "/share/applications"
      "/share/desktop-directories"
      "/share/emacs"
      "/share/icons"
      "/share/menus"
      "/share/mime"
      "/share/nano"
      "/share/org"
      "/share/themes"
      "/share/vim-plugins"
      "/share/vulkan"
      "/share/kservices5"
      "/share/kservicestype5"
      "/share/kxmlgui5"
    ];

    stork.manifest = pkgs.writeText "${config.stork.app-name}-manifest"
      (builtins.toJSON {
        name = config.stork.meta.name;
#        authors = config.stork.meta.authors;
        canonical = "kite+app://${config.stork.app-domain}/${config.stork.app-name}";
        nix-closure = config.stork.toplevel;
      });

    stork.toplevel =
      let startScript = pkgs.writeScript "start-script" ''
            #!/bin/sh
            ${config.stork.startHook}
          '';
          healthCheckScript = pkgs.writeScript "health-check" ''
            #!/bin/sh
            ${config.stork.healthCheckHook}
          '';
      in pkgs.buildEnv {
           name = "stork-environment-${config.stork.app-name}";
           ignoreCollisions = true;
           paths = config.stork.systemPackages;
           inherit (config.stork) pathsToLink extraOutputsToInstall;

           postBuild = ''
             mkdir -p $out/dev
             mkdir -p $out/nix
             mkdir -p $out/proc
             mkdir -p $out/dev
             mkdir -p $out/sys
             mkdir -p $out/stork
             mkdir -p $out/app
             ln -s ${healthCheckScript} $out/app/hc
             ln -s ${startScript} $out/app/start
           '';
         };
  };
}
