{ config, pkgs, lib, ... }: {
  imports = [ ./supervisord.nix ] ; # ./activation.nix ];

  options = with lib; {
    kite.app-domain = mkOption {
      type = types.string;
      description = "App domain uri";
    };
    kite.app-name = mkOption {
      type = types.string;
      description = "A short alphanumeric name for this application";
    };

    kite.startHook = mkOption {
      type = types.string;
      description = "Script to run when kite wants to start this application";
    };

    kite.healthCheckHook = mkOption {
      type = types.string;
      description = "Script to run when kite wants to run a health check on this application";
    };

    kite.runAsAdmin = mkOption {
      type = types.bool;
      default = false;
      description = ''
        If true, this process is run with administrator privileges.

        Currently, this means access to the local API socket.

        Packages which request this permission may not receive it. Check to make sure.

        Packages which request this permission will likely need to be signed.
      '';
    };

    kite.singleton = mkOption {
      type = types.bool;
      default = false;
      description = ''
        If true, this container is only instantiated once for the entire system.

        It can determine the source of a packet by asking the bridge controller.
      '';
    };

    kite.systemPackages = mkOption {
      type = types.listOf types.package;
      default = [];
      example = literalExample "[ pkgs.bind ]";
      description = ''
        The set of packages available under the root directory.

        These are automatically updated each time the application is built
      '';
    };

    kite.pathsToLink = mkOption {
      type = types.listOf types.str;
      default = [];
      example = [ "/" ];
      description = "The list of paths to link under the root directory";
    };

    kite.extraOutputsToInstall = mkOption {
      type = types.listOf types.str;
      default = [];
      example = [ "info" "dev" ];
      description = "List of additional derivation outputs to be linked to root directory";
    };

    kite.toplevel = mkOption {
      type = types.package;
      internal = true;
      description = "The top-level package";
    };

    kite.manifest = mkOption {
      type = types.package;
      internal = true;
      description = "Manifest build";
    };

    kite.meta = mkOption {
      type = types.submodule {
        options = {
          name = mkOption {
            type = types.str;
            default = config.kite.app-name;
            description = "Human-readable names of package";
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
    kite.systemPackages = with pkgs; [
      utillinux
      coreutils
      glibc
      bash
      iproute
    ];

    kite.pathsToLink = [
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

    kite.manifest = pkgs.writeText "${config.kite.app-name}-manifest"
      (builtins.toJSON {
        name = config.kite.meta.name;
#        authors = config.kite.meta.authors;
        canonical = "kite+app://${config.kite.app-domain}/${config.kite.app-name}";
        nix-closure = config.kite.toplevel;
        runAsAdmin = config.kite.runAsAdmin;
        singleton = config.kite.singleton;
      });

    kite.toplevel =
      let startScript = pkgs.writeScript "start-script" ''
            #!/bin/sh
            ${config.kite.startHook}
          '';
          healthCheckScript = pkgs.writeScript "health-check" ''
            #!/bin/sh
            ${config.kite.healthCheckHook}
          '';
      in pkgs.buildEnv {
           name = "kite-environment-${config.kite.app-name}";
           ignoreCollisions = true;
           paths = config.kite.systemPackages;
           inherit (config.kite) pathsToLink extraOutputsToInstall;

           postBuild = ''
             mkdir -p $out/dev
             mkdir -p $out/nix
             mkdir -p $out/proc
             mkdir -p $out/dev
             mkdir -p $out/sys
             mkdir -p $out/kite
             mkdir -p $out/app
             mkdir -p $out/run
             mkdir -p $out/var/log
             ln -s ${healthCheckScript} $out/app/hc
             ln -s ${startScript} $out/app/start
           '';
         };
  };
}
