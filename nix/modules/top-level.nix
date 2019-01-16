{ config, pkgs, lib, ... }: {
  imports = [ ./supervisord.nix ./permissions.nix ] ; # ./activation.nix ];

  options = with lib; {
    kite.identifier = mkOption {
      type = types.string;
      description = "App domain URI";
    };

    kite.version.major = mkOption {
      type = types.ints.unsigned;
      description = "Major version number";
      default = 0;
    };

    kite.version.minor = mkOption {
      type = types.ints.unsigned;
      description = "Minor version number";
      default = 0;
    };

    kite.version.revision = mkOption {
      type = types.ints.unsigned;
      description = "Revision version number";
    };

    kite.environment = mkOption {
      type = types.attrsOf types.string;
      description = "Environment variables shared between all running processes in this container";
      default = {};
    };

    kite.binaryCaches = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          url = mkOption {
            type = types.str;
            description = "Url of binary cache";
          };

          signatures = mkOption {
            type = types.str;
            description = "Signatures for this cache";
          };

          type = mkOption {
            type = types.enum [ "system" "app" ];
            description = "The type of this cache (system or app)";
          };

          priority = mkOption {
            type = types.int;
            description = "Priority of this cache";
          };
        };
      });
      description = "List of binary caches";
    };

    kite.startHook = mkOption {
      type = types.string;
      description = "Script to run when kite wants to start this application";
    };

    kite.healthCheckHook = mkOption {
      type = types.string;
      description = "Script to run when kite wants to run a health check on this application";
    };

    kite.permsHook = mkOption {
      type = types.nullOr types.string;
      description = "Script to run to get information on app permissions";
      default = null;
    };

    kite.bindMounts = mkOption {
      type = types.listOf types.string;
      default = [];
      description = ''
        Directories to identity mount (only available for administrative apps)
      '';
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

    kite.meta = mkOption {
      type = types.submodule {
        options = {
          slug = mkOption {
            type = types.str;
            description = "Slug of package";
          };

          name = mkOption {
            type = types.str;
            description = "Human-readable names of package";
          };

          authors = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Names of package authors";
          };

          app-url = mkOption {
            type = types.str;
            description = "Default homepage of app on the internet";
          };

          icon = mkOption {
            type = types.str;
            description = "Application icon";
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
      getconf
      getent
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

    kite.binaryCaches = [
      { url = "https://hydra.flywithkite.com/cache";
        signatures = [ "cache.flywithkite.com-1:7JJMfk9Vl5tetCyL8TnGSmo6IMvJypOlLv4Y7huDvDQ=" ];
        type = "system";
        priority = 1000000; }
    ];

    kite.version.revision = builtins.currentTime;

    kite.toplevel =
      let startScript = pkgs.writeScript "${config.kite.meta.slug}-start-script" ''
            #!/bin/sh
            source /etc/profile
            ${config.kite.startHook}
          '';
          healthCheckScript = pkgs.writeScript "${config.kite.meta.slug}-health-check" ''
            #!/bin/sh
            source /etc/profile
            ${config.kite.healthCheckHook}
          '';
          permsScript = pkgs.writeScript "${config.kite.meta.slug}-perms"
            (if config.kite.permsHook == null
             then ''
               #!/bin/sh
               exit 10
             ''
             else ''
               #!/bin/sh
               source /etc/profile
               exec ${config.kite.permsHook} "$@"
             '');

          cmpPrio = a: b: a.priority < b.priority;
          mkPermission = perm: with perm;
             let base = { inherit description dynamic; };
             in if !(builtins.isNull perm.name)
                then base // { inherit name; }
                else if !(builtins.isNull perm.regex)
                     then base // { inherit regex; }
                     else builtins.abort "Either name or regex must be specified in permission";
          sortedPermissions = map mkPermission (lib.sort cmpPrio config.kite.permissions);
          kitePermissions = pkgs.writeText "permissions.json" (builtins.toJSON sortedPermissions);
      in pkgs.buildEnv {
           name = "kite-environment-${config.kite.meta.slug}";
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
             mkdir -p $out/etc
             mkdir -p $out/etc/ssl/certs
             mkdir -p $out/var/log
             mkdir -p $out/tmp
             chmod 777 $out/tmp
             ln -s ${healthCheckScript} $out/app/hc
             ln -s ${startScript} $out/app/start
             ln -s ${permsScript} $out/app/perms
             ln -s ${kitePermissions} $out/permissions.json

             cat >$out/etc/profile <<EOF
             ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: val: "export ${name}=\"${val}\"") config.kite.environment)}
             EOF
             chmod +x $out/etc/profile

             cat >$out/etc/passwd <<EOF
             root:x:0:0:System administrator:/kite:${pkgs.bash}/bin/bash
             kite:x:1000:100:Kite user:/kite:${pkgs.bash}/bin/bash
             EOF

             cat >$out/etc/group <<EOF
             root:x:0:
             kite:x:100:
             EOF

             ln -s /run/hosts $out/etc/hosts

             cat >$out/etc/resolv.conf <<EOF
             # Only admin apps can access the internet
             EOF

             cat >$out/etc/nsswitch.conf <<EOF
             hosts: files dns
             EOF

             touch $out/etc/ssl/certs/ca-certificates.crt

             ln -s /etc/ssl/certs/ca-certificates.crt $out/etc/ssl/certs/ca-bundle.crt
           '';
         };
  };
}
