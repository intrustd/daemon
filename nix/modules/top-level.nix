{ config, pkgs, lib, ... }: {
  imports = [ ./supervisord.nix ./permissions.nix ] ; # ./activation.nix ];

  options = with lib; {
    app.identifier = mkOption {
      type = types.string;
      description = "App domain URI";
    };

    app.version.major = mkOption {
      type = types.ints.unsigned;
      description = "Major version number";
      default = 0;
    };

    app.version.minor = mkOption {
      type = types.ints.unsigned;
      description = "Minor version number";
      default = 0;
    };

    app.version.revision = mkOption {
      type = types.ints.unsigned;
      description = "Revision version number";
    };

    app.environment = mkOption {
      type = types.attrsOf types.string;
      description = "Environment variables shared between all running processes in this container";
      default = {};
    };

    app.binaryCaches = mkOption {
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

    app.startHook = mkOption {
      type = types.string;
      description = "Script to run when applianced wants to start this application";
    };

    app.healthCheckHook = mkOption {
      type = types.string;
      description = "Script to run when applianced wants to run a health check on this application";
    };

    app.permsHook = mkOption {
      type = types.nullOr types.string;
      description = "Script to run to get information on app permissions";
      default = null;
    };

    app.bindMounts = mkOption {
      type = types.listOf types.string;
      default = [];
      description = ''
        Directories to identity mount (only available for administrative apps)
      '';
    };

    app.runAsAdmin = mkOption {
      type = types.bool;
      default = false;
      description = ''
        If true, this process is run with administrator privileges.

        Currently, this means access to the local API socket.

        Packages which request this permission may not receive it. Check to make sure.

        Packages which request this permission will likely need to be signed.
      '';
    };

    app.autostart = mkOption {
      type = types.bool;
      default = false;
      description = ''
        If true, this app should be auto-started, if the user has given permissions.
      '';
    };

    app.singleton = mkOption {
      type = types.bool;
      default = false;
      description = ''
        If true, this container is only instantiated once for the entire system.

        It can determine the source of a packet by asking the bridge controller.
      '';
    };

    app.systemPackages = mkOption {
      type = types.listOf types.package;
      default = [];
      example = literalExample "[ pkgs.bind ]";
      description = ''
        The set of packages available under the root directory.

        These are automatically updated each time the application is built
      '';
    };

    app.pathsToLink = mkOption {
      type = types.listOf types.str;
      default = [];
      example = [ "/" ];
      description = "The list of paths to link under the root directory";
    };

    app.extraOutputsToInstall = mkOption {
      type = types.listOf types.str;
      default = [];
      example = [ "info" "dev" ];
      description = "List of additional derivation outputs to be linked to root directory";
    };

    app.toplevel = mkOption {
      type = types.package;
      internal = true;
      description = "The top-level package";
    };

    app.meta = mkOption {
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
    app.systemPackages = with pkgs; [
      utillinux
      coreutils
      getconf
      getent
      bash
      iproute
    ];

    app.pathsToLink = [
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

    app.binaryCaches = [
      { url = "https://hydra.intrustd.com/cache";
        signatures = [ "cache.intrustd.com-1:7JJMfk9Vl5tetCyL8TnGSmo6IMvJypOlLv4Y7huDvDQ=" ];
        type = "system";
        priority = 1000000; }
    ];

    app.version.revision = builtins.currentTime;

    app.toplevel =
      let startScript = pkgs.writeScript "${config.app.meta.slug}-start-script" ''
            #!/bin/sh
            source /etc/profile
            ${config.app.startHook}
          '';
          healthCheckScript = pkgs.writeScript "${config.app.meta.slug}-health-check" ''
            #!/bin/sh
            source /etc/profile
            ${config.app.healthCheckHook}
          '';
          permsScript = pkgs.writeScript "${config.app.meta.slug}-perms"
            (if config.app.permsHook == null
             then ''
               #!/bin/sh
               exit 10
             ''
             else ''
               #!/bin/sh
               source /etc/profile
               exec ${config.app.permsHook} "$@"
             '');

          cmpPrio = a: b: a.priority < b.priority;
          mkPermission = perm: with perm;
             let base = { inherit description dynamic superuser; };
             in if !(builtins.isNull perm.name)
                then base // { inherit name; }
                else if !(builtins.isNull perm.regex)
                     then base // { inherit regex; }
                     else builtins.abort "Either name or regex must be specified in permission";
          sortedPermissions = map mkPermission (lib.sort cmpPrio config.app.permissions);
          appPermissions = pkgs.writeText "permissions.json" (builtins.toJSON sortedPermissions);
      in pkgs.buildEnv {
           name = "intrustd-environment-${config.app.meta.slug}";
           ignoreCollisions = true;
           paths = config.app.systemPackages;
           inherit (config.app) pathsToLink extraOutputsToInstall;

           postBuild = ''
             mkdir -p $out/dev
             mkdir -p $out/nix
             mkdir -p $out/proc
             mkdir -p $out/dev
             mkdir -p $out/sys
             mkdir -p $out/intrustd
             mkdir -p $out/app
             mkdir -p $out/run
             mkdir -p $out/etc
             mkdir -p $out/etc/ssl/certs
             mkdir -p $out/var/log
             mkdir -p $out/var/empty
             mkdir -p $out/tmp
             chmod 777 $out/tmp
             ln -s ${healthCheckScript} $out/app/hc
             ln -s ${startScript} $out/app/start
             ln -s ${permsScript} $out/app/perms
             ln -s ${appPermissions} $out/permissions.json

             cat >$out/etc/profile <<EOF
             ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: val: "export ${name}=\"${val}\"") config.app.environment)}
             EOF
             chmod +x $out/etc/profile

             cat >$out/etc/passwd <<EOF
             root:x:0:0:System administrator:/intrustd:${pkgs.bash}/bin/bash
             intrustd:x:1000:100:Intrustd user:/intrustd:${pkgs.bash}/bin/bash
             nobody:x:65534:65534:Unprivileged account:/var/empty:${pkgs.shadow}/bin/nologin
             EOF

             cat >$out/etc/group <<EOF
             root:x:0:
             intrustd:x:100:
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
