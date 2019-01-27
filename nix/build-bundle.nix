let defaultPkgs = import <nixpkgs> {};
    defaultSystems = builtins.listToAttrs [ { name = defaultPkgs.hostPlatform.config;
                                              value = import <nixpkgs> {}; } ];
in { app-module
   , systems ? defaultSystems
   , pure-build ? false }:

let evalInPlatform = pkgs: import <nixpkgs/nixos/lib/eval-config.nix> {
      inherit pkgs;
      system = pkgs.stdenv.targetPlatform.system;
      modules = [ ./modules/top-level.nix (builtins.toPath app-module) ];
      extraArgs = { intrustd = (import ./lib/intrustd.nix) pkgs; inherit pure-build; };
    };

    platforms = map (name: rec { inherit name; config = (evalInPlatform (builtins.getAttr name systems)).config; package = config.app.toplevel; })
                    (builtins.attrNames systems);

    config = (builtins.head platforms).config;
    closures = builtins.listToAttrs (map ({name, package, ...}: { inherit name; value = package; }) platforms);

in ((import <nixpkgs> {}).writeText "${config.app.meta.slug}-manifest"
    (builtins.toJSON {
        name = config.app.meta.name;
        app-url = config.app.meta.app-url;
        icon = config.app.meta.icon;
#        authors = config.app.meta.authors;
        domain = config.app.identifier;
        nix-closure = closures;
        run-as-admin = config.app.runAsAdmin;
        singleton = config.app.singleton;

        version = "${builtins.toString config.app.version.major}.${builtins.toString config.app.version.minor}.${builtins.toString config.app.version.revision}";

        bind-mounts = config.app.bindMounts;
    })) // { toplevels = closures; appName = config.app.meta.name; }


