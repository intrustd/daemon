let pkgs = import <nixpkgs> {};
in with pkgs.lib;

let kiteSystems = builtins.attrNames (import <system/systems.nix>);

    mkJobs = platform:
      let pkgs = (import <system/kite-appliance.nix> {
                    inherit platform;
                    nixpkgs-path = <nixpkgs>;
                  }).pkgs;
      in { name = pkgs.hostPlatform.config;
           value = pkgs; };

    manifest = import ./build-bundle.nix rec {
       systems = builtins.listToAttrs (map mkJobs kiteSystems);
       kite-app-module = <src/kite.nix>;
       pure-build = true;
    };

in { inherit manifest; } //
   mapAttrs' (platform: value: nameValuePair "app-${platform}" value) manifest.toplevels
