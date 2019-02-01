let pkgs = import <nixpkgs> {};
in with pkgs.lib;

let systems = builtins.attrNames (import <system/systems.nix>);

    mkJobs = platform:
      let pkgs = (import <system/appliance.nix> {
                    inherit platform;
                    nixpkgs-path = <nixpkgs>;
                  }).pkgs;
      in { name = pkgs.hostPlatform.config;
           value = pkgs; };

    bundle = import ./build-bundle.nix {
       systems = builtins.listToAttrs (map mkJobs systems);
       app-module = <src/app.nix>;
       pure-build = true;
    };

in { inherit (bundle) manifest;
     static = pkgs.callPackage <src/static.nix> { inherit (bundle) manifest; };
   } //
   mapAttrs' (platform: value: nameValuePair "app-${platform}" value) bundle.toplevels
