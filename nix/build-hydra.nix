let pkgs = import <nixpkgs> {};
in with pkgs.lib;

let systems = builtins.attrNames (import <system/systems.nix>);

    mkJobs = platform:
      let pkgs = (import <system/kite-appliance.nix> {
                    inherit platform;
                    nixpkgs-path = <nixpkgs>;
                  }).pkgs;

          manifest = import ./build-bundle.nix rec {
                       inherit pkgs;
                       system = pkgs.stdenv.targetPlatform.system;
                       kite-app-module = <src/kite.nix>;
                       pure-build = true;
                     };

      in [ (nameValuePair "manifest-${platform}" manifest)
           (nameValuePair "app-${platform}" manifest.toplevel) ];

in listToAttrs (concatLists (map mkJobs systems))
