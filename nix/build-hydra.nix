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

    nodePkgSet = import <src/js> { pkgs = pkgs.buildPackages; nodejs = pkgs.buildPackages."nodejs-8_x"; };

    nodeDeps = (nodePkgSet.shell.override { bypassCache = true; }).nodeDependencies;

in { inherit (bundle) manifest;
     static = pkgs.stdenv.mkDerivation {
       name = "${bundle.appName}-static";
       src = <src/js>;

       nativeBuildInputs = with pkgs; [ nodeDeps nodejs-8_x ];

       phases = [ "unpackPhase" "buildPhase" "installPhase" ];

       buildPhase = ''
         ln -s ${nodeDeps}/lib/node_modules ./node_modules
         ln -s ${nodeDeps}/lib/package-lock.json ./package-lock.json
         npm run build
       '';

       installPhase = ''
          mkdir $out
          cp -R ./dist $out
          cp ${bundle.manifest} $out/manifest.json
       '';
     };
   } //
   mapAttrs' (platform: value: nameValuePair "app-${platform}" value) bundle.toplevels
