rec {

  manifest = import ./build-bundle.nix rec {
    pkgs = import <nixpkgs> {};
    system = pkgs.stdenv.targetPlatform.system;
    kite-app-module = <src/kite.nix>;
    pure-build = true;
  };

  app = manifest.toplevel;

}
