{
  nixpkgs.config = {
    allowUnfree = true;
    packageOverrides = super: let self = super.pkgs; in rec {
      kite = self.callPackage ../pkgs/kite.nix { curl = my-curl; };
      lksctp-tools-1-0-18 = self.callPackage ../pkgs/lksctp-tools.nix {};
      my-curl = super.curl.override {
        c-aresSupport = true; sslSupport = true; idnSupport = true;
        scpSupport = false; gssSupport = true;
        brotliSupport = true; openssl = super.openssl_1_1_0;
      };
    };
  };
}
