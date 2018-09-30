{ pkgs ? (import <nixpkgs> {}) }:

let stdenv = pkgs.stdenv;

    # TODO figure out how to get node grpc plugin here

    grpc-io-tools = ps: ps.buildPythonPackage rec {
        pname = "grpcio-tools";
        version = "1.9.1";

        src = ps.fetchPypi {
          inherit pname version;
          sha256 = "0gv7a0jy2waa1jc32bvqahpm6pmbgvzpnp28lw0gz5csabbrndhh";
        };

        enableParallelBuilding = true;

        propagatedBuildInputs = with ps; [ pkgs.grpc grpcio ];

        # no tests in the package
        doCheck = false;

        meta = with stdenv.lib; {
          description = "Protobuf code generator for gRPC";
          license = lib.licenses.asl20;
          homepage = "https://grpc.io/grpc/python/";
          maintainers = with maintainers; [ vanschelven ];
        };
      };

   usrsctp = pkgs.stdenv.mkDerivation rec {
       name = "usrsctp-${rev}";
       rev = "348a36c8b38a53b34087214b87565e9207c5469b";
       src = pkgs.fetchFromGitHub {
         owner = "sctplab";
         repo = "usrsctp";
         rev = rev;
         sha256 = "0zr65q58a8i6daw2xqd3nmp5cd2q2ai1bcqf289lar3bli1fz7dr";
       };

       nativeBuildInputs = [ pkgs.libtool pkgs.autoconf pkgs.automake pkgs.pkgconfig ];

       configureFlags = [ "--disable-warnings-as-errors" ];

       patchPhase = ''
         substituteInPlace ./Makefile.am --replace "# pkgconfig" "pkgconfig"
         substituteInPlace ./configure.ac --replace "dnl PKG_PROG_PKG_CONFIG" "PKG_PROG_PKG_CONFIG"
         substituteInPlace ./configure.ac --replace "dnl PKG_INSTALLDIR" "PKG_INSTALLDIR"
         substituteInPlace ./configure.ac --replace "dnl AC_CONFIG_FILES([usrsctp.pc])" "AC_CONFIG_FILES([usrsctp.pc])"
       '';

       preConfigure = ''
         libtoolize
         aclocal
         autoconf
         automake --foreign --add-missing --copy
       '';
   };

   curl-kite = pkgs.curl.override {
     c-aresSupport = true; sslSupport = true; idnSupport = true;
     scpSupport = false; gssSupport = true;
     brotliSupport = true; openssl = pkgs.openssl_1_1_0;
   };

   lksctp-tools-1-0-18 = pkgs.callPackage ./deploy/pkgs/lksctp-tools.nix { };

in pkgs.stdenv.mkDerivation {
  name = "stork-cpp";

  buildInputs = with pkgs; [
    pkgconfig cmake gdb openssl_1_1_0.dev
    uriparser nodejs
    uthash zlib

    ncat

    valgrind stun graphviz awscli

    lksctp-tools-1-0-18 libnl thrift
    curl-kite curl-kite.dev

    (python3.withPackages (ps: [
       ps.flask ps.sqlalchemy
     ]))
  ];

#  CMAKE_
}
