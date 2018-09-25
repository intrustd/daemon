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

   lksctp-tools-1-0-18 = stdenv.mkDerivation rec {
     name = "lksctp-tools-1.0.18";

     src = pkgs.fetchurl {
       url = "https://github.com/sctp/lksctp-tools/archive/lksctp-tools-1.0.18.tar.gz";
       sha256 = "14q0pjhskyx5j1z0v9141zmxyqjwl7niiqi4adv6882g0za7bvwh";
     };

     preConfigure = ''
       autoreconf
     '';

     nativeBuildInputs = [ pkgs.autoreconfHook ];

     preInstall = ''
     mkdir -p $out/include/netinet
     cp ./src/include/netinet/sctp.h $out/include/netinet/sctp.h
     '';

     meta = with stdenv.lib; {
       description = "Linux Kernel Stream Control Transmission Protocol Tools.";
       homepage = http://lksctp.sourceforge.net/;
       license = with licenses; [ gpl2 lgpl21 ]; # library is lgpl21
       platforms = platforms.linux;
     };
   };

   curl-kite = pkgs.curl.override {
     c-aresSupport = true; sslSupport = true; idnSupport = true;
     scpSupport = false; gssSupport = true;
     brotliSupport = true; openssl = pkgs.openssl_1_1_0;
   };
in pkgs.stdenv.mkDerivation {
  name = "stork-cpp";

  buildInputs = with pkgs; [
    pkgconfig  boost boost.dev cmake gdb openssl_1_1_0.dev
    uriparser nodejs protobuf grpc
    uthash zlib

    runc criu ncat

    valgrind stun graphviz

    lksctp-tools-1-0-18 libnl thrift
    curl-kite curl-kite.dev

    (python3.withPackages (ps: [
       ps.flask ps.grpcio ps.googleapis_common_protos (grpc-io-tools ps)
       ps.sqlalchemy
     ]))
  ];

#  CMAKE_
}
