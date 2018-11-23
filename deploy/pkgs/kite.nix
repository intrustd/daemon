{ pkgs, stdenv, cmake, uriparser, lksctp-tools-1-0-18, curl, pkgconfig, zlib, openssl_1_1_0, uthash, check }:

stdenv.mkDerivation rec {
   name = "kite-${version}";
   version = "0.1.0";

   src = ./.. + "/kite-${version}.tar.bz2";

   buildInputs = [ cmake uriparser lksctp-tools-1-0-18 curl pkgconfig openssl_1_1_0 uthash check ];

   outputs = [ "out" "flockd" "applianced" "appliancectl" ];

   configurePhase = ''
     ${cmake}/bin/cmake -DCMAKE_BUILD_TYPE=Release .
   '';

   installPhase = ''
     mkdir -p $flockd/bin
     mkdir -p $applianced/bin
     mkdir -p $appliancectl/bin
     mkdir -p $out

     cp -R bin $out/bin

     mv bin/flockd $flockd/bin/flockd

     mv bin/appliancectl $appliancectl/bin/appliancectl

     mv bin/applianced $applianced/bin/applianced
     mv bin/app-instance-init $applianced/bin/app-instance-init
     mv bin/persona-init $applianced/bin/persona-init
     mv bin/webrtc-proxy $applianced/bin/webrtc-proxy
   '';

   meta = with stdenv.lib; {
     description = "Kite binaries";
     homepage = http://flywithkite.com/;
     licenses = licenses.mit;
     platforms = platforms.linux;
   };
}
