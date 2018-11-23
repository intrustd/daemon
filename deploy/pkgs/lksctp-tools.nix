{ stdenv, pkgs }:

stdenv.mkDerivation rec {
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
}
