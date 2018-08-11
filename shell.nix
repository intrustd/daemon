{ pkgs ? (import <nixpkgs> {}) }:

let stdenv = pkgs.stdenv;

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

in pkgs.stdenv.mkDerivation {
  name = "stork-cpp";

  buildInputs = with pkgs; [
    pkgconfig  boost boost.dev cmake gdb openssl_1_1_0.dev
    uriparser nodejs protobuf grpc

    runc criu

    valgrind stun

    lksctp-tools libnl

    (python3.withPackages (ps: [ ps.grpcio ps.googleapis_common_protos (grpc-io-tools ps) ]))
  ];

#  CMAKE_
}
