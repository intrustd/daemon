{ stdenv, pkgs, pythonPackages, certbot, fetchFromGitHub }:

pythonPackages.buildPythonPackage rec {
  name = "certbot-dns-route53-${version}";
  version = certbot.version;

  src = fetchFromGitHub {
    owner = "certbot";
    repo = "certbot";
    rev = "v${version}";
    sha256 = "0gsq4si0bqwzd7ywf87y7bbprqg1m72qdj11h64qmwb5zl4vh444";
  } + "/certbot-dns-route53";

  propagatedBuildInputs = with pythonPackages; [ certbot zope_interface acme boto3 mock setuptools ];

  meta = with stdenv.lib; {
    homepage = src.meta.homepage;
    description = "Route53 DNS Authenticator plugin for Certbot";
    platform = platforms.unix;
    license = licenses.asl20;
  };
}
