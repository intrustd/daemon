{ pkgs, pythonPackages, stdenv, fetchurl, certbot }:

pythonPackages.buildPythonPackage {
  name = "certbot-s3front-0.1.3";
  src = fetchurl {
    url =https://pypi.python.org/packages/6c/74/306bff86f5c20b964c5aa0d9faa7fa72bc7592da4c7125eaefbf82f02f60/certbot-s3front-0.3.1.tar.gz;
    sha256 = "0jx3zarqcz6dwnjkyd82nai0n9rqylmgfkraljc4f0gc5zp99h1i";
  };

  propagatedBuildInputs = [ certbot ] ++ (with pythonPackages; [ zope_interface boto3 acme ]);

  meta = {
    homepage = "https://github.com/dlapiduz/certbot-s3front";
    description = "S3/CloudFront plugin for Certbot client";
    license = stdenv.lib.licenses.mit;
  };
}
