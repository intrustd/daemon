{ network.description = "Kite flockd";

  flockd =
    { config, pkgs, ... }:
    { imports = [ ./modules/flockd.nix
                  ./modules/overrides.nix ];
      config = {
        services.flockd = {
          enable = true;
          certificate = "/run/keys/flockd-certificate";
          privateKey = "/run/keys/flockd-key";
        };

        boot.kernelPackages = pkgs.linuxPackages_4_18;

        networking.firewall.allowedTCPPorts = [ 80 443 22 ];
        networking.firewall.allowedUDPPorts = [ 6854 ];

        deployment.keys = {
          flockd-certificate.text = builtins.readFile ../certificate.pem;
          flockd-certificate.user = "flockd";
          flockd-certificate.group = "flockd";
          flockd-certificate.permissions = "0444";

          flockd-key.text = builtins.readFile ../key.pem;
          flockd-key.user = "flockd";
          flockd-key.group = "flockd";
          flockd-key.permissions = "0400";
        };

        security.acme.certs."flock.flywithkite.com".email = "travis@athougies.net";

        services.nginx = {
          enable = true;

          recommendedGzipSettings = true;
          recommendedOptimisation = true;
          recommendedProxySettings = true;
          recommendedTlsSettings = true;

	  commonHttpConfig = ''
	    map $request_uri $flock {
	      "~/flock/(.*)$" $1;
	    }
	  '';

          virtualHosts."flock.flywithkite.com" = {
            forceSSL = true;
            enableACME = true;

            locations = {
              "/portal" = {
                extraConfig = ''
                  add_header "Access-Control-Allow-Origin" "*";
                  return 200 'https://admin.flywithkite.com/';
                '';
              };

              "~ /flock/(.*)$" = {
	         proxyPass = "http://127.0.0.1:6853/$flock";
                 proxyWebsockets = true;
		 extraConfig = ''
		   proxy_buffering off;
		 '';
              };
            };
          };
        };
      };
    };
}
