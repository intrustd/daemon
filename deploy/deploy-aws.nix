{ accessKeyId ? "iammisc", region ? "us-west-2" }:
let domains = [
      { url = "admin.flywithkite.com";  cfDistributionId = "E356BORMX8ICUT"; }
      { url = "photos.flywithkite.com"; cfDistributionId = "E2JDBQTQAURF1P"; }
    ];

    route53ZoneId = "Z24OSVPJK407O6";

in {
  flockd = {resources, config, lib, pkgs, ...}:
    let letsencrypt-s3front = pkgs.callPackages ./pkgs/le-s3front.nix {};
        certbot-dns-route53 = pkgs.callPackages ./pkgs/certbot-dns-route53.nix {};

        certArgs = ''
          ${lib.concatStringsSep " " (map (d: "-d ${d.url}") domains)} \
          -m travis@athougies.net --no-eff-email \
        '';

        installCertificate = domain: ''
          ${pkgs.certbot}/bin/certbot --agree-tos -a certbot-s3front:auth \
            -i certbot-s3front:installer \
            --certbot-s3front:auth-s3-bucket ${domain.url} \
            --certbot-s3front:installer-cf-distribution-id ${domain.cfDistributionId} \
            ${certArgs} \
            --config-dir /var/lib/letsencrypt \
            --keep-until-expiring --expand
        '';

    in {
      deployment.targetEnv = "ec2";
      deployment.ec2.accessKeyId = accessKeyId;
      deployment.ec2.region = region;
      deployment.ec2.instanceType = "t2.medium";
      deployment.ec2.keyPair = resources.ec2KeyPairs.flockd-deploy-key-pair;
      deployment.ec2.instanceProfile = resources.iamRoles.flockd-role.name;
      deployment.ec2.securityGroups = [ "flockd" ];

      deployment.route53.hostName = "flock.flywithkite.com";
      deployment.route53.usePublicDNSName = true;
      deployment.route53.accessKeyId = "AKIAI6EY7PJMUNAJNLSQ";

      systemd.services.letsencrypt-s3 = {
        description = "Let's Encrypt renewer for cloudfront distribution";
        after = [ "network.target" "network-online.target" ];
        wantedBy = [ "multi-user.target" ];

        script = ''
          export PYTHONPATH="$PYTHONPATH:${pkgs.pythonPackages.makePythonPath [letsencrypt-s3front certbot-dns-route53]}"

	  ${pkgs.certbot}/bin/certbot --agree-tos certonly \
	    --dns-route53 \
	    ${certArgs} \
            --config-dir /var/lib/letsencrypt --reinstall --expand

          ${lib.concatStringsSep "\n" (map installCertificate domains)}
        '';

        serviceConfig = { User = "root"; Group = "root"; };
      };

      systemd.timers.letsencrypt-s3 = {
        description = "Let's Encrypt renewer for cloudfront distribution";
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = "weekly";
          Unit = "letsencrypt-s3";
          Persistent = "yes";
          AccuracySec = "5m";
          RandomizedDelaySec = "1h";
        };
      };
    };

  resources.ec2KeyPairs.flockd-deploy-key-pair = {
    inherit accessKeyId region;
  };

  resources.iamRoles.flockd-role = {
    inherit accessKeyId;
    policy = ''
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Action": [
              "dynamodb:UpdateItem",
              "dynamodb:DeleteItem",
              "dynamodb:PutItem",
              "dynamodb:GetItem"
            ],
            "Resource": ["arn:aws:dynamodb:us-west-2:079437634674:table/flockd"]
          },
          {
            "Effect": "Allow",
            "Action": [
              "s3:PutObject",
              "s3:PutObjectACL"
            ],
            "Resource": ["arn:aws:s3:::*.flywithkite.com/*"]
          },
          {
            "Effect": "Allow",
            "Action": [
              "s3:DeleteObject"
            ],
            "Resource": ["arn:aws:s3:::*.flywithkite.com/.well-known/*"]
          },
          {
            "Effect": "Allow",
            "Action": [
              "cloudfront:GetDistributionConfig",
              "cloudfront:UpdateDistribution"
            ],
            "Resource": [ "*" ]
          },
          {
              "Effect": "Allow",
              "Action": [
                  "iam:UploadServerCertificate",
                  "iam:UpdateServerCertificate",
                  "iam:DeleteServerCertificate",
                  "iam:ListServerCertificates"
              ],
              "Resource": [
                  "*"
              ]
          },
          {
              "Effect": "Allow",
              "Action": [
                  "route53:ListHostedZones",
                  "route53:GetChange"
              ],
              "Resource": [
                  "*"
              ]
          },
          {
              "Effect" : "Allow",
              "Action" : [
                  "route53:ChangeResourceRecordSets"
              ],
              "Resource" : [
                  "arn:aws:route53:::hostedzone/${route53ZoneId}"
              ]
          }
        ]
      }
    '';
  };
}
