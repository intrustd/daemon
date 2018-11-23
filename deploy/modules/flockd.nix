{config, lib, pkgs, ...}:
with lib;
let cfg = config.services.flockd;
in
{
  options = {
    services.flockd = {
       enable = mkEnableOption "Flockd server";

       certificate = mkOption {
          type = types.str;
          description = "Path to certificate.pem file";
       };

       privateKey = mkOption {
         type = types.str;
         description = "Path to key.pem file";
       };

       package = mkOption {
         type = types.package;
         default = pkgs.kite.flockd;
         description = "Kite package";
       };
    };
  };

  config = mkIf cfg.enable {
    systemd.services.flockd = {
      description = "Kite flockd server";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/flockd -c ${cfg.certificate} -k ${cfg.privateKey}";
      };
    };

    users.users = singleton {
       name = "flockd";
       group = "flockd";
       uid = 1001;
    };

    users.groups = singleton {
      name = "flockd";
      gid = 1001;
    };
  };
}
