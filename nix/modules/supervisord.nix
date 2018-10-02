{ config, pkgs, lib, ... }:
let servicesType = with lib; {
      options = {
        name = mkOption {
          type = types.str;
          description = "Name of this service";
        };

        startExec = mkOption {
          type = types.str;
          description = "Script to run on service start";
        };

        autostart = mkOption {
          type = types.bool;
          default = false;
          description = "Whether to auto-start this script";
        };

        environment = mkOption {
          type = types.attrsOf types.str;
          default = {};
          description = "Extra environment variables";
        };
      };
    };
in {

  options = with lib; {
    kite.services = mkOption {
      type = types.attrsOf (types.submodule servicesType);
      description = "Service configurations";
    };
  };

  config =
    let supervisorConfig = pkgs.writeText "supervisor.conf" supervisorConfigTxt;

        supervisorConfigTxt = ''
          [unix_http_server]
          file=/run/supervisord

          [supervisord]
          nodaemon=true
          logfile=/var/log/supervisord.log
          logfile_maxbytes=16384
          logfile_backups=0

          [supervisorctl]
          serverurl=unix:///run/supervisord

          ${lib.concatStringsSep "\n" serviceConfigs}
        '';

        mkScript = script: ''
          #!${pkgs.bash}/bin/bash
          ${script}
        '';

        mkEnvironmentVars = env: lib.concatStringsSep ", " (lib.mapAttrsToList mkEnvironmentVar env);
        mkEnvironmentVar = var: val: "${var}=\"${val}\"";

        mkServiceConfig = name: cfg:
          let environment = mkEnvironmentVars cfg.environment;
          in ''
            [program:${name}]
            command=${pkgs.writeScript "start-${name}" (mkScript cfg.startExec)}
            autostart=${if cfg.autostart then "true" else "false"}
            ${if environment == "" then "" else "environment=${environment}"}
          '';

        serviceConfigs = lib.mapAttrsToList mkServiceConfig config.kite.services;
    in {
      kite.startHook = ''
        exec ${pkgs.pythonPackages.supervisor}/bin/supervisord -c ${supervisorConfig} -n
      '';

      kite.healthCheckHook = ''
        exec ${pkgs.pythonPackages.supervisor}/bin/supervisorctl -c ${supervisorConfig} status
      '';
    };
}
