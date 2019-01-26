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

        priority = mkOption {
          type = types.nullOr types.int;
          default = null;
          description = "Relative priority";
        };

        autorestart = mkOption {
          type = types.str;
          default = "true";
          description = "Whether to restart the program";
        };

        oneshot = mkOption {
          type = types.bool;
          default = false;
          description = "Whether this is a oneshot";
        };
      };
    };
in {

  options = with lib; {
    app.services = mkOption {
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

        oneShotConf = ''
          startsecs=0
          exitcodes=0
        '';
        mkServiceConfig = name: cfg:
          let environment = mkEnvironmentVars cfg.environment;
          in ''
            [program:${name}]
            command=${pkgs.writeScript "start-${name}" (mkScript cfg.startExec)}
            autostart=${if cfg.autostart then "true" else "false"}
            autorestart=${cfg.autorestart}
            ${if cfg.oneshot then oneShotConf else ""}
            ${if environment == "" then "" else "environment=${environment}"}
            ${if isNull cfg.priority then "" else "priority=${builtins.toString cfg.priority}"}
            stdout_logfile=/var/log/${name}-stdout.log
            stderr_logfile=/var/log/${name}-stderr.log
          '';

        serviceConfigs = lib.mapAttrsToList mkServiceConfig config.app.services;
    in {
      app.startHook = ''
        exec ${pkgs.pythonPackages.supervisor}/bin/supervisord -c ${supervisorConfig} -n
      '';

      app.healthCheckHook = ''
        exec ${pkgs.pythonPackages.supervisor}/bin/supervisorctl -c ${supervisorConfig} status
      '';
    };
}
