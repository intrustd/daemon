# Not done

pkgs:
{ name ? "default",
  stateDir ? "/kite/logs/nginx-${name}",
  nginx ? pkgs.nginx,
  port ? 50051,
  statusPage ? false,

  sendfile ? true,
  tcpNoPush ? true,
  tcpNoDelay ? true }:

with pkgs.stdenv.lib;
let configFile = pkgs.writeText "nginx-${name}-config" ''
      error_log stderr;
      daemon off;

      http {
        include ${nginx}/conf/mime.types;
        include ${nginx}/conf/fastcgi.conf;
        include ${nginx}/conf/uwsgi_params;

        ${optionalString sendfile "sendfile on;"}
        ${optionalString tcpNoPush "tcp_nopush on;" }
        ${optionalString tcpNoDelay "tcp_nodelay on;"}
      }

      server {
        listen ${port};
        server_name app;

      }
    '';
in {
  name = "nginx-${name}";
  startExec = ''
    mkdir -p ${stateDir}/logs
    chmod 700 ${stateDir}/logs
    ${nginx}/bin/nginx -c ${configFile} -p ${stateDir} -t
  '';
}
