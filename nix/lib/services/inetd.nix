pkgs:

with pkgs.lib;
{ name, inetd ? pkgs.xinetd,
  environment ? {}, extraDefaults ? "",
  services }:

let

  configFile = pkgs.writeText "xinetd.conf"
    ''
      defaults
      {
        log_type       = SYSLOG daemon info
        log_on_failure = HOST
        log_on_success = PID HOST DURATION EXIT
        ${extraDefaults}
      }
      ${concatMapStrings makeService (attrValues services)}
    '';

  makeService = srv:
    let protocol = attrByPath [ "protocol" ] "tcp" srv;
        unlisted = attrByPath [ "unlisted" ] false srv;
        flags = attrByPath [ "flags" ] "" srv;
        port = attrByPath [ "port" ] 0 srv;
        serverArgs = attrByPath [ "serverArgs" ] "" srv;
        extraConfig = attrByPath [ "extraConfig" ] "" srv;
     in ''
       service ${srv.name}
       {
         protocol    = ${protocol}
         ${optionalString unlisted "type        = UNLISTED"}
         ${optionalString (flags != "") "flags = ${flags}"}
         socket_type = ${if protocol == "udp" then "dgram" else "stream"}
         ${if port != 0 then "port        = ${toString port}" else ""}
         wait        = ${if protocol == "udp" then "yes" else "no"}
         user        = intrustd
         server      = ${srv.server}
         ${optionalString (serverArgs != "") "server_args = ${serverArgs}"}
         ${extraConfig}
       }
     '';

in {
  name = "inetd-${name}";
  startExec = "${pkgs.xinetd}/bin/xinetd -syslog daemon -dontfork -stayalive -f ${configFile}";
  inherit environment;
  autostart = true;
}
