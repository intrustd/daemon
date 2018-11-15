pkgs:

with pkgs.lib;
{ name, config, lighttpd ? pkgs.lighttpd }:

let configFile = pkgs.writeText "lighttpd-${name}-config" config;

in { name = "lighttpd-${name}";
     startExec = ''
       ${getBin lighttpd}/bin/lighttpd -D -f ${configFile}
     '';
     autostart = true;
   }
