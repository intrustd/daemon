pkgs:

with pkgs.lib;
{ name, pythonPackages ? []
, module, socket, uwsgi ? pkgs.uwsgi
, environment ? { }
, http ? null }:

let pythonEnv = pkgs.python3.withPackages (ps: pythonPackages);

    uwsgiWithPlugins = uwsgi.override { plugins = [ "python3" ]; };

in { name = "uwsgi-${name}";
     startExec = ''
       ${getBin uwsgiWithPlugins}/bin/uwsgi -s ${socket} --manage-script-name --mount /=${module} --plugin python3 --uid root ${optionalString (http != null) "--http ${http}"}
     '';
     environment = environment // { PYTHONPATH = "${pythonEnv}/${pkgs.python3.sitePackages}"; FLASK_DEBUG="1"; };
     autostart = true;
   }
