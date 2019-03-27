pkgs:
{ templates.nginx = (import ./services/nginx.nix) pkgs;
  templates.httpd = (import ./services/httpd.nix) pkgs;
  templates.lighttpd = (import ./services/lighttpd.nix) pkgs;
  templates.uwsgi = (import ./services/uwsgi.nix) pkgs;
  templates.redis = (import ./services/redis.nix) pkgs;
  templates.inetd = (import ./services/inetd.nix) pkgs;
}
