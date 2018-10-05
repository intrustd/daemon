pkgs:
{ templates.nginx = (import ./services/nginx.nix) pkgs;
  templates.httpd = (import ./services/httpd.nix) pkgs;
}
