pkgs:
{ name ? "default",
  stateDir ? "/run/apache-${name}",
  logDir ? "/intrustd/logs/apache-${name}",
  apache ? pkgs.apacheHttpd,
  root,
  php ? pkgs.php,
  port ? 50051,
  enablePhp ? false,
  autostart ? true }:
with pkgs.stdenv.lib;
let allDenied = ''
      Require all denied
    '';
    allGranted = ''
      Require all granted
    '';

    phpPkg = php.override { apacheHttpd = apache.dev; };
    phpMajorVersion = head (splitString "." phpPkg.version);
    phpModule = { name = "php${phpMajorVersion}";
                  module = "${phpPkg}/modules/libphp${phpMajorVersion}.so"; };

    loadModule = {name, module}: "LoadModule ${name}_module ${module}";
    defaultModuleNames = [ "authz_core" "authz_host" "mime" "log_config" "unixd" "dir" ];
    defaultModules = map (name: { inherit name; module = "${apache}/modules/mod_${name}.so"; }) defaultModuleNames;

    mimeConf = ''
      TypesConfig ${apache}/conf/mime.types
      AddType application/x-x509-ca-cert .crt
      AddType application/x-pkcs7-crl    .crl
      AddType application/x-httpd-php    .php .phtml
      <IfModule mod_mime_magic.c>
          MIMEMagicFile ${apache}/conf/magic
      </IfModule>
    '';

    loggingConf = ''
      ErrorLog ${logDir}/error_log
      LogLevel notice
      LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
      LogFormat "%h %l %u %t \"%r\" %>s %b" common
      LogFormat "%{Referer}i -> %U" referer
      LogFormat "%{User-agent}i" agent
    '';

    confFile = pkgs.writeText "apache-${name}-config" ''
      ServerRoot ${root}
      ServerName localhost
      Listen ${toString port}

      User intrustd
      Group intrustd

      DefaultRuntimeDir ${stateDir}/runtime
      PidFile ${stateDir}/apache.pid

      <IfModule prefork.c>
        MaxClients 10
        MaxRequestsPerChild 10
      </IfModule>

      LoadModule mpm_event_module ${apache}/modules/mod_mpm_event.so
      ${concatStringsSep "\n" (map loadModule defaultModules)}
      ${optionalString enablePhp (loadModule phpModule)}

      <Files ~ "^\.ht">
        ${allDenied}
      </Files>

      ${mimeConf}
      ${loggingConf}

      <Directory />
        Options FollowSymLinks
        AllowOverride None
        ${allDenied}
      </Directory>

      <Directory /nix/store>
        ${allGranted}
      </Directory>

      DocumentRoot ${root}
      <Directory ${root}>
        Options Indexes FollowSymLinks
        AllowOverride None
        ${allGranted}
        DirectoryIndex index.php
      </Directory>
    '';

    phpIni = pkgs.writeText "apache-${name}-php.ini" ''
    '';
in {
  name = "apache-${name}";

  startExec = ''
    mkdir -p ${stateDir}/runtime
    mkdir -p ${logDir}

    ${apache}/bin/httpd -f ${confFile} -DFOREGROUND
  '';

  environment = { } //
     (if enablePhp then { PHPRC = "${phpIni}"; } else {});

  inherit autostart;
}
