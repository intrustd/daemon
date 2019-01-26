pkgs:
{ redis ? pkgs.redis,
  port ? 6379,
  bind ? [ "127.0.0.1" ],
  databases ? 16,
  loglevel ? "notice",
  savePoints ? [ { seconds = 900; changes = 1; }
                 { seconds = 300; changes = 10; }
                 { seconds = 60; changes = 10000; } ],
  dbfilename ? "dump.rdb",
  dir ? "/intrustd/",
  extraConfig ? "",
  name }:

let mkSavePoint = { seconds, changes }: "save ${builtins.toString seconds} ${builtins.toString changes}";
    confFile = with pkgs.lib; pkgs.writeText "${name}-redis.conf" ''
      bind ${concatStringsSep " " bind}
      port ${builtins.toString port}g
      daemonize no
      supervised no
      loglevel ${loglevel}
      databases ${builtins.toString databases}
      ${concatStringsSep "\n" (map mkSavePoint savePoints)}
      dbfilename ${dbfilename}
      dir ${dir}
      ${extraConfig}
    '';

in {
  name = "redis-${name}";
  autostart = true;
  startExec = ''
     ${pkgs.lib.getBin redis}/bin/redis-server ${confFile}
  '';
}
