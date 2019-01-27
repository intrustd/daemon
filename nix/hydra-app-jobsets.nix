{ description, src }:

let pkgs = import <nixpkgs> {};
in {
  jobsets =
    let spec = {
          app = {
            inherit description;
            enabled = 1;
            hidden = false;
            nixexprinput = "intrustd";
            nixexprpath = "nix/build-hydra.nix";
            checkinterval = 300;
            schedulingshares = 50;
            enableemail = true;
            emailoverride = "";
            keepnr = 3;
            inputs = {
              inherit src;
              nixpkgs = { type = "git"; value = "git://github.com/intrustd/nixpkgs.git kite"; emailresponsible = true; };
              intrustd = { type = "git"; value = "git://github.com/intrustd/daemon.git"; emailresponsible = true; };
              system = { type = "git"; value = "git://github.com/intrustd/appliance.git"; emailresponsible = true; };
            };
          };
        };
    in pkgs.writeText "spec.json" (builtins.toJSON spec);
}
