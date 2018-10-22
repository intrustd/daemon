{ config, pkgs, lib, ... }:
let permissionsType = with lib; types.submodule {
      options = {
        name = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Name of permission. Either this or regex must be specified";
        };

        regex = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Regex matching permission. Either this or name must be specified";
        };

        description = mkOption {
          type = types.str;
          default = "";
          description = "Description of this permission";
        };

        priority = mkOption {
          type = types.int;
          default = 1000;
          description = "Priority";
        };

        verifyCmd = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "A command to run, with optional substitutions from the regex field, using python's regex syntax";
        };
      };
    };
in {
  assertions = [
  ];

  options = with lib; {
    kite.permissions = mkOption {
      type = types.listOf permissionsType;
      description = "Permissions for this application";
    };
  };

  config = {
    kite.permissions = [
      { name = "admin";
        priority = 10000;
        description = "Have full admin rights"; }
    ];
  };
}
