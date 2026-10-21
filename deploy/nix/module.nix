self: { config, lib, pkgs, utils, ... }:
let
  cfg = config.services.positron;
in {
  options.services.positron = {
    enable = lib.mkEnableOption "Positron standalone database";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.positron;
      description = "Authenticated Positron package selected for this installation.";
    };
    configFile = lib.mkOption {
      type = lib.types.str;
      default = "/etc/positron/positron.toml";
      description = "Absolute path to the canonical TOML file. Keep secret material outside the Nix store.";
    };
    initialize = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Explicitly allow the native transactional initialization of empty data and secrets directories.";
    };
    extraReadWritePaths = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Additional existing owner-controlled paths required by canonical configuration, such as local backup repositories. This grants filesystem access without configuring a repository.";
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = lib.hasPrefix "/" cfg.configFile;
      message = "services.positron.configFile must be an absolute path";
    }];
    users.groups.positron = { };
    users.users.positron = {
      isSystemUser = true;
      group = "positron";
      description = "Positron database service";
    };
    environment.systemPackages = [ cfg.package ];
    systemd.tmpfiles.rules = [
      "d /etc/positron 0750 root positron -"
      "d /var/lib/positron 0700 positron positron -"
      "d /var/lib/positron-secrets 0700 positron positron -"
    ];
    systemd.services.positron = {
      description = "Positron observability database";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        User = "positron";
        Group = "positron";
        ExecStartPre = utils.escapeSystemdExecArgs [ "${cfg.package}/bin/positron" "config" "validate" "--config" cfg.configFile ];
        ExecStart = utils.escapeSystemdExecArgs (
          [ "${cfg.package}/bin/positron" "serve" ]
          ++ lib.optional cfg.initialize "--init-if-empty"
          ++ [ "--config" cfg.configFile ]
        );
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        Restart = "on-failure";
        KillSignal = "SIGTERM";
        # Covers the Configuration Contract's maximum 3600-second Drain deadline.
        TimeoutStopSec = 3605;
        UMask = "0077";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ReadWritePaths = [ "/var/lib/positron" "/var/lib/positron-secrets" "/run/positron" ] ++ cfg.extraReadWritePaths;
        RuntimeDirectory = "positron";
        RuntimeDirectoryMode = "0700";
      };
    };
  };
}
