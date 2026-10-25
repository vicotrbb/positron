{ pkgs, package, module, candidate, fixture, commit }:
let
  # Correct the pinned acceptance platform's symlinked-rule reload cache.
  # This does not alter the exported Positron module or the guest's PID1/initrd.
  serviceUdev = assert pkgs.systemd.version == "260.5";
    pkgs.systemd.overrideAttrs (old: {
      patches = (old.patches or []) ++ [ ./systemd-260.5-udev-rule-path.patch ];
    });
  configuration = pkgs.writeText "positron-service.toml" ''
        schema_version = 1
        [runtime]
        shutdown_grace_seconds = 5
        [listener]
        operations_bind_address = "127.0.0.1:4310"
        api_bind_address = "127.0.0.1:4311"
        otlp_grpc_bind_address = "127.0.0.1:4312"
        otlp_http_bind_address = "127.0.0.1:4313"
        loki_push_bind_address = "127.0.0.1:4314"
        operations_transport = "plaintext"
        api_transport = "plaintext"
        otlp_grpc_transport = "plaintext"
        otlp_http_transport = "plaintext"
        loki_push_transport = "plaintext"
      '';
in pkgs.testers.runNixOSTest {
  name = "positron-service";
  # Exercise the same guest on builders without nested virtualization as well.
  requiredFeatures.kvm = false;
  nodes.machine = { lib, ... }: {
    imports = [ module ];
    systemd.services.systemd-udevd.serviceConfig.ExecStart = lib.mkForce [
      ""
      "${serviceUdev}/lib/systemd/systemd-udevd"
    ];
    virtualisation.memorySize = 2048;
    services.positron = {
      enable = true;
      initialize = true;
      inherit package;
      configFile = "/var/lib/positron-release/positron.toml";
      extraReadWritePaths = [ "/var/lib/positron-repository" "/var/lib/positron-recovery" ];
    };
    systemd.tmpfiles.rules = [
      "d /var/lib/positron-repository 0700 positron positron -"
      "d /var/lib/positron-recovery 0700 positron positron -"
      "d /var/lib/positron-release 0700 positron positron -"
      "C /var/lib/positron-release/positron.toml 0600 positron positron - ${configuration}"
    ];
    environment.etc."positron/positron.toml" = {
      mode = "0440";
      group = "positron";
      source = configuration;
    };
    environment.etc."positron-service-check.py".source = ./service-check.py;
    environment.etc."positron-lifecycle-check.py".source = ./lifecycle-check.py;
    environment.etc."positron-upgrade-inputs.json".text = builtins.toJSON {
      source = "${package}/bin/positron";
      candidate = "${candidate}/bin/positron";
      fixture = "${fixture}/bin/positron-upgrade-fixture";
      version = candidate.version;
      inherit commit;
    };
    environment.systemPackages = [ pkgs.curl pkgs.python3 pkgs.age pkgs.util-linux ];
    specialisation.removed.configuration.services.positron.enable = pkgs.lib.mkForce false;
    specialisation.upgraded.configuration = {
      services.positron.package = pkgs.lib.mkForce candidate;
      services.positron.extraReadWritePaths = pkgs.lib.mkAfter [ "/var/lib/positron-upgraded" ];
      systemd.tmpfiles.rules = [ "d /var/lib/positron-upgraded 0700 positron positron -" ];
    };
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("positron.service")
    machine.succeed("test -r /sys/fs/cgroup/system.slice/positron.service/cpu.max")
    machine.wait_until_succeeds("curl --fail http://127.0.0.1:4310/health/ready")
    machine.succeed("test $(systemctl show -p User --value positron) = positron")
    for path in ["/var/lib/positron", "/var/lib/positron-secrets", "/run/positron"]:
        machine.succeed(f"test $(stat -c %a {path}) = 700")
        machine.succeed(f"test $(stat -c %U {path}) = positron")
    machine.fail("su -s /bin/sh nobody -c 'cat /var/lib/positron-secrets/local-root-key.v1'")
    machine.succeed("systemctl stop positron")
    machine.succeed("umask 077; su -s /bin/sh positron -c 'positron bootstrap claim --config /etc/positron/positron.toml' > /root/positron-claim")
    machine.fail("su -s /bin/sh positron -c 'positron bootstrap claim --config /etc/positron/positron.toml'")
    machine.succeed("systemctl start positron")
    machine.wait_until_succeeds("curl --fail http://127.0.0.1:4310/health/ready")
    machine.succeed("sha256sum /var/lib/positron-secrets/local-root-key.v1 > /root/key.sha256")
    machine.succeed("python /etc/positron-service-check.py ingest")
    machine.succeed("python /etc/positron-service-check.py query")
    machine.succeed("systemctl stop positron")
    machine.succeed("umask 077; python /etc/positron-lifecycle-check.py recovery")
    machine.succeed("systemctl start positron")
    machine.wait_until_succeeds("curl --fail http://127.0.0.1:4310/health/ready")
    machine.succeed("python /etc/positron-lifecycle-check.py backup")
    machine.succeed("systemctl reload positron")
    machine.succeed("systemctl restart positron")
    try:
        machine.wait_until_succeeds("curl --fail http://127.0.0.1:4310/health/ready")
    except Exception:
        try:
            code, observation = machine.execute("timeout --kill-after=1s 14s python /etc/positron-service-check.py readiness-diagnostics")
            if code == 0:
                print(observation, end="")
            else:
                print('{"event":"readiness_observation","outcome":"unavailable"}')
        except Exception:
            print('{"event":"readiness_observation","outcome":"unavailable"}')
        raise
    machine.succeed("sha256sum --check /root/key.sha256")
    machine.succeed("python /etc/positron-service-check.py query")
    machine.succeed("systemctl stop positron")
    machine.succeed("python /etc/positron-lifecycle-check.py prepare-upgrade")
    machine.succeed("systemctl start positron")
    machine.wait_until_succeeds("curl --fail http://127.0.0.1:4310/health/ready")
    machine.succeed("python /etc/positron-service-check.py query")
    machine.succeed("python /etc/positron-lifecycle-check.py upgrade")
    try:
        machine.wait_until_succeeds("test $(systemctl show -p ActiveState --value positron) = inactive")
    except Exception:
        try:
            code, observation = machine.execute("timeout --kill-after=1s 34s python /etc/positron-lifecycle-check.py source-exit-diagnostics")
            if code == 0:
                print(observation, end="")
            else:
                print('{"event":"upgrade_source_exit","outcome":"unavailable"}')
        except Exception:
            print('{"event":"upgrade_source_exit","outcome":"unavailable"}')
        raise
    machine.succeed("python /etc/positron-lifecycle-check.py publish-upgrade")
    machine.succeed("/run/booted-system/specialisation/upgraded/bin/switch-to-configuration test")
    machine.wait_for_unit("positron.service")
    machine.wait_until_succeeds("curl --fail http://127.0.0.1:4310/health/ready")
    machine.succeed("systemctl show -p ReadWritePaths --value positron | grep -F /var/lib/positron-upgraded")
    machine.succeed("python /etc/positron-service-check.py query")
    machine.succeed("python /etc/positron-lifecycle-check.py upgraded")
    machine.succeed("systemctl stop positron")
    machine.succeed("test $(systemctl show -p ExecMainStatus --value positron) = 0")
    machine.succeed("su -s /bin/sh positron -c 'positron verify --offline --config /var/lib/positron-release/positron.toml'")
    machine.succeed("mv /var/lib/positron /root/original-data; mv /var/lib/positron-secrets /root/original-secrets")
    machine.succeed("install -d -m 0700 -o positron -g positron /var/lib/positron /var/lib/positron-secrets")
    machine.succeed("python /etc/positron-lifecycle-check.py restore")
    machine.succeed("systemctl start positron")
    machine.wait_until_succeeds("curl --fail http://127.0.0.1:4310/health/ready")
    machine.succeed("python /etc/positron-service-check.py query")
    machine.succeed("sha256sum --check /root/key.sha256")
    machine.succeed("/run/booted-system/specialisation/removed/bin/switch-to-configuration test")
    machine.fail("systemctl is-active positron")
    machine.succeed("test -d /var/lib/positron")
    machine.succeed("sha256sum --check /root/key.sha256")
    machine.succeed("test -f /etc/positron/positron.toml")
    machine.succeed("/run/booted-system/specialisation/upgraded/bin/switch-to-configuration test")
    machine.wait_for_unit("positron.service")
    machine.wait_until_succeeds("curl --fail http://127.0.0.1:4310/health/ready")
    machine.succeed("python /etc/positron-service-check.py query")
    machine.succeed("sha256sum --check /root/key.sha256")
    machine.succeed("systemctl stop positron")
  '';
}
