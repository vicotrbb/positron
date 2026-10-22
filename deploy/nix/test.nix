{ pkgs, package, module, candidate, fixture, commit }:
let
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
  nodes.machine = { ... }: {
    imports = [ module ];
    # Finite serial-visible observations also run when the driver backdoor
    # cannot start. They neither gate nor change any observed unit or device.
    systemd.services.positron-device-observation = {
      path = [ pkgs.coreutils pkgs.systemd pkgs.procps pkgs.gawk pkgs.strace ];
      serviceConfig = {
        Type = "oneshot";
        TimeoutStartSec = 15;
        TimeoutStopSec = 1;
        StandardOutput = "journal";
        StandardError = "journal";
      };
      script = ''
        set +e
        trap 'echo "positron-device-observation SNAPSHOT-INCOMPLETE"; exit 143' TERM INT
        observe() {
          label="$1"
          shift
          printf 'positron-device-observation BEGIN %s\n' "$label"
          timeout --kill-after=1s 2s "$@" 2>&1 | head -c 4096
          result="''${PIPESTATUS[0]}"
          printf '\npositron-device-observation END %s status=%s\n' "$label" "$result"
          if test "$result" -ne 0; then
            printf 'positron-device-observation ERROR %s\n' "$label"
          fi
        }
        observe units systemctl show --no-pager \
          --property=Names,ActiveState,SubState,SysFSPath,Result,Job,MainPID,TasksCurrent \
          dev-hvc0.device dev-ttyAMA0.device systemd-udevd.service
        for tty in hvc0 ttyAMA0; do
          observe "$tty-sysfs" ${pkgs.runtimeShell} -c '
            if test -r "/sys/class/tty/$1/uevent"; then
              cat "/sys/class/tty/$1/uevent"
            else
              echo "MISSING tty sysfs uevent"
            fi
          ' sh "$tty"
          observe "$tty-udev" ${pkgs.runtimeShell} -c '
            udevadm info --query=property --path="/sys/class/tty/$1" 2>&1 |
              awk "/^(DEVPATH|DEVNAME|SUBSYSTEM|TAGS|CURRENT_TAGS|SYSTEMD_READY|ID_PROCESSING|USEC_INITIALIZED)=/"
            exit "''${PIPESTATUS[0]}"
          ' sh "$tty"
          observe "$tty-database" ${pkgs.runtimeShell} -c '
            device=$(cat "/sys/class/tty/$1/dev")
            case "$device" in
              ""|*[!0-9:]*) echo "MISSING tty device number" ;;
              *)
                if test -r "/run/udev/data/c$device"; then
                  awk "/^(I:[0-9]+|G:systemd|Q:systemd|E:SYSTEMD_READY=[01])$/" "/run/udev/data/c$device"
                else
                  echo "MISSING tty device database"
                fi
                ;;
            esac
          ' sh "$tty"
        done
        pid=$(timeout --kill-after=1s 2s systemctl show --property=MainPID --value systemd-udevd.service)
        case "$pid" in
          ""|0|*[!0-9]*) echo "positron-device-observation MISSING udevd PID" ;;
          *)
            observe udevd-status awk '/^(State|Threads):/' "/proc/$pid/status"
            # Only syscall counts for the manager: no child tracing or arguments.
            # SIGINT first detaches and prints the summary; timeout/error labels
            # remain visible if attach or bounded summary collection fails.
            observe udevd-syscalls timeout --signal=INT --kill-after=1s 1s strace -c -p "$pid"
            observe udevd-threads ps -L -p "$pid" -o pid,lwp,stat,wchan,time
            observe udevd-children ps --ppid "$pid" -o pid,ppid,stat,wchan,time
            ;;
        esac
        echo "positron-device-observation SNAPSHOT-END"
      '';
    };
    systemd.timers.positron-device-observation-first = {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnBootSec = "180s"; AccuracySec = "1s"; Unit = "positron-device-observation.service"; };
    };
    systemd.timers.positron-device-observation-second = {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnBootSec = "380s"; AccuracySec = "1s"; Unit = "positron-device-observation.service"; };
    };
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
    machine.wait_until_succeeds("curl --fail http://127.0.0.1:4310/health/ready")
    machine.succeed("sha256sum --check /root/key.sha256")
    machine.succeed("python /etc/positron-service-check.py query")
    machine.succeed("systemctl stop positron")
    machine.succeed("python /etc/positron-lifecycle-check.py prepare-upgrade")
    machine.succeed("systemctl start positron")
    machine.wait_until_succeeds("curl --fail http://127.0.0.1:4310/health/ready")
    machine.succeed("python /etc/positron-service-check.py query")
    machine.succeed("python /etc/positron-lifecycle-check.py upgrade")
    machine.wait_until_succeeds("test $(systemctl show -p ActiveState --value positron) = inactive")
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
