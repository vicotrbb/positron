{ pkgs, package, module, candidate, fixture, commit }:
let
  # Diagnostic only: replace stage-2 udevd, retaining original PID1/initrd/journald.
  # Target 0=hvc0, 1=ttyAMA0. Stages: 1=receive, 2=queued, 3=blocked,
  # 4=unblocked, 5=attached, 6=notified, 7=worker-exit, 8=run-error, 9=queue-error.
  diagnosticSystemd = assert pkgs.systemd.version == "260.5";
    pkgs.systemd.overrideAttrs (old: {
      patches = (old.patches or []) ++ [ (pkgs.writeText "positron-udev-manager.patch" ''
        --- a/src/udev/udev-manager.c
        +++ b/src/udev/udev-manager.c
        @@ -48,6 +48,59 @@
         #define EVENT_REQUEUE_INTERVAL_USEC (200 * USEC_PER_MSEC)
         #define EVENT_REQUEUE_TIMEOUT_USEC  (3 * USEC_PER_MINUTE)
         
        +
        +/* Temporary issue117 diagnostic: fixed tty identities, no device paths/properties. */
        +typedef struct PositronTtyObservation {
        +        unsigned stage;
        +        uint64_t seqnum, blocker;
        +        pid_t pid;
        +        int status, code;
        +        bool processed, again;
        +} PositronTtyObservation;
        +
        +static void positron_tty_observe(sd_device *dev, unsigned stage, uint64_t blocker, pid_t pid,
        +                                int status, int code, bool processed, bool again) {
        +        static PositronTtyObservation last[2];
        +        static unsigned records;
        +        const char *name, *subsystem;
        +        uint64_t seqnum = 0;
        +        unsigned target;
        +
        +        if (!dev || sd_device_get_subsystem(dev, &subsystem) < 0 || !streq(subsystem, "tty") ||
        +            sd_device_get_sysname(dev, &name) < 0)
        +                return;
        +        if (streq(name, "hvc0"))
        +                target = 0;
        +        else if (streq(name, "ttyAMA0"))
        +                target = 1;
        +        else
        +                return;
        +        (void) sd_device_get_seqnum(dev, &seqnum);
        +        PositronTtyObservation *previous = &last[target];
        +        if (previous->stage == stage && previous->seqnum == seqnum && previous->blocker == blocker &&
        +            previous->pid == pid && previous->status == status && previous->code == code &&
        +            previous->processed == processed && previous->again == again)
        +                return;
        +        *previous = (PositronTtyObservation) { stage, seqnum, blocker, pid, status, code, processed, again };
        +        if (records >= 64)
        +                return;
        +        log_info("POSITRON-UDEV target=%u stage=%u seq=%"PRIu64" blocker=%"PRIu64" pid="PID_FMT" status=%i code=%i processed=%u again=%u",
        +                 target, stage, seqnum, blocker, pid, status, code, processed ? 1U : 0U, again ? 1U : 0U);
        +        if (++records == 64)
        +                log_info("POSITRON-UDEV INCOMPLETE target-record-cap");
        +}
        +
        +static void positron_manager_observe(unsigned stage) {
        +        static unsigned records[2], previous[2];
        +        unsigned group = stage == 3;
        +        if (previous[group] == stage || records[group] >= 16)
        +                return;
        +        previous[group] = stage;
        +        log_info("POSITRON-UDEV manager-stage=%u", stage);
        +        if (++records[group] == 16)
        +                log_info("POSITRON-UDEV INCOMPLETE manager-record-cap group=%u", group);
        +}
        +
         static void event_unset_whole_disk(Event *event) {
                 Manager *manager = ASSERT_PTR(ASSERT_PTR(event)->manager);
         
        @@ -321,6 +374,7 @@
                          * when explicitly requested or at least one .rules file or friend is updated. */
                         return;
         
        +        positron_manager_observe(1); /* reload-enter */
                 (void) notify_reloading();
         
                 flags |= manager_reload_config(manager);
        @@ -339,6 +393,7 @@
                 }
         
                 notify_ready(manager);
        +        positron_manager_observe(2); /* reload-exit */
         }
         
         void manager_revert(Manager *manager) {
        @@ -385,6 +440,7 @@
                 worker->event = event;
                 event->state = EVENT_RUNNING;
                 event->worker = worker;
        +        positron_tty_observe(event->dev, 5, 0, worker->pidref.pid, 0, 0, false, false); /* attached */
         
                 (void) event_reset_time_relative(
                                 manager->event,
        @@ -433,6 +489,7 @@
                 sd_device *dev = event ? ASSERT_PTR(event->dev) : NULL;
         
                 assert(si);
        +        positron_tty_observe(dev, 7, 0, si->si_pid, si->si_status, si->si_code, false, false); /* worker-exit */
         
                 switch (si->si_code) {
                 case CLD_EXITED:
        @@ -620,9 +677,11 @@
         
                 /* lookup event for identical, parent, child device */
         
        -        if (event->blocker && event->blocker->state != EVENT_PROCESSED)
        +        if (event->blocker && event->blocker->state != EVENT_PROCESSED) {
                         /* Previously found blocker is not processed yet. */
        +                positron_tty_observe(event->dev, 3, event->blocker->seqnum, 0, 0, 0, false, false);
                         return;
        +        }
         
                 /* If we have not found blocker yet, or the previously found blocker has been processed, let's find
                  * (another) blocker for this event. */
        @@ -641,12 +700,14 @@
                                          event->seqnum, e->seqnum);
         
                         unref_and_replace_full(event->blocker, e, event_ref, event_unref);
        +                positron_tty_observe(event->dev, 3, e->seqnum, 0, 0, 0, false, false);
                         return;
                 }
         
                 /* No new blocker is found, and if set, previously found blocker has been processed. Clear the
                  * previous blocker if set. */
                 event->blocker = event_unref(event->blocker);
        +        positron_tty_observe(event->dev, 4, 0, 0, 0, 0, false, false); /* unblocked */
         }
         
         static bool manager_can_process_event(Manager *manager) {
        @@ -671,6 +732,7 @@
                         children_max_reached_logged = true;
                 }
         
        +        positron_manager_observe(3); /* worker-limit */
                 return false;
         
         yes_we_can:
        @@ -710,8 +772,10 @@
                                 continue;
         
                         r = event_run(event);
        -                if (r < 0)
        +                if (r < 0) {
        +                        positron_tty_observe(event->dev, 8, 0, 0, r, 0, false, false);
                                 return r;
        +                }
         
                         /* A worker is activated now. Let's check if we can process more events. */
                         if (!manager_can_process_event(manager))
        @@ -931,6 +995,7 @@
                                          manager->last_event->seqnum, event->seqnum);
         
                 event->manager = manager;
        +        positron_tty_observe(dev, 2, 0, 0, 0, 0, false, false); /* queued */
                 TAKE_PTR(event);
                 log_device_uevent(dev, "Device is queued");
         
        @@ -1044,6 +1109,7 @@
                 int r;
         
                 DEVICE_TRACE_POINT(kernel_uevent_received, dev);
        +        positron_tty_observe(dev, 1, 0, 0, 0, 0, false, false); /* received */
         
                 (void) manager_create_queue_file(manager);
         
        @@ -1051,6 +1117,7 @@
         
                 r = event_queue_insert(manager, dev);
                 if (r < 0) {
        +                positron_tty_observe(dev, 9, 0, 0, r, 0, false, false);
                         log_device_error_errno(dev, r, "Failed to insert device into event queue: %m");
                         return 1;
                 }
        @@ -1110,6 +1177,7 @@
                 if (r < 0)
                         return log_error_errno(r, "Failed to set priority to device monitor: %m");
         
        +        log_info("POSITRON-UDEV READY manager-monitor-started");
                 return 0;
         }
         
        @@ -1176,6 +1244,8 @@
                         return 0;
                 }
         
        +        positron_tty_observe(worker->event ? worker->event->dev : NULL, 6, 0, sender.pid, 0, 0,
        +                             strv_contains(l, "PROCESSED=1"), strv_contains(l, "TRY_AGAIN=1"));
                 _cleanup_(event_enter_processedp) Event *event = worker_detach_event(worker);
         
                 if (strv_contains(l, "TRY_AGAIN=1")) {
      '') ];
    });
  ttyEventParser = pkgs.writeText "positron-tty-events.awk" ''
    function emit(message) {
      if (output_bytes + length(message) + 32 > 3968) fail("output-limit")
      print "positron-tty-event-observation " message
      output_bytes += length(message) + 32
      fflush()
    }
    function fail(reason) {
      failed = 1
      print "positron-tty-event-observation INCOMPLETE " reason
      fflush()
      exit 1
    }
    function reset_event() {
      delete values
      delete seen
      device = source = stamp = ""
      invalid = 0
    }
    function finish_event() {
      if (source == "") return
      if (++events > 4096) fail("event-limit")
      if (device != "") {
        if (invalid || !("ACTION" in values) || !("SEQNUM" in values)) fail("invalid-target-event")
        if (++target_events > 32) fail("target-event-limit")
        emit("EVENT source=" source " device=" device " time=" stamp " action=" values["ACTION"] \
          " seq=" values["SEQNUM"] " initialized=" values["USEC_INITIALIZED"] \
          " processing=" values["ID_PROCESSING"] " ready=" values["SYSTEMD_READY"] \
          " systemd_tag=" values["TAGS"] " current_systemd_tag=" values["CURRENT_TAGS"] \
          " worker_failed=" values["UDEV_WORKER_FAILED"] " errno=" values["UDEV_WORKER_ERRNO"] \
          " exit_status=" values["UDEV_WORKER_EXIT_STATUS"] " signal=" values["UDEV_WORKER_SIGNAL"])
      }
      reset_event()
    }
    {
      input_bytes += length($0) + 1
      if (length($0) > 4096 || input_bytes > 1048576 || NR > 16384) fail("input-limit")
    }
    $0 == "POSITRON_MONITOR_DIAGNOSTIC" {
      if (!loss) emit("INCOMPLETE monitor-diagnostic")
      loss = 1
      next
    }
    !ready && $0 == "UDEV - the event which udev sends out after rule processing" { udev = 1; next }
    !ready && $0 == "KERNEL - the kernel uevent" { kernel = 1; next }
    !ready && $0 == "" && udev && kernel {
      if (system("timeout --kill-after=1s 2s systemd-notify --ready >/dev/null 2>&1") != 0) fail("notify-unavailable")
      ready = 1
      emit("SUBSCRIBED stage2-only")
      next
    }
    !ready { next }
    /^(KERNEL|UDEV) *\[[0-9]+\.[0-9]+\] / {
      finish_event()
      source = substr($0, 1, 6)
      gsub(/ /, "", source)
      match($0, /\[[0-9]+\.[0-9]+\]/)
      stamp = substr($0, RSTART + 1, RLENGTH - 2)
      next
    }
    $0 == "" { finish_event(); next }
    source != "" && index($0, "=") {
      separator = index($0, "=")
      key = substr($0, 1, separator - 1)
      value = substr($0, separator + 1)
      if (key == "DEVNAME") {
        if (++seen[key] > 1) invalid = 1
        if (value == "/dev/hvc0" || value == "hvc0") device = "hvc0"
        else if (value == "/dev/ttyAMA0" || value == "ttyAMA0") device = "ttyAMA0"
      } else if (key == "ACTION") {
        if (++seen[key] > 1 || value !~ /^(add|remove|change|move|online|offline|bind|unbind)$/) invalid = 1
        else values[key] = value
      } else if (key == "TAGS" || key == "CURRENT_TAGS") {
        if (++seen[key] > 1) invalid = 1
        values[key] = value ~ /(^|:)systemd(:|$)/ ? 1 : 0
      } else if (key ~ /^(SEQNUM|USEC_INITIALIZED|ID_PROCESSING|SYSTEMD_READY|UDEV_WORKER_FAILED|UDEV_WORKER_ERRNO|UDEV_WORKER_EXIT_STATUS|UDEV_WORKER_SIGNAL)$/) {
        if (++seen[key] > 1 || value !~ /^[0-9]+$/ || length(value) > 20) invalid = 1
        else values[key] = value
      }
    }
    END {
      if (!failed && !ready) fail("subscription-unavailable")
      if (!failed) { finish_event(); emit("PARSER-END"); if (loss) exit 1; }
    }
  '';
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
    # The early subscriber gates the normal stage2 trigger only until subscribed.
    # Initrd events are outside this history, and subscription/ptrace can perturb timing.
    # Preserve the multicall daemon basename and its own same-source shared library.
    # This instrumentation is observation-only and does not qualify original udevd.
    systemd.services.systemd-udevd.serviceConfig.ExecStart = lib.mkForce [
      ""
      "${diagnosticSystemd}/lib/systemd/systemd-udevd"
    ];
    systemd.services.positron-tty-event-observation = {
      wantedBy = [ "sysinit.target" ];
      before = [ "systemd-udev-trigger.service" ];
      after = [ "systemd-journald.socket" ];
      unitConfig.DefaultDependencies = false;
      path = [ pkgs.coreutils pkgs.systemd pkgs.gawk ];
      serviceConfig = {
        Type = "notify";
        NotifyAccess = "all";
        TimeoutStartSec = 15;
        TimeoutStopSec = 1;
        RuntimeMaxSec = 400;
        KillMode = "control-group";
        StandardOutput = "journal";
        StandardError = "journal";
      };
      script = ''
        set +e
        monitor_pid=""
        parser_pid=""
        cleanup() {
          trap - EXIT TERM INT
          for pid in "$monitor_pid" "$parser_pid"; do
            if test -n "$pid"; then kill -TERM "$pid" 2>/dev/null || true; fi
          done
          for pid in "$monitor_pid" "$parser_pid"; do
            if test -n "$pid"; then wait "$pid" 2>/dev/null; fi
          done
        }
        trap cleanup EXIT
        trap 'echo "positron-tty-event-observation INCOMPLETE interrupted"; exit 143' TERM INT
        exec {events}< <(exec timeout --kill-after=1s 400s udevadm monitor --kernel --udev --subsystem-match=tty --property 2> >(
          if LC_ALL=C IFS= read -r -n 1 -d ""; then
            printf '\nPOSITRON_MONITOR_DIAGNOSTIC\n'
            cat >/dev/null
          fi
        ))
        monitor_pid=$!
        awk -f ${ttyEventParser} <&"$events" &
        parser_pid=$!
        exec {events}<&-
        wait "$parser_pid"
        parser_status=$?
        parser_pid=""
        kill -TERM "$monitor_pid" 2>/dev/null || true
        wait "$monitor_pid"
        monitor_status=$?
        monitor_pid=""
        if test "$parser_status" -eq 0 && test "$monitor_status" -eq 124; then
          echo "positron-tty-event-observation WINDOW-END"
        else
          echo "positron-tty-event-observation UNAVAILABLE-OR-LOSS parser=$parser_status monitor=$monitor_status"
          exit 1
        fi
      '';
    };
    # Late serial-visible observations also run without the backdoor and do not gate devices.
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
