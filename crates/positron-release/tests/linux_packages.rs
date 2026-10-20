//! Native package-manager qualification; run in an isolated Linux fixture as root.
//! The package path and its independently built native archive are explicit inputs.
#![cfg(target_os = "linux")]
use std::{fs, path::Path, process::Command};

fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .env("LC_ALL", "C")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{program}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
#[ignore = "requires root in an isolated Debian/RPM fixture, POSITRON_TEST_PACKAGE, POSITRON_TEST_ARCHIVE and RPM key when applicable"]
fn native_manager_installs_exact_payload_and_retains_owner_configuration_data_and_keys() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let package = std::env::var("POSITRON_TEST_PACKAGE").unwrap();
    let archive = std::env::var("POSITRON_TEST_ARCHIVE").unwrap();
    let debian = package.ends_with(".deb");
    if !debian {
        let public = std::env::var("POSITRON_TEST_RPM_KEY").unwrap();
        let keyring =
            std::env::temp_dir().join(format!("positron-package-keyring-{}", std::process::id()));
        fs::create_dir(&keyring).unwrap();
        let keyring_path = keyring.to_str().unwrap();
        run("rpmkeys", &["--dbpath", keyring_path, "--import", &public]);
        assert!(
            run(
                "rpmkeys",
                &["--dbpath", keyring_path, "--checksig", &package]
            )
            .contains("signatures OK")
        );
        let damaged = keyring.join("damaged.rpm");
        let mut bytes = fs::read(&package).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&damaged, bytes).unwrap();
        let rejected = Command::new("rpmkeys")
            .args([
                "--dbpath",
                keyring_path,
                "--checksig",
                damaged.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!rejected.status.success());
        fs::remove_dir_all(keyring).unwrap();
    }
    let install = || {
        if debian {
            run("dpkg", &["--install", &package]);
        } else {
            run("rpm", &["--upgrade", "--replacepkgs", &package]);
        }
    };
    install();
    let binary = fs::read("/usr/bin/positron").unwrap();
    let mut contents = tar::Archive::new(flate2::read::GzDecoder::new(
        fs::File::open(archive).unwrap(),
    ));
    let mut matched = false;
    for entry in contents.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.path().unwrap() == Path::new("positron/bin/positron") {
            use std::io::Read;
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            assert_eq!(binary, bytes);
            matched = true;
        }
    }
    assert!(matched);
    assert_eq!(
        fs::read_to_string("/etc/positron/positron.toml").unwrap(),
        positron_config::generated_example()
    );
    let uid: u32 = run("id", &["-u", "positron"]).trim().parse().unwrap();
    assert_ne!(uid, 0);
    let identity = run("getent", &["passwd", "positron"]);
    let shell = identity.trim().rsplit(':').next().unwrap();
    run("usermod", &["--shell", "/bin/sh", "positron"]);
    let rejected = if debian {
        Command::new("dpkg")
            .args(["--install", &package])
            .output()
            .unwrap()
    } else {
        Command::new("rpm")
            .args(["--upgrade", "--replacepkgs", &package])
            .output()
            .unwrap()
    };
    run("usermod", &["--shell", shell, "positron"]);
    assert!(
        !rejected.status.success(),
        "unsafe pre-existing identity must reject installation"
    );
    install();
    for hazard in ["duplicate_uid", "supplementary_group", "primary_group"] {
        let uid_text = uid.to_string();
        match hazard {
            "duplicate_uid" => {
                run(
                    "useradd",
                    &[
                        "--non-unique",
                        "--uid",
                        &uid_text,
                        "--shell",
                        "/usr/sbin/nologin",
                        "positron-alias",
                    ],
                );
            },
            "supplementary_group" => {
                run("useradd", &["--groups", "positron", "positron-alias"]);
            },
            _ => {
                run("useradd", &["--gid", "positron", "positron-alias"]);
            },
        }
        let rejected = if debian {
            Command::new("dpkg")
                .args(["--install", &package])
                .output()
                .unwrap()
        } else {
            Command::new("rpm")
                .args(["--upgrade", "--replacepkgs", &package])
                .output()
                .unwrap()
        };
        run("userdel", &["positron-alias"]);
        assert!(
            !rejected.status.success(),
            "shared identity {hazard} must reject installation"
        );
        install();
    }
    for path in ["/var/lib/positron", "/var/lib/positron-secrets"] {
        let metadata = fs::metadata(path).unwrap();
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }
    assert_eq!(
        fs::metadata("/etc/positron").unwrap().permissions().mode() & 0o777,
        0o750
    );
    assert_eq!(
        fs::metadata("/etc/positron/positron.toml")
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    run(
        "runuser",
        &[
            "-u",
            "positron",
            "--",
            "/usr/bin/positron",
            "config",
            "validate",
            "--config",
            "/etc/positron/positron.toml",
        ],
    );
    fs::write("/var/lib/positron/retained", b"retained-data").unwrap();
    fs::write("/var/lib/positron-secrets/retained", b"retained-key").unwrap();
    let config = format!(
        "{}\n# operator retained setting\n",
        positron_config::generated_example()
    );
    fs::write("/etc/positron/positron.toml", &config).unwrap();
    install();
    assert_eq!(
        fs::read_to_string("/etc/positron/positron.toml").unwrap(),
        config
    );
    if debian {
        run("dpkg", &["--purge", "positron"]);
    } else {
        run("rpm", &["--erase", "positron"]);
    }
    assert!(!Path::new("/usr/bin/positron").exists());
    assert_eq!(
        fs::read("/var/lib/positron/retained").unwrap(),
        b"retained-data"
    );
    assert_eq!(
        fs::read("/var/lib/positron-secrets/retained").unwrap(),
        b"retained-key"
    );
    assert_eq!(run("id", &["-u", "positron"]).trim(), uid.to_string());
    install();
    assert_eq!(
        fs::read("/var/lib/positron/retained").unwrap(),
        b"retained-data"
    );
    assert_eq!(
        fs::read("/var/lib/positron-secrets/retained").unwrap(),
        b"retained-key"
    );
    fs::remove_file("/var/lib/positron/retained").unwrap();
    fs::remove_file("/var/lib/positron-secrets/retained").unwrap();
}

#[test]
#[ignore = "requires native dpkg/rpmbuild, POSITRON_TEST_ARCHIVE and POSITRON_TEST_PACKAGE_TARGET"]
fn native_packagers_reproduce_bytes_in_independent_directories() {
    let archive = std::env::var("POSITRON_TEST_ARCHIVE").unwrap();
    let target = std::env::var("POSITRON_TEST_PACKAGE_TARGET").unwrap();
    let recipe = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/linux/build.sh");
    let root = std::env::temp_dir().join(format!("positron-packages-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    for kind in ["deb", "rpm"] {
        let mut results = Vec::new();
        for build in ["first", "independent"] {
            let output = root.join(format!("{kind}-{build}"));
            run(
                recipe.to_str().unwrap(),
                &[kind, &archive, "0.0.0", &target, output.to_str().unwrap()],
            );
            let files = fs::read_dir(output)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(files.len(), 1);
            results.push(fs::read(files.first().unwrap().path()).unwrap());
        }
        assert_eq!(
            results.first(),
            results.get(1),
            "{kind} independent package bytes"
        );
    }
    let output = root.join("wrong-target");
    let wrong = if target == "aarch64" {
        "x86_64"
    } else {
        "aarch64"
    };
    let status = Command::new(recipe)
        .args(["deb", &archive, "0.0.0", wrong, output.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires an isolated booted Linux systemd fixture with the real package installed"]
fn systemd_unit_initializes_explicitly_runs_non_root_and_drains_before_restart() {
    use std::{
        io::{Read, Write},
        net::TcpStream,
        os::unix::fs::MetadataExt,
        time::{Duration, Instant},
    };
    assert!(Path::new("/run/systemd/system").is_dir());
    let config = positron_config::generated_example()
        .replace("_transport = \"tls\"", "_transport = \"plaintext\"");
    fs::write("/etc/positron/positron.toml", format!("{config}\n[security]\nlocal_key_file = \"/var/lib/positron-secrets/local-root-key.v1\"\n")).unwrap();
    run(
        "runuser",
        &[
            "-u",
            "positron",
            "--",
            "/usr/bin/positron",
            "config",
            "validate",
            "--config",
            "/etc/positron/positron.toml",
        ],
    );
    let override_dir = "/run/systemd/system/positron.service.d";
    fs::create_dir_all(override_dir).unwrap();
    let initialization = format!("{override_dir}/initialize.conf");
    fs::write(&initialization, "[Service]\nExecStart=\nExecStart=/usr/bin/positron serve --init-if-empty --config /etc/positron/positron.toml\n").unwrap();
    run("systemctl", &["daemon-reload"]);
    for first in [true, false] {
        run("systemctl", &["start", "positron.service"]);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let ready = TcpStream::connect("127.0.0.1:13133").ok().is_some_and(|mut stream| {
                stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                stream.write_all(b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                let mut response = String::new();
                stream.take(8192).read_to_string(&mut response).is_ok() && response.starts_with("HTTP/1.1 200 ")
            });
            if ready {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "systemd service did not become ready"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        let pid = run(
            "systemctl",
            &["show", "positron.service", "--property=MainPID", "--value"],
        );
        let owner = fs::metadata(format!("/proc/{}", pid.trim())).unwrap().uid();
        assert_ne!(owner, 0);
        assert_eq!(owner.to_string(), run("id", &["-u", "positron"]).trim());
        run("systemctl", &["stop", "positron.service"]);
        assert_eq!(
            run(
                "systemctl",
                &[
                    "show",
                    "positron.service",
                    "--property=ExecMainStatus",
                    "--value"
                ]
            )
            .trim(),
            "0"
        );
        run(
            "runuser",
            &[
                "-u",
                "positron",
                "--",
                "/usr/bin/positron",
                "verify",
                "--offline",
                "--config",
                "/etc/positron/positron.toml",
            ],
        );
        if first {
            fs::remove_file(&initialization).unwrap();
            run("systemctl", &["daemon-reload"]);
        }
    }
}
