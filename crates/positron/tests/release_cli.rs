use std::process::Command;
#[test]
fn native_release_cli_is_available_without_database_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["release", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("release verify")
    );
}

#[path = "../../positron-release/tests/support/mod.rs"]
mod support;
use positron_release::*;
fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_positron"))
        .arg("release")
        .args(arguments)
        .output()
        .unwrap()
}
fn path(path: &std::path::Path) -> &str {
    path.to_str().unwrap()
}
fn installed(fixture: &support::Fixture, now: u64) -> (InstalledReleaseTrust, TrustSnapshot) {
    let key = fixture.key();
    let snapshot = TrustSnapshot {
        format: 1,
        sequence: 2,
        current_version: fixture.inventory.version,
        issued_unix: now - 60,
        expires_unix: now + 3600,
        identities: [
            KeyPurpose::Release,
            KeyPurpose::Publisher,
            KeyPurpose::Transparency,
        ]
        .into_iter()
        .map(|purpose| SigningIdentity {
            public_key: key,
            purpose,
            not_before_unix: 100,
            expires_unix: now + 3600,
        })
        .collect(),
        native_publishers: fixture.native_publishers(),
        revoked_keys: vec![],
        revoked_manifests: vec![],
        revoked_artifacts: vec![],
    };
    (
        InstalledReleaseTrust {
            format: 1,
            root: InstalledProjectTrustRoot {
                public_key: key,
                minimum_sequence: 2,
            },
            release_signer: key,
            signed_snapshot: snapshot.sign(&fixture.pair).unwrap(),
        },
        snapshot,
    )
}
#[test]
fn native_cli_constructs_attaches_and_verifies_a_complete_offline_fixture() {
    let mut fixture = support::Fixture::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    fixture.inventory.security_support.expires_unix = now + 3600;
    let (_signed, _prepared) = fixture.published();
    let input = fixture.root.join("input.json");
    let output = fixture.root.join("constructed");
    let trust_file = fixture.root.join("trust.json");
    let (trust, _snapshot) = installed(&fixture, now);
    write_release_file(&trust_file, &trust.canonical_bytes().unwrap()).unwrap();
    std::fs::write(
        &input,
        serde_json::to_vec_pretty(&fixture.inventory).unwrap(),
    )
    .unwrap();
    let constructed = run(&[
        "construct",
        "--inventory",
        path(&input),
        "--bundle",
        path(&fixture.root.join("bundle")),
        "--rebuild",
        path(&fixture.rebuild),
        "--out",
        path(&output),
    ]);
    assert!(
        constructed.status.success(),
        "{}",
        String::from_utf8_lossy(&constructed.stderr)
    );
    assert!(
        String::from_utf8(constructed.stdout)
            .unwrap()
            .contains("unsigned-construction")
    );
    let signature_file = fixture.root.join("signature.bin");
    let signed_file = fixture.root.join("signed.manifest");
    std::fs::write(
        &signature_file,
        fixture
            .pair
            .sign(&std::fs::read(output.join("signing-message.bin")).unwrap())
            .as_ref(),
    )
    .unwrap();
    let attached = run(&[
        "attach",
        "--manifest",
        path(&output.join("manifest.json")),
        "--signature",
        path(&signature_file),
        "--trust",
        path(&trust_file),
        "--out",
        path(&signed_file),
    ]);
    assert!(
        attached.status.success(),
        "{}",
        String::from_utf8_lossy(&attached.stderr)
    );
    let verified = run(&[
        "verify",
        "--manifest",
        path(&signed_file),
        "--inventory",
        path(&output.join("inventory.json")),
        "--trust",
        path(&trust_file),
        "--bundle",
        path(&fixture.root.join("bundle")),
        "--rebuild",
        path(&fixture.rebuild),
        "--target",
        "linux-x86_64",
    ]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(report["state"], "verified-complete-published-set");
    assert_eq!(report["artifacts"], 35);
    assert!(report["verified_at_unix_seconds"].as_u64().unwrap() >= now);
    assert!(
        !run(&[
            "attach",
            "--manifest",
            path(&output.join("manifest.json")),
            "--signature",
            path(&signature_file),
            "--trust",
            path(&trust_file),
            "--out",
            path(&signed_file)
        ])
        .status
        .success()
    );
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&trust_file, std::fs::Permissions::from_mode(0o666)).unwrap();
    let rejected = fixture.root.join("untrusted.manifest");
    assert!(
        !run(&[
            "attach",
            "--manifest",
            path(&output.join("manifest.json")),
            "--signature",
            path(&signature_file),
            "--trust",
            path(&trust_file),
            "--out",
            path(&rejected)
        ])
        .status
        .success()
    );
    assert!(!rejected.exists());
}
#[test]
fn native_cli_prepares_and_authenticates_a_root_signed_trust_update() {
    let fixture = support::Fixture::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (trust, snapshot) = installed(&fixture, now);
    let source = fixture.root.join("snapshot.json");
    let message = fixture.root.join("message.bin");
    let signature = fixture.root.join("signature.bin");
    let root = fixture.root.join("root.json");
    let output = fixture.root.join("snapshot.signed");
    std::fs::write(&source, snapshot.canonical_bytes().unwrap()).unwrap();
    std::fs::write(&root, serde_json::to_vec(&trust.root).unwrap()).unwrap();
    assert!(
        run(&[
            "trust-message",
            "--snapshot",
            path(&source),
            "--out",
            path(&message)
        ])
        .status
        .success()
    );
    std::fs::write(
        &signature,
        fixture
            .pair
            .sign(&std::fs::read(&message).unwrap())
            .as_ref(),
    )
    .unwrap();
    let result = run(&[
        "trust-attach",
        "--snapshot",
        path(&source),
        "--signature",
        path(&signature),
        "--root",
        path(&root),
        "--out",
        path(&output),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        trust
            .root
            .verify(&std::fs::read(output).unwrap(), now)
            .unwrap()
            .sequence(),
        2
    );
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o666)).unwrap();
    let refused = run(&[
        "trust-attach",
        "--snapshot",
        path(&source),
        "--signature",
        path(&signature),
        "--root",
        path(&root),
        "--out",
        path(&fixture.root.join("untrusted-snapshot.signed")),
    ]);
    assert!(
        !refused.status.success(),
        "writable installed root cannot authorize a snapshot"
    );
}
#[test]
fn native_binary_itself_passes_inspection_with_an_independent_file_checksum() {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_positron"));
    let mut file = std::fs::File::open(executable).unwrap();
    let mut buffer = [0; 65536];
    let mut hash = Sha256::new();
    let mut size = 0;
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        size += read;
    }
    let output = run(&[
        "inspect",
        "--directory",
        path(executable.parent().unwrap()),
        "--file",
        executable.file_name().unwrap().to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["sha256"], support::hex(&hash.finalize()));
    assert_eq!(report["size"], size);
}
#[test]
fn malformed_cli_inputs_refuse_without_creating_or_rendering_secret_material() {
    for arguments in [
        vec![],
        vec!["unknown"],
        vec!["inspect", "--directory"],
        vec!["inspect", "--file", "x", "--file", "y"],
        vec!["inspect", "--unknown", "value"],
        vec!["verify", "--target", "windows-x86_64"],
        vec!["--help", "extra"],
    ] {
        let result = run(&arguments);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }
}
