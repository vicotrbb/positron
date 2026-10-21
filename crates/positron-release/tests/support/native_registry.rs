//! Native package bytes and private test authorities; never live registry evidence.
use super::keyless::{self, KeylessFixture};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use positron_release::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use signed_note::{Note, StandardSigner};
use std::io::{Cursor, Write};

pub struct NativeArtifactFixture {
    pub surface: Surface,
    pub filename: String,
    pub contents: Vec<u8>,
    pub payload: Option<Vec<u8>>,
    pub registry: String,
    pub subject: String,
    pub revision: Option<String>,
    pub policy: NativePublisherPolicy,
    pub proof: Value,
}

pub fn fixtures(version: &str, source_commit: &str) -> Vec<NativeArtifactFixture> {
    let crate_name = "positron-sdk";
    let cargo = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"{version}\"\nedition = \"2024\"\n"
    );
    let vcs = serde_json::to_vec(
        &json!({"git":{"sha1":source_commit,"dirty":false},"path_in_vcs":"sdk/rust"}),
    )
    .unwrap();
    let contents = tar_gzip(
        &format!("{crate_name}-{version}"),
        &[
            ("Cargo.toml", cargo.as_bytes()),
            (".cargo_vcs_info.json", &vcs),
            ("src/lib.rs", b"pub struct Client;\n"),
        ],
    );
    let rust = artifact(
        Surface::SdkRust,
        format!("{crate_name}-{version}.crate"),
        contents.clone(),
        "https://crates.io",
        format!("pkg:cargo/{crate_name}@{version}"),
        None,
        NativePublisherPolicy::CratesIo {
            repository: "vicotrbb/positron".into(),
        },
        json!({"profile":"crates-io-oidc-upload-no-offline-receipt-v1","index":{"name":crate_name,"vers":version,"cksum":hex(&Sha256::digest(&contents)),"yanked":false},"trustpub":{"provider":"github","repository":"vicotrbb/positron","run_id":"28987632348","sha":source_commit}}),
    );

    let module = "github.com/vicotrbb/positron/sdk/go";
    let go_version = format!("v{version}");
    let go_mod = format!("module {module}\n\ngo 1.24.0\n");
    let source = b"package positron\n\ntype Client struct{}\n";
    let prefix = format!("{module}@{go_version}");
    let files = [
        (format!("{prefix}/go.mod"), go_mod.as_bytes()),
        (format!("{prefix}/sdk.go"), source.as_slice()),
    ];
    let contents = zip(&files
        .iter()
        .map(|(path, data)| (path.as_str(), *data))
        .collect::<Vec<_>>());
    let text = format!(
        "{module} {go_version} {}\n{module} {go_version}/go.mod {}\n",
        h1(&files),
        h1(&[("go.mod".into(), go_mod.as_bytes())])
    );
    let key = Ed25519KeyPair::from_seed_unchecked(&[45; 32]).unwrap();
    let name = "sumdb.test.invalid";
    let mut public = vec![1];
    public.extend(key.public_key().as_ref());
    let id = signed_note::key_id(name, &public);
    let verifier_key = format!("{name}+{id:08x}+{}", B64.encode(public));
    let mut private = vec![1];
    private.extend([45; 32]);
    let signer = StandardSigner::new(&format!(
        "PRIVATE+KEY+{name}+{id:08x}+{}",
        B64.encode(private)
    ))
    .unwrap();
    let mut leaf = vec![0];
    leaf.extend(text.as_bytes());
    let checkpoint_text = format!(
        "go.sum database tree\n1\n{}\n",
        B64.encode(Sha256::digest(leaf))
    );
    let mut note = Note::new(checkpoint_text.as_bytes(), &[]).unwrap();
    note.add_sigs(&[&signer]).unwrap();
    let checkpoint = String::from_utf8(note.to_bytes()).unwrap();
    let root = json!({"verifier_key":verifier_key,"checkpoint":checkpoint});
    let go = artifact(
        Surface::SdkGo,
        format!("positron-sdk-go-{version}.zip"),
        contents,
        "https://proxy.golang.org",
        format!("pkg:golang/{module}@{version}"),
        None,
        NativePublisherPolicy::GoChecksum {
            trusted_root_sha256: Sha256::digest(serde_json::to_vec(&root).unwrap()).into(),
        },
        json!({"trustedRoot":root,"sumdb":{"record":{"id":0,"text":text},"checkpoint":checkpoint,"inclusion":[],"consistency":[]}}),
    );

    let package_json = serde_json::to_vec(
        &json!({"name":"@positron/sdk","version":version,"type":"module","exports":"./index.js"}),
    )
    .unwrap();
    let npm_bytes = tar_gzip(
        "package",
        &[
            ("package.json", &package_json),
            ("index.js", b"export class Client {}\n"),
        ],
    );
    let npm = keyless_artifact(
        Surface::SdkTypeScript,
        format!("positron-sdk-{version}.tgz"),
        npm_bytes,
        "https://registry.npmjs.org",
        format!("pkg:npm/%40positron/sdk@{version}"),
        NativePublicationKind::Npm,
        keyless::REPOSITORY,
        source_commit,
        None,
    );
    let metadata = format!("Metadata-Version: 2.4\nName: positron-sdk\nVersion: {version}\n");
    let dist_info = format!("positron_sdk-{version}.dist-info");
    let wheel=b"Wheel-Version: 1.0\nGenerator: positron-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n";
    let init = b"class Client:\n    pass\n";
    let mut wheel_files = vec![
        ("positron_sdk/__init__.py".into(), init.to_vec()),
        (format!("{dist_info}/METADATA"), metadata.into_bytes()),
        (format!("{dist_info}/WHEEL"), wheel.to_vec()),
    ];
    let mut record = String::new();
    for (name, bytes) in &wheel_files {
        record.push_str(&format!(
            "{name},sha256={},{}\n",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
            bytes.len()
        ));
    }
    record.push_str(&format!("{dist_info}/RECORD,,\n"));
    wheel_files.push((format!("{dist_info}/RECORD"), record.into_bytes()));
    let python_filename = format!("positron_sdk-{version}-py3-none-any.whl");
    let python = keyless_artifact(
        Surface::SdkPython,
        python_filename.clone(),
        zip(&wheel_files
            .iter()
            .map(|(path, data)| (path.as_str(), data.as_slice()))
            .collect::<Vec<_>>()),
        "https://pypi.org",
        python_filename,
        NativePublicationKind::PyPi,
        keyless::REPOSITORY,
        source_commit,
        None,
    );
    vec![
        rust,
        go,
        npm,
        python,
        homebrew(b"unmeasured local formula fixture".to_vec()),
    ]
}

pub(super) fn homebrew(contents: Vec<u8>) -> NativeArtifactFixture {
    let tap_repository = "https://github.com/vicotrbb/homebrew-positron";
    let tap_commit = "a93b5bd7d3985809503963ae400594ea16df31cf";
    keyless_artifact(
        Surface::Homebrew,
        "positron.rb".into(),
        contents,
        tap_repository,
        "positron.rb".into(),
        NativePublicationKind::HomebrewTap,
        tap_repository,
        tap_commit,
        Some(tap_commit.into()),
    )
}

#[allow(clippy::too_many_arguments)]
fn artifact(
    surface: Surface,
    filename: String,
    contents: Vec<u8>,
    registry: &str,
    subject: String,
    revision: Option<String>,
    policy: NativePublisherPolicy,
    proof: Value,
) -> NativeArtifactFixture {
    NativeArtifactFixture {
        surface,
        filename,
        payload: Some(contents.clone()),
        contents,
        registry: registry.into(),
        subject,
        revision,
        policy,
        proof,
    }
}

#[allow(clippy::too_many_arguments)]
fn keyless_artifact(
    surface: Surface,
    filename: String,
    contents: Vec<u8>,
    registry: &str,
    subject: String,
    kind: NativePublicationKind,
    repository: &str,
    commit: &str,
    revision: Option<String>,
) -> NativeArtifactFixture {
    let identity = format!(
        "{repository}/.github/workflows/release.yml@{}",
        keyless::REF
    );
    let authority = KeylessFixture::for_workflow(&identity, repository, commit);
    let root = authority.trusted_root();
    let digest = if kind == NativePublicationKind::Npm {
        json!({"sha512":hex(&Sha512::digest(&contents))})
    } else {
        json!({"sha256":hex(&Sha256::digest(&contents))})
    };
    let mut statement = json!({"_type":"https://in-toto.io/Statement/v1","subject":[{"name":subject,"digest":digest}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":if kind==NativePublicationKind::Npm {"https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"} else {"https://actions.github.io/buildtypes/workflow/v1"},"externalParameters":{"workflow":{"repository":repository,"ref":keyless::REF,"path":".github/workflows/release.yml"}},"resolvedDependencies":[{"uri":format!("git+{repository}@{}",keyless::REF),"digest":{"gitCommit":commit}}]}}});
    if kind == NativePublicationKind::PyPi {
        statement["predicateType"] = json!("https://docs.pypi.org/attestations/publish/v1");
        statement["predicate"] = json!({});
    }
    let bundle = authority.bundle(&serde_json::to_vec(&statement).unwrap());
    let bundle = if kind == NativePublicationKind::PyPi {
        json!({"version":1,"envelope":{"statement":bundle["dsseEnvelope"]["payload"],"signature":bundle["dsseEnvelope"]["signatures"][0]["sig"]},"verification_material":{"certificate":bundle["verificationMaterial"]["certificate"]["rawBytes"],"transparency_entries":bundle["verificationMaterial"]["tlogEntries"]}})
    } else {
        bundle
    };
    let policy = NativePublisherPolicy::Keyless(NativeKeylessPublisher {
        kind,
        trusted_root_sha256: Sha256::digest(serde_json::to_vec(&root).unwrap()).into(),
        identity,
        issuer: keyless::ISSUER.into(),
        repository: repository.into(),
        source_ref: keyless::REF.into(),
    });
    artifact(
        surface,
        filename,
        contents,
        registry,
        subject,
        revision,
        policy,
        json!({"trustedRoot":root,"bundle":bundle}),
    )
}
fn tar_gzip(prefix: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut archive = tar::Builder::new(gzip);
    for (path, contents) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, format!("{prefix}/{path}"), *contents)
            .unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap()
}
fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, contents) in files {
        archive
            .start_file(
                *path,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        archive.write_all(contents).unwrap();
    }
    archive.finish().unwrap().into_inner()
}
fn h1(files: &[(String, &[u8])]) -> String {
    let mut files = files.to_vec();
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut summary = String::new();
    for (path, contents) in files {
        summary.push_str(&format!("{}  {path}\n", hex(&Sha256::digest(contents))));
    }
    format!("h1:{}", B64.encode(Sha256::digest(summary)))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
