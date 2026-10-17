#![no_main]
use libfuzzer_sys::fuzz_target;
use positron_release::*;
use std::io::{Cursor, Read, Write};
#[path = "../../crates/positron-release/tests/support/mod.rs"]
mod support;

// Start with authenticated, structurally valid native packages. Re-sign only
// the project's enclosing publication statement so mutations reach each native
// parser/verifier rather than stopping at the outer signature.
fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let mut fixture = support::Fixture::new();
    let selection = usize::from(data.first().copied().unwrap_or(0));
    let index = selection % fixture.inventory.artifacts.len();
    let selected = fixture.inventory.artifacts[index].clone();
    let package_mutated = data.len() > 1 && mutate_package(&mut fixture, index, data);
    if package_mutated
        && construct_release(
            &fixture.inventory,
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            &[],
            vec![],
        )
        .is_err()
    {
        // Malformed decoded framing or detected credential forms are normal refusals.
        return;
    }
    let (signed, prepared) = fixture.published_with(
        |artifact, statement| {
            if artifact.file != selected.file || data.len() < 2 {
                return;
            }
            let parameters = &mut statement["predicate"]["buildDefinition"]["externalParameters"];
            if package_mutated {
                if artifact.surface == Surface::SdkRust {
                    parameters["native"]["index"]["cksum"] = support::hex(
                        &fixture
                            .inventory
                            .file(&artifact.file)
                            .unwrap()
                            .identity
                            .sha256,
                    )
                    .into();
                }
                return;
            }
            let field = if matches!(artifact.surface, Surface::OciImage | Surface::OciIndex) {
                "cosign"
            } else {
                "native"
            };
            let mut bytes = serde_json::to_vec(&parameters[field]).expect("fixture JSON");
            for (index, value) in data.iter().copied().enumerate().skip(1) {
                let offset = (index * 257 + usize::from(value)) % bytes.len();
                bytes[offset] ^= value.max(1);
            }
            parameters[field] = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        },
        |_, _| {},
    );
    let result = verify_release(
        &signed,
        &prepared.inventory_bytes,
        fixture.key(),
        &fixture.trust(),
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        "linux-x86_64",
        &[],
    );
    if data.len() < 2 {
        assert!(result.is_ok(), "unmutated native corpus must qualify");
    }
    let mutate = |bytes: &mut Vec<u8>| {
        for (index, value) in data.iter().copied().enumerate().skip(1) {
            let offset = (index * 257 + usize::from(value)) % bytes.len();
            bytes[offset] ^= value.max(1);
        }
    };
    let mut inventory = fixture
        .inventory
        .canonical_bytes()
        .expect("valid inventory seed");
    mutate(&mut inventory);
    let _inventory = ReleaseInventory::from_bytes(&inventory);
    let mut snapshot = Vec::new();
    let mut signed_snapshot = Vec::new();
    let _authority = fixture.trust_with(|value| {
        snapshot = value.canonical_bytes().expect("valid snapshot seed");
        signed_snapshot = value.sign(&fixture.pair).expect("signed snapshot seed");
    });
    mutate(&mut snapshot);
    let _trust = TrustSnapshot::from_bytes(&snapshot);
    let installed = InstalledReleaseTrust {
        format: 1,
        root: InstalledProjectTrustRoot {
            public_key: fixture.key(),
            minimum_sequence: 2,
        },
        release_signer: fixture.key(),
        signed_snapshot,
    };
    let mut bytes = installed
        .canonical_bytes()
        .expect("valid installed trust seed");
    mutate(&mut bytes);
    if let Ok(installed) = InstalledReleaseTrust::from_bytes(&bytes) {
        let _verified = installed.verify(support::keyless::NOW as u64);
    }
    let _raw_inventory = ReleaseInventory::from_bytes(data);
    let _raw_trust = TrustSnapshot::from_bytes(data);
    std::fs::write(fixture.root.join("bundle").join("fuzz-archive"), data).expect("fuzz input");
    let _decoded = scan_release_contents(&fixture.root.join("bundle"), "fuzz-archive", &[]);
});

// Mutate native package boundaries while preserving the independently bound
// payload/wrapper framing needed to reach them through the public verifier.
fn mutate_package(fixture: &mut support::Fixture, index: usize, data: &[u8]) -> bool {
    let artifact = fixture.inventory.artifacts[index].clone();
    let path = fixture.root.join("bundle").join(&artifact.file);
    let mut bytes = std::fs::read(path).unwrap();
    let mut payload = None;
    match artifact.surface {
        Surface::SdkDotNet => {
            let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
            let member = archive.by_name(".signature.p7s").unwrap();
            let start = member.data_start().unwrap() as usize;
            let end = start + member.size() as usize;
            let local = member.header_start() as usize;
            let central = member.central_header_start() as usize;
            drop(member);
            drop(archive);
            mutate(&mut bytes[start..end], data);
            let crc = crc32fast::hash(&bytes[start..end]).to_le_bytes();
            bytes[local + 14..local + 18].copy_from_slice(&crc);
            bytes[central + 16..central + 20].copy_from_slice(&crc);
            payload = Some(
                std::fs::read(
                    fixture
                        .root
                        .join("bundle")
                        .join(artifact.payload.as_ref().unwrap()),
                )
                .unwrap(),
            );
        },
        Surface::SdkGo => {
            let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
            let member = archive.by_index(0).unwrap();
            let start = member.data_start().unwrap() as usize;
            let end = start + member.size() as usize;
            let local = member.header_start() as usize;
            let central = member.central_header_start() as usize;
            drop(member);
            drop(archive);
            mutate(&mut bytes[start..end], data);
            let crc = crc32fast::hash(&bytes[start..end]).to_le_bytes();
            bytes[local + 14..local + 18].copy_from_slice(&crc);
            bytes[central + 16..central + 20].copy_from_slice(&crc);
        },
        Surface::SdkRust => {
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(bytes.as_slice())
                .read_to_end(&mut decoded)
                .unwrap();
            // The fixture's first regular tar member is its normalized Cargo.toml.
            let size = tar::Archive::new(decoded.as_slice())
                .entries()
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .size() as usize;
            mutate(&mut decoded[512..512 + size], data);
            let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            gzip.write_all(&decoded).unwrap();
            bytes = gzip.finish().unwrap();
        },
        Surface::SdkJava if artifact.file.ends_with(".pom") => mutate(&mut bytes, data),
        _ => return false,
    }
    fixture.replace_artifact(index, &bytes, payload.as_deref().unwrap_or(&bytes));
    true
}
fn mutate(bytes: &mut [u8], data: &[u8]) {
    for (index, value) in data.iter().copied().enumerate().skip(1) {
        let offset = (index * 257 + usize::from(value)) % bytes.len();
        bytes[offset] ^= value.max(1);
    }
}
