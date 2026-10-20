//! Captured rpmbuild/rpmsign protocol fixtures; the wrapped syscall ELF is not Positron.
use super::native_registry::NativeArtifactFixture;
use positron_release::*;
use serde_json::json;
use sha2::{Digest, Sha256};

pub fn fixtures() -> Vec<NativeArtifactFixture> {
    let root = json!({"public_key":include_str!("../fixtures/rpm-protocol-public.asc")});
    let trusted_root_sha256 = Sha256::digest(serde_json::to_vec(&root).unwrap()).into();
    [
        (
            "x86_64",
            include_bytes!("../fixtures/positron-1.0.0-1.x86_64.rpm").as_slice(),
        ),
        (
            "aarch64",
            include_bytes!("../fixtures/positron-1.0.0-1.aarch64.rpm").as_slice(),
        ),
    ]
    .into_iter()
    .map(|(arch, bytes)| NativeArtifactFixture {
        surface: Surface::Rpm,
        filename: format!("positron-1.0.0-1.{arch}.rpm"),
        contents: bytes.to_vec(),
        payload: Some(rpm_functional_payload(bytes).unwrap().to_vec()),
        registry: "https://github.com/vicotrbb/positron/releases".into(),
        subject: format!("pkg:rpm/positron@1.0.0-1?arch={arch}"),
        revision: None,
        policy: NativePublisherPolicy::Rpm {
            trusted_root_sha256,
        },
        proof: json!({"trustedRoot":root}),
    })
    .collect()
}
