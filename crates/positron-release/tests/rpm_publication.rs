mod support;
use positron_release::*;
use std::io::{Read, Write};

#[test]
fn rpm_requires_native_signature_evidence_even_with_authenticated_workflow_provenance() {
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
    let trust = fixture.trust_with(|snapshot| {
        let generic = snapshot
            .native_publishers
            .iter()
            .find_map(|publisher| match &publisher.policy {
                NativePublisherPolicy::Keyless(policy) => Some(policy.clone()),
                _ => None,
            })
            .unwrap();
        for publisher in &mut snapshot.native_publishers {
            if matches!(publisher.policy, NativePublisherPolicy::Rpm { .. }) {
                publisher.policy = NativePublisherPolicy::Keyless(generic.clone());
            }
        }
    });
    let result = verify_release(
        &signed,
        &prepared.inventory_bytes,
        fixture.key(),
        &trust,
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        "linux-x86_64",
        &[],
    );
    assert!(
        result.is_err(),
        "generic workflow provenance cannot replace RPM signature evidence"
    );
}

#[test]
fn native_rpmbuild_signatures_authenticate_both_required_targets() {
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
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
    assert!(result.is_ok(), "{result:?}");
}

fn verify_fixture(
    fixture: &support::Fixture,
    trust: &VerifiedTrust,
) -> Result<ReleaseVerificationReport, ReleaseError> {
    let (signed, prepared) = fixture.published();
    verify_release(
        &signed,
        &prepared.inventory_bytes,
        fixture.key(),
        trust,
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        "linux-x86_64",
        &[],
    )
}
#[test]
fn native_rpm_key_authority_and_revocation_come_from_installed_release_trust() {
    let fixture = support::Fixture::new();
    for revoked in [false, true] {
        let trust = fixture.trust_with(|snapshot| {
            for publisher in &mut snapshot.native_publishers {
                if let NativePublisherPolicy::Rpm {
                    trusted_root_sha256,
                } = &mut publisher.policy
                {
                    if revoked {
                        snapshot.revoked_artifacts.push(*trusted_root_sha256);
                    } else {
                        *trusted_root_sha256 = [7; 32];
                    }
                }
            }
        });
        assert_eq!(
            verify_fixture(&fixture, &trust).unwrap_err(),
            if revoked {
                ReleaseError::Revoked
            } else {
                ReleaseError::Authentication
            }
        );
    }
}
#[test]
fn remeasured_outer_artifacts_cannot_replace_native_rpm_header_or_payload_authentication() {
    for part in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] {
        let mut fixture = support::Fixture::new();
        let index = fixture
            .inventory
            .artifacts
            .iter()
            .position(|artifact| artifact.surface == Surface::Rpm)
            .unwrap();
        let artifact = fixture.inventory.artifacts[index].clone();
        let mut bytes = std::fs::read(fixture.root.join("bundle").join(&artifact.file)).unwrap();
        let word = |offset: usize| {
            u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
        };
        let main = (96 + 16 + word(104) * 16 + word(108)).next_multiple_of(8);
        let payload = main + 16 + word(main + 8) * 16 + word(main + 12);
        if part == 0 {
            // Native RSA signature MPI, leaving its packet framing intact.
            let count = word(104);
            let tag = (0..count)
                .map(|index| 112 + index * 16)
                .find(|offset| matches!(word(*offset), 267 | 268))
                .unwrap();
            let last = 112 + count * 16 + word(tag + 8) + word(tag + 12) - 1;
            bytes[last] ^= 1;
        } else if part == 1 {
            let name = bytes[main..payload]
                .windows(9)
                .position(|window| window == b"positron\0")
                .unwrap()
                + main;
            bytes[name] = b'q';
        } else if part == 7 || part == 8 {
            let count = word(main + 8);
            let data = main + 16 + count * 16;
            let tag = (0..count)
                .map(|index| main + 16 + index * 16)
                .find(|offset| word(*offset) == 5093)
                .unwrap();
            if part == 7 {
                bytes[tag + 4..tag + 8].copy_from_slice(&7u32.to_be_bytes());
            } else {
                let offset = data + word(tag + 8);
                bytes[offset..offset + 4].copy_from_slice(&2u32.to_be_bytes());
            }
        } else if part == 4 || part == 5 || part == 6 || part == 9 {
            let count = word(104);
            let tag = (0..count)
                .map(|index| 112 + index * 16)
                .find(|offset| matches!(word(*offset), 267 | 268))
                .unwrap();
            if part == 9 {
                bytes[tag + 4..tag + 8].copy_from_slice(&1u32.to_be_bytes());
            } else if part == 6 {
                let length = word(tag + 12);
                let end = 112 + count * 16 + word(tag + 8) + length;
                bytes[end] = 0xc2;
                bytes[tag + 12..tag + 16].copy_from_slice(&((length + 1) as u32).to_be_bytes());
            } else if part == 4 {
                bytes[tag..tag + 4].copy_from_slice(&266u32.to_be_bytes());
            } else {
                let start = 112 + count * 16 + word(tag + 8);
                bytes[start] = 0;
            }
        } else if part == 3 {
            let script = bytes[main..payload]
                .windows(9)
                .position(|window| window == b"systemctl")
                .unwrap()
                + main;
            bytes[script] = b'x';
        } else {
            // Another valid compressed payload passes decoded screening, but its
            // original signed header's SHA256 must still reject substitution.
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(&bytes[payload..])
                .read_to_end(&mut decoded)
                .unwrap();
            let executable = decoded
                .windows(4)
                .position(|window| window == b"\x7fELF")
                .unwrap();
            decoded[executable + 1] = b'D';
            let mut replacement =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            replacement.write_all(&decoded).unwrap();
            bytes.truncate(payload);
            bytes.extend(replacement.finish().unwrap());
        }
        let functional = rpm_functional_payload(&bytes).unwrap().to_vec();
        fixture.replace_artifact(index, &bytes, &functional);
        assert_eq!(
            verify_fixture(&fixture, &fixture.trust()).err(),
            Some(if part == 1 {
                ReleaseError::IdentityMismatch
            } else if part == 5 || part == 6 || part == 7 || part == 9 {
                ReleaseError::Invalid
            } else if part == 8 {
                ReleaseError::Unsupported
            } else {
                ReleaseError::Authentication
            }),
            "mutation {part}"
        );
    }
}
