mod support;
use positron_release::*;

fn verify(
    fixture: &support::Fixture,
    signed: &[u8],
    prepared: &ReleaseConstruction,
    trust: &VerifiedTrust,
) -> Result<ReleaseVerificationReport, ReleaseError> {
    verify_release(
        signed,
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
fn authenticated_native_workflow_claims_bind_source_and_subject() {
    for pointer in [
        "/subject/0/name",
        "/predicate/buildDefinition/externalParameters/workflow/repository",
        "/predicate/buildDefinition/externalParameters/workflow/ref",
        "/predicate/buildDefinition/externalParameters/workflow/path",
        "/predicate/buildDefinition/resolvedDependencies/0/digest/gitCommit",
    ] {
        let fixture = support::Fixture::new();
        let (signed, prepared) = fixture.published_with_native(
            |_, _| {},
            |_, _| {},
            |artifact, statement| {
                if artifact.surface == Surface::NativeExecutable
                    && artifact.target == "linux-x86_64"
                {
                    *statement.pointer_mut(pointer).unwrap() = serde_json::json!("wrong");
                }
            },
        );
        assert!(
            verify(&fixture, &signed, &prepared, &fixture.trust()).is_err(),
            "{pointer}"
        );
    }
}
#[test]
fn native_trust_root_identity_issuer_and_source_are_explicitly_authorized() {
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
    for field in 0..5 {
        let trust = fixture.trust_with(|snapshot| {
            let NativePublisherPolicy::Keyless(publisher) =
                &mut snapshot.native_publishers[0].policy
            else {
                panic!("keyless fixture")
            };
            match field {
                0 => publisher.trusted_root_sha256 = [7; 32],
                1 => publisher.identity = "wrong".into(),
                2 => publisher.issuer = "wrong".into(),
                3 => publisher.repository = "wrong".into(),
                _ => publisher.source_ref = "wrong".into(),
            }
        });
        assert!(verify(&fixture, &signed, &prepared, &trust).is_err());
    }
}

#[test]
fn pypi_publish_attestation_uses_its_native_predicate_and_pep740_envelope() {
    let mut fixture = support::Fixture::new();
    for artifact in &mut fixture.inventory.artifacts {
        if artifact.surface == Surface::SdkPython {
            artifact.publication.registry = "https://pypi.org".into();
        }
    }
    let (signed,prepared)=fixture.published_with_native(|artifact,statement| {
        if artifact.surface==Surface::SdkPython {
            let native=&mut statement["predicate"]["buildDefinition"]["externalParameters"]["native"];
            let bundle=&native["bundle"];
            native["bundle"]=serde_json::json!({"version":1,"envelope":{"statement":bundle["dsseEnvelope"]["payload"],"signature":bundle["dsseEnvelope"]["signatures"][0]["sig"]},"verification_material":{"certificate":bundle["verificationMaterial"]["certificate"]["rawBytes"],"transparency_entries":bundle["verificationMaterial"]["tlogEntries"]}});
        }
    },|_,_|{},|artifact,statement| {if artifact.surface==Surface::SdkPython { statement["predicateType"]=serde_json::json!("https://docs.pypi.org/attestations/publish/v1");statement["predicate"]=serde_json::json!({}); }});
    let trust = fixture.trust_with(|snapshot| {
        for publisher in &mut snapshot.native_publishers {
            if publisher.registry == "https://pypi.org"
                && let NativePublisherPolicy::Keyless(policy) = &mut publisher.policy
            {
                policy.kind = NativePublicationKind::PyPi;
            }
        }
    });
    verify(&fixture, &signed, &prepared, &trust).unwrap();
}

#[test]
fn npm_native_provenance_requires_the_registry_sha512_subject_profile() {
    let mut fixture = support::Fixture::new();
    for artifact in &mut fixture.inventory.artifacts {
        if artifact.surface == Surface::SdkTypeScript {
            artifact.publication.registry = "https://registry.npmjs.org".into();
            artifact.publication.native_subject = "pkg:npm/positron-sdk@1.0.0".into();
        }
    }
    let (signed, prepared) = fixture.published_with_native(
        |_, _| {},
        |_, _| {},
        |artifact, statement| {
            if artifact.surface == Surface::SdkTypeScript {
                statement["predicate"]["buildDefinition"]["buildType"] = serde_json::json!(
                    "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
                );
            }
        },
    );
    let trust = fixture.trust_with(|snapshot| {
        for publisher in &mut snapshot.native_publishers {
            if publisher.registry == "https://registry.npmjs.org"
                && let NativePublisherPolicy::Keyless(policy) = &mut publisher.policy
            {
                policy.kind = NativePublicationKind::Npm;
            }
        }
    });
    assert_eq!(
        verify(&fixture, &signed, &prepared, &trust).err(),
        Some(ReleaseError::IdentityMismatch)
    );
}

#[test]
fn github_native_attestation_accepts_the_official_actions_build_type() {
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published_with_native(
        |_, _| {},
        |_, _| {},
        |_, statement| {
            statement["predicate"]["buildDefinition"]["buildType"] =
                serde_json::json!("https://actions.github.io/buildtypes/workflow/v1")
        },
    );
    verify(&fixture, &signed, &prepared, &fixture.trust()).unwrap();
}

#[test]
fn homebrew_native_evidence_uses_the_actual_tap_revision_and_identity() {
    const TAP: &str = "https://github.com/vicotrbb/homebrew-positron";
    const REVISION: &str = "1111111111111111111111111111111111111111";
    let identity = format!("{TAP}/.github/workflows/release.yml@refs/heads/main");
    let native = support::keyless::KeylessFixture::for_workflow(&identity, TAP, REVISION);
    let mut fixture = support::Fixture::new();
    fixture
        .inventory
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.surface == Surface::Homebrew)
        .unwrap()
        .publication
        .registry = TAP.into();
    fixture
        .inventory
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.surface == Surface::Homebrew)
        .unwrap()
        .publication
        .native_revision = Some(REVISION.into());
    let (signed,prepared)=fixture.published_with_native(|artifact,statement| {
        if artifact.surface==Surface::Homebrew {
            let proof=&mut statement["predicate"]["buildDefinition"]["externalParameters"]["native"];
            use base64::Engine;
            let payload=base64::engine::general_purpose::STANDARD.decode(proof["bundle"]["dsseEnvelope"]["payload"].as_str().unwrap()).unwrap();
            let mut payload:serde_json::Value=serde_json::from_slice(&payload).unwrap();
            payload["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["repository"]=serde_json::json!(TAP);
            payload["predicate"]["buildDefinition"]["resolvedDependencies"]=serde_json::json!([{"uri":format!("git+{TAP}@refs/heads/main"),"digest":{"gitCommit":REVISION}}]);
            *proof=serde_json::json!({"trustedRoot":native.trusted_root(),"bundle":native.bundle(&serde_json::to_vec(&payload).unwrap()),"revision":REVISION});
        }
    },|_,_|{},|_,_|{});
    let trust = fixture.trust_with(|snapshot| {
        let publisher = snapshot
            .native_publishers
            .iter_mut()
            .find(|publisher| publisher.registry == TAP)
            .unwrap();
        let NativePublisherPolicy::Keyless(policy) = &mut publisher.policy else {
            panic!()
        };
        policy.kind = NativePublicationKind::HomebrewTap;
        policy.identity = identity.clone();
        policy.repository = TAP.into();
    });
    verify(&fixture, &signed, &prepared, &trust).unwrap();
}

#[test]
fn maven_central_refuses_a_jar_without_its_required_publication_members() {
    let mut fixture = support::Fixture::new();
    fixture.inventory.artifacts.retain(|artifact| {
        artifact.surface != Surface::SdkJava
            || artifact.publication.native_subject.ends_with("?type=jar")
    });
    let java = fixture
        .inventory
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.surface == Surface::SdkJava)
        .unwrap();
    java.publication.registry = "https://repo.maven.apache.org/maven2".into();
    java.publication.native_subject = "pkg:maven/dev.positron/sdk@1.0.0?type=jar".into();
    assert_eq!(
        construct_release(
            &fixture.inventory,
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            &[],
            vec![]
        )
        .err(),
        Some(ReleaseError::PartialSet)
    );
}

#[test]
fn npm_native_sha512_provenance_binds_the_shared_release_version() {
    use sha2::{Digest, Sha512};
    for version in ["1.0.0", "9.9.9"] {
        let mut fixture = support::Fixture::new();
        let artifact = fixture
            .inventory
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.surface == Surface::SdkTypeScript)
            .unwrap();
        artifact.publication.registry = "https://registry.npmjs.org".into();
        artifact.publication.native_subject = "pkg:npm/positron-sdk@1.0.0".into();
        let digest = support::hex(&Sha512::digest(
            std::fs::read(fixture.root.join("bundle").join(&artifact.file)).unwrap(),
        ));
        let (signed, prepared) = fixture.published_with_native(
            |_, _| {},
            |_, _| {},
            |artifact, statement| {
                if artifact.surface == Surface::SdkTypeScript {
                    statement["subject"][0]["digest"] = serde_json::json!({"sha512":digest});
                    statement["subject"][0]["name"] =
                        serde_json::json!(format!("pkg:npm/positron-sdk@{version}"));
                    statement["predicate"]["buildDefinition"]["buildType"] = serde_json::json!(
                        "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
                    );
                }
            },
        );
        let trust = fixture.trust_with(|snapshot| {
            for publisher in &mut snapshot.native_publishers {
                if publisher.registry == "https://registry.npmjs.org" {
                    let NativePublisherPolicy::Keyless(policy) = &mut publisher.policy else {
                        panic!()
                    };
                    policy.kind = NativePublicationKind::Npm;
                }
            }
        });
        let result = verify(&fixture, &signed, &prepared, &trust);
        if version == "1.0.0" {
            result.unwrap();
        } else {
            assert_eq!(result.err(), Some(ReleaseError::IdentityMismatch));
        }
    }
}

#[test]
fn standard_registry_contexts_cannot_downgrade_to_generic_workflow_provenance() {
    for surface in [
        Surface::SdkRust,
        Surface::SdkTypeScript,
        Surface::SdkPython,
        Surface::SdkGo,
        Surface::SdkJava,
        Surface::SdkDotNet,
        Surface::Homebrew,
    ] {
        for relabel in [false, true] {
            let mut fixture = support::Fixture::new();
            let registry = if relabel {
                let registry = "https://github.com/vicotrbb/positron/releases";
                for artifact in &mut fixture.inventory.artifacts {
                    if artifact.surface == surface {
                        artifact.publication.registry = registry.into();
                    }
                }
                registry.to_owned()
            } else {
                fixture
                    .inventory
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.surface == surface)
                    .unwrap()
                    .publication
                    .registry
                    .clone()
            };
            if relabel {
                assert_eq!(
                    construct_release(
                        &fixture.inventory,
                        &fixture.root.join("bundle"),
                        &fixture.rebuild,
                        &[],
                        vec![]
                    )
                    .err(),
                    Some(ReleaseError::Unsupported),
                    "{surface:?} registry relabelling"
                );
                continue;
            }
            let (signed, prepared) = fixture.published_with_native(
                |_, _| {},
                |_, _| {},
                |artifact, statement| {
                    if artifact.surface == surface {
                        statement["predicate"]["unrelatedWorkflowClaim"] = serde_json::json!(true);
                    }
                },
            );
            let trust = fixture.trust_with(|snapshot| {
                let generic = snapshot
                    .native_publishers
                    .iter()
                    .find(|publisher| {
                        matches!(
                            publisher.policy,
                            NativePublisherPolicy::Keyless(NativeKeylessPublisher {
                                kind: NativePublicationKind::GithubActions,
                                ..
                            })
                        )
                    })
                    .unwrap()
                    .policy
                    .clone();
                snapshot
                    .native_publishers
                    .iter_mut()
                    .find(|publisher| publisher.registry == registry)
                    .unwrap()
                    .policy = generic;
            });
            assert_eq!(
                verify(&fixture, &signed, &prepared, &trust).err(),
                Some(ReleaseError::Unsupported),
                "{surface:?} relabel={relabel}"
            );
        }
    }
}

#[test]
fn oci_publication_cannot_replace_native_cosign_with_generic_provenance() {
    for surface in [Surface::OciImage, Surface::OciIndex] {
        let fixture = support::Fixture::new();
        let (signed, prepared) = fixture.published_with(
            |artifact, statement| {
                if artifact.surface == surface {
                    statement["predicate"]["buildDefinition"]["externalParameters"]
                        .as_object_mut()
                        .unwrap()
                        .remove("cosign");
                }
            },
            |_, _| {},
        );
        assert_eq!(
            verify(&fixture, &signed, &prepared, &fixture.trust()).err(),
            Some(ReleaseError::Authentication)
        );
    }
}
