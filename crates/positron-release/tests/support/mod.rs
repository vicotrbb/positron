#![allow(dead_code)]
pub mod keyless;
mod native_packages;
mod native_registry;
mod native_rpm;
pub mod nix_cache;
use positron_kernel::release_manifest::{
    FormatCompatibility, ProductVersion, ReleaseCompatibility,
};
use positron_release::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub struct Fixture {
    pub root: PathBuf,
    pub rebuild: PathBuf,
    pub inventory: ReleaseInventory,
    pub pair: Ed25519KeyPair,
    native_artifacts: Vec<native_registry::NativeArtifactFixture>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).expect("cleanup");
    }
}
impl Fixture {
    pub fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "positron-release-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let rebuild = root.join("rebuild");
        std::fs::create_dir_all(&rebuild).unwrap();
        std::fs::create_dir(root.join("bundle")).unwrap();
        let pair = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap();
        let format = FormatCompatibility {
            readable_epochs: vec![2],
            writable_epoch: 2,
            migrations: vec![],
        };
        let compatibility = ReleaseCompatibility {
            config_schema: 1,
            previous_config_schema: None,
            persistent: format.clone(),
            backup: format,
            receiver: [1; 32],
            api: [2; 32],
            query: [3; 32],
            schema: Sha256::digest(b"canonical api definition").into(),
            crd: [5; 32],
            operator: [6; 32],
        };
        let version = ProductVersion {
            major: 1,
            minor: 0,
            patch: 0,
        };
        let inventory = ReleaseInventory {
            format: 1,
            version,
            source_commit: keyless::SOURCE_COMMIT.into(),
            build_identity: "independent-build-1".into(),
            api_version: "positron.v1".into(),
            compatibility,
            inputs: vec![],
            files: vec![],
            artifacts: vec![],
            security_support: SecuritySupport {
                expires_unix: keyless::NOW as u64 + 50,
                upgrade_paths: vec![[7; 32]],
            },
        };
        let mut fixture = Self {
            root,
            rebuild,
            inventory,
            pair,
            native_artifacts: Vec::new(),
        };
        for name in [
            "rust",
            "linker",
            "protobuf",
            "openapi",
            "sdk",
            "frontend",
            "packaging",
            "documentation",
            "lockfile",
        ] {
            let file = fixture.add(
                format!("input-{name}"),
                format!("pinned {name} content").as_bytes(),
            );
            fixture.inventory.inputs.push(BuildInput {
                name: name.into(),
                version: "1.0.0".into(),
                file,
            });
        }
        // Enumerated independently from the implementation's required set.
        use Surface::*;
        let mut required = vec![];
        for surface in [NativeExecutable, NativeArchive, Nix] {
            for target in [
                "linux-x86_64",
                "linux-aarch64",
                "macos-x86_64",
                "macos-aarch64",
            ] {
                required.push((surface, target));
            }
        }
        for surface in [Debian, Rpm, OciImage] {
            for target in ["linux-x86_64", "linux-aarch64"] {
                required.push((surface, target));
            }
        }
        for target in [
            "nix-linux-x86_64",
            "nix-linux-aarch64",
            "nix-macos-x86_64",
            "nix-macos-aarch64",
        ] {
            required.push((NativeExecutable, target));
        }
        for surface in [
            Homebrew,
            OciIndex,
            Compose,
            Helm,
            Grafana,
            SdkRust,
            SdkTypeScript,
            SdkPython,
            SdkGo,
            SdkJava,
            SdkDotNet,
            Source,
            Api,
            Documentation,
        ] {
            required.push((surface, "any"));
        }
        let inputs_hash = hex(&Sha256::digest(
            serde_json::to_vec(
                &fixture
                    .inventory
                    .inputs
                    .iter()
                    .map(|input| {
                        (
                            input,
                            &fixture.inventory.file(&input.file).unwrap().identity,
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        ));
        let compatibility_hash = hex(&Sha256::digest(
            serde_json::to_vec(&fixture.inventory.compatibility).unwrap(),
        ));
        for (index, (surface, target)) in required.into_iter().enumerate() {
            let payload_bytes = if surface == Debian {
                if target == "linux-x86_64" {
                    include_bytes!("../fixtures/positron_1.0.0_amd64.deb").to_vec()
                } else {
                    include_bytes!("../fixtures/positron_1.0.0_arm64.deb").to_vec()
                }
            } else if surface == Api {
                b"canonical api definition".to_vec()
            } else if surface == Nix {
                include_bytes!("../fixtures/positron.nar").to_vec()
            } else {
                format!("functional artifact {index}").into_bytes()
            };
            let payload = fixture.add(format!("payload-{index}"), &payload_bytes);
            std::fs::write(fixture.rebuild.join(&payload), &payload_bytes).unwrap();
            let content = if surface == OciImage {
                let layer = FileIdentity::of(&payload_bytes);
                let configuration = serde_json::to_vec(&json!({"architecture":if target == "linux-x86_64" {"amd64"} else {"arm64"},"os":"linux","rootfs":{"type":"layers","diff_ids":[format!("sha256:{}",hex(&layer.sha256))]}})).unwrap();
                let config_identity = FileIdentity::of(&configuration);
                fixture.add(format!("config-{index}"), &configuration);
                serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":format!("sha256:{}",hex(&config_identity.sha256)),"size":config_identity.size},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":format!("sha256:{}",hex(&layer.sha256)),"size":layer.size}]})).unwrap()
            } else if surface == OciIndex {
                let manifests:Vec<_> = fixture.inventory.artifacts.iter().filter(|artifact|artifact.surface == OciImage).map(|artifact| {
                    let identity = &fixture.inventory.file(&artifact.file).unwrap().identity;
                    json!({"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":format!("sha256:{}",hex(&identity.sha256)),"size":identity.size,"platform":{"os":"linux","architecture":if artifact.target == "linux-x86_64" {"amd64"} else {"arm64"}}})
                }).collect();
                serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":manifests})).unwrap()
            } else {
                payload_bytes.clone()
            };
            let payload = if surface == OciIndex {
                std::fs::write(fixture.root.join("bundle").join(&payload), &content).unwrap();
                std::fs::write(fixture.rebuild.join(&payload), &content).unwrap();
                fixture
                    .inventory
                    .files
                    .iter_mut()
                    .find(|file| file.id == payload)
                    .unwrap()
                    .identity = FileIdentity::of(&content);
                payload
            } else {
                payload
            };
            let filename = if surface == Debian {
                format!(
                    "positron_1.0.0_{}.deb",
                    if target == "linux-x86_64" {
                        "amd64"
                    } else {
                        "arm64"
                    }
                )
            } else {
                format!("artifact-{index}")
            };
            let file = fixture.add(filename, &content);
            let digest = hex(&FileIdentity::of(&content).sha256);
            let spdx = fixture.add(format!("spdx-{index}"),&serde_json::to_vec(&json!({"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"SPDXID":"SPDXRef-positron","name":file,"versionInfo":"1.0.0","licenseConcluded":"MIT","checksums":[{"algorithm":"SHA256","checksumValue":digest}]}]})).unwrap());
            let cyclonedx = fixture.add(format!("cdx-{index}"),&serde_json::to_vec(&json!({"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"application","name":file,"version":"1.0.0","hashes":[{"alg":"SHA-256","content":digest}]}]})).unwrap());
            let provenance = fixture.add(format!("provenance-{index}"),&serde_json::to_vec(&json!({"_type":"https://in-toto.io/Statement/v1","subject":[{"name":file,"digest":{"sha256":digest}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"https://positron.dev/release/v1","externalParameters":{"source_commit":fixture.inventory.source_commit,"build_identity":fixture.inventory.build_identity,"api_version":fixture.inventory.api_version,"product_version":"1.0.0","target":target,"inputs_sha256":inputs_hash,"schema_sha256":hex(&fixture.inventory.compatibility.schema),"compatibility_sha256":compatibility_hash}},"runDetails":{"builder":{"id":"builder-one"}}}})).unwrap());
            let license_notices = fixture.add(
                format!("licenses-{index}"),
                b"MIT License, Positron and dependency notices",
            );
            let evidence = fixture.add(format!("evidence-{index}"),&serde_json::to_vec(&json!({"artifact_sha256":digest,"builder":"builder-one","independent_builder":"builder-two","results":{"unit":true,"integration":true,"fuzz":true,"conformance":true,"fault":true,"security":true,"dependency_policy":true,"secret_scan":true}})).unwrap());
            fixture.inventory.artifacts.push(Artifact {
                file: file.clone(),
                surface,
                target: target.into(),
                payload: Some(payload),
                spdx,
                cyclonedx,
                provenance,
                license_notices,
                evidence,
                publication: Publication {
                    registry: format!("https://registry.example/{file}"),
                    immutable_identity: format!("sha256:{digest}"),
                    native_subject: if surface == Nix {
                        format!("/nix/store/00000000000000000000000000000000-positron-{target}")
                    } else {
                        file.clone()
                    },
                    native_revision: None,
                    state: PublicationState::Published,
                    proof: format!("receipt-{index}"),
                },
            });
        }
        let mut native = native_registry::fixtures("1.0.0", &fixture.inventory.source_commit);
        native.extend(native_packages::fixtures("1.0.0"));
        native.extend(native_rpm::fixtures());
        fixture.install_native(native);
        fixture.refresh_homebrew();
        fixture
    }
    fn install_native(&mut self, native: Vec<native_registry::NativeArtifactFixture>) {
        let mut seen = Vec::new();
        for data in &native {
            let base = self
                .inventory
                .artifacts
                .iter()
                .position(|artifact| {
                    artifact.surface == data.surface
                        && (data.surface != Surface::Rpm
                            || data
                                .filename
                                .contains(artifact.target.strip_prefix("linux-").unwrap()))
                })
                .unwrap();
            let index = if seen.contains(&data.surface) && data.surface != Surface::Rpm {
                let mut artifact = self.inventory.artifacts[base].clone();
                let next = self.inventory.artifacts.len();
                for id in [
                    &mut artifact.spdx,
                    &mut artifact.cyclonedx,
                    &mut artifact.provenance,
                    &mut artifact.license_notices,
                    &mut artifact.evidence,
                ] {
                    let bytes = std::fs::read(self.root.join("bundle").join(&*id)).unwrap();
                    *id = self.add(format!("native-metadata-{next}-{id}"), &bytes);
                }
                artifact.publication.proof = format!("native-receipt-{next}");
                self.inventory.artifacts.push(artifact);
                next
            } else {
                seen.push(data.surface);
                base
            };
            let previous = self.inventory.artifacts[index].clone();
            let old = hex(&self.inventory.file(&previous.file).unwrap().identity.sha256);
            let digest = hex(&FileIdentity::of(&data.contents).sha256);
            self.add(data.filename.clone(), &data.contents);
            self.inventory.artifacts[index].file = data.filename.clone();
            self.inventory.artifacts[index].payload = data.payload.as_ref().map(|bytes| {
                let id = self.add(format!("native-payload-{index}"), bytes);
                std::fs::write(self.rebuild.join(&id), bytes).unwrap();
                id
            });
            for id in [
                &previous.spdx,
                &previous.cyclonedx,
                &previous.provenance,
                &previous.evidence,
            ] {
                let contents = std::fs::read_to_string(self.root.join("bundle").join(id))
                    .unwrap()
                    .replace(&previous.file, &data.filename)
                    .replace(&old, &digest);
                std::fs::write(self.root.join("bundle").join(id), contents.as_bytes()).unwrap();
                self.inventory
                    .files
                    .iter_mut()
                    .find(|file| file.id == *id)
                    .unwrap()
                    .identity = FileIdentity::of(contents.as_bytes());
            }
            let publication = &mut self.inventory.artifacts[index].publication;
            publication.registry = data.registry.clone();
            publication.native_subject = data.subject.clone();
            publication.native_revision = data.revision.clone();
            publication.immutable_identity = format!("sha256:{digest}");
        }
        self.native_artifacts = native;
    }
    pub fn add(&mut self, id: String, bytes: &[u8]) -> String {
        std::fs::write(self.root.join("bundle").join(&id), bytes).unwrap();
        self.inventory.files.push(InventoryFile {
            id: id.clone(),
            identity: FileIdentity::of(bytes),
        });
        id
    }
    fn refresh_homebrew(&mut self) {
        let index = self
            .inventory
            .artifacts
            .iter()
            .position(|artifact| artifact.surface == Surface::Homebrew)
            .unwrap();
        let formula = homebrew_formula(&self.inventory).unwrap();
        self.replace_artifact(index, formula.as_bytes(), formula.as_bytes());
        *self
            .native_artifacts
            .iter_mut()
            .find(|artifact| artifact.surface == Surface::Homebrew)
            .unwrap() = native_registry::homebrew(formula.into_bytes());
    }
    pub fn replace_artifact(&mut self, index: usize, bytes: &[u8], payload: &[u8]) {
        let artifact = self.inventory.artifacts[index].clone();
        let old = hex(&self.inventory.file(&artifact.file).unwrap().identity.sha256);
        let identity = FileIdentity::of(bytes);
        let new = hex(&identity.sha256);
        let mut members = vec![(&artifact.file, bytes)];
        if let Some(id) = &artifact.payload {
            members.push((id, payload));
        }
        for (id, content) in members {
            std::fs::write(self.root.join("bundle").join(id), content).unwrap();
            self.inventory
                .files
                .iter_mut()
                .find(|file| file.id == *id)
                .unwrap()
                .identity = FileIdentity::of(content);
        }
        if let Some(id) = &artifact.payload {
            std::fs::write(self.rebuild.join(id), payload).unwrap();
        }
        for id in [
            &artifact.spdx,
            &artifact.cyclonedx,
            &artifact.provenance,
            &artifact.evidence,
        ] {
            let contents = std::fs::read_to_string(self.root.join("bundle").join(id))
                .unwrap()
                .replace(&old, &new);
            std::fs::write(self.root.join("bundle").join(id), contents.as_bytes()).unwrap();
            self.inventory
                .files
                .iter_mut()
                .find(|file| file.id == *id)
                .unwrap()
                .identity = FileIdentity::of(contents.as_bytes());
        }
        self.inventory.artifacts[index]
            .publication
            .immutable_identity = format!("sha256:{new}");
        if artifact.surface == Surface::NativeArchive {
            self.refresh_homebrew();
        }
    }
    pub fn key(&self) -> [u8; 32] {
        self.pair.public_key().as_ref().try_into().unwrap()
    }
    pub fn native_publishers(&self) -> Vec<NativePublisher> {
        let root = keyless::KeylessFixture::new().trusted_root();
        let mut publishers = Vec::new();
        for artifact in &self.inventory.artifacts {
            if publishers.iter().any(|publisher: &NativePublisher| {
                publisher.registry == artifact.publication.registry
            }) {
                continue;
            }
            let policy = if artifact.surface == Surface::Nix {
                NativePublisherPolicy::NixCache {
                    key_name: nix_cache::NAME.into(),
                    key_hint: nix_cache::hint(),
                }
            } else {
                self.native_artifacts
                    .iter()
                    .find(|data| data.filename == artifact.file)
                    .map(|data| data.policy.clone())
                    .unwrap_or_else(|| {
                        NativePublisherPolicy::Keyless(NativeKeylessPublisher {
                            kind: NativePublicationKind::GithubActions,
                            trusted_root_sha256: Sha256::digest(serde_json::to_vec(&root).unwrap())
                                .into(),
                            identity: keyless::SAN.into(),
                            issuer: keyless::ISSUER.into(),
                            repository: keyless::REPOSITORY.into(),
                            source_ref: keyless::REF.into(),
                        })
                    })
            };
            publishers.push(NativePublisher {
                registry: artifact.publication.registry.clone(),
                policy,
            });
        }
        publishers
    }

    pub fn trust(&self) -> VerifiedTrust {
        self.trust_with(|_| {})
    }
    pub fn trust_with(&self, mutate: impl FnOnce(&mut TrustSnapshot)) -> VerifiedTrust {
        let key = self.key();
        let mut snapshot = TrustSnapshot {
            format: 1,
            sequence: 2,
            current_version: self.inventory.version,
            issued_unix: keyless::NOW as u64 - 50,
            expires_unix: keyless::NOW as u64 + 50,
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
                expires_unix: keyless::NOW as u64 + 50,
            })
            .collect(),
            native_publishers: self.native_publishers(),
            revoked_keys: vec![],
            revoked_manifests: vec![],
            revoked_artifacts: vec![],
        };
        snapshot.identities.push(SigningIdentity {
            public_key: nix_cache::key(),
            purpose: KeyPurpose::Publisher,
            not_before_unix: 100,
            expires_unix: keyless::NOW as u64 + 50,
        });
        mutate(&mut snapshot);
        InstalledProjectTrustRoot {
            public_key: key,
            minimum_sequence: 2,
        }
        .verify(&snapshot.sign(&self.pair).unwrap(), keyless::NOW as u64)
        .unwrap()
    }
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Fixture {
    pub fn published(&self) -> (Vec<u8>, ReleaseConstruction) {
        self.published_with(|_, _| {}, |_, _| {})
    }
    pub fn published_with(
        &self,
        change_statement: impl FnMut(&Artifact, &mut serde_json::Value),
        change_body: impl FnMut(&Artifact, &mut serde_json::Value),
    ) -> (Vec<u8>, ReleaseConstruction) {
        self.published_with_native(change_statement, change_body, |_, _| {})
    }
    pub fn published_with_native(
        &self,
        mut change_statement: impl FnMut(&Artifact, &mut serde_json::Value),
        mut change_body: impl FnMut(&Artifact, &mut serde_json::Value),
        mut change_native: impl FnMut(&Artifact, &mut serde_json::Value),
    ) -> (Vec<u8>, ReleaseConstruction) {
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        use positron_kernel::release_manifest::SignedReleaseManifest;
        let construction = construct_release(
            &self.inventory,
            &self.root.join("bundle"),
            &self.rebuild,
            &[],
            vec![],
        )
        .unwrap();
        let signature = self.pair.sign(&construction.signing_message().unwrap());
        let signed = SignedReleaseManifest::new(
            construction.manifest.clone(),
            signature.as_ref().try_into().unwrap(),
        )
        .unwrap()
        .to_bytes()
        .unwrap();
        let manifest = verify_manifest(&signed, self.key(), &self.trust())
            .unwrap()
            .digest();
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki.extend(self.key());
        let key_id = Sha256::digest(&spki);
        let hint = hex(&key_id);
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            B64.encode(&spki)
        );
        let native = keyless::KeylessFixture::new();
        for artifact in &self.inventory.artifacts {
            let digest = hex(&self.inventory.file(&artifact.file).unwrap().identity.sha256);
            let mut parameters = json!({"registry":artifact.publication.registry,"immutable_identity":artifact.publication.immutable_identity});
            if matches!(artifact.surface, Surface::OciImage | Surface::OciIndex) {
                let payload=serde_json::to_vec(&json!({"critical":{"type":"cosign container image signature","identity":{"docker-reference":artifact.publication.registry.trim_start_matches("https://")},"image":{"docker-manifest-digest":format!("sha256:{digest}")}},"optional":{"positron-release-manifest":hex(&manifest)}})).unwrap();
                parameters["cosign"] = json!({"payload":B64.encode(&payload),"signature":B64.encode(self.pair.sign(&payload).as_ref())});
            }
            if !matches!(artifact.surface, Surface::OciImage | Surface::OciIndex) {
                let mut native_statement = json!({"_type":"https://in-toto.io/Statement/v1","subject":[{"name":artifact.publication.native_subject,"digest":{"sha256":digest}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1","externalParameters":{"workflow":{"repository":keyless::REPOSITORY,"ref":keyless::REF,"path":".github/workflows/release.yml"}},"resolvedDependencies":[{"uri":format!("git+{}@{}",keyless::REPOSITORY,keyless::REF),"digest":{"gitCommit":self.inventory.source_commit}}]}}});
                let unchanged = native_statement.clone();
                change_native(artifact, &mut native_statement);
                let payload = serde_json::to_vec(&native_statement).unwrap();
                parameters["native"] = if artifact.surface == Surface::Nix
                    && native_statement == unchanged
                {
                    nix_cache::proof(artifact, &self.inventory)
                } else if native_statement == unchanged {
                    self.native_artifacts.iter().find(|data|data.filename==artifact.file).map(|data|data.proof.clone()).unwrap_or_else(||json!({"trustedRoot":native.trusted_root(),"bundle":native.bundle(&payload)}))
                } else {
                    json!({"trustedRoot":native.trusted_root(),"bundle":native.bundle(&payload)})
                };
            }
            let mut statement = json!({"_type":"https://in-toto.io/Statement/v1","subject":[{"name":artifact.file,"digest":{"sha256":digest}},{"name":"positron-release-manifest","digest":{"sha256":hex(&manifest)}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"https://positron.dev/publication/v1","externalParameters":parameters},"runDetails":{"builder":{"id":"publisher"}}}});
            change_statement(artifact, &mut statement);
            let payload = serde_json::to_vec(&statement).unwrap();
            let mut pae =
                format!("DSSEv1 28 application/vnd.in-toto+json {} ", payload.len()).into_bytes();
            pae.extend(&payload);
            let signature = B64.encode(self.pair.sign(&pae).as_ref());
            let envelope = json!({"payloadType":"application/vnd.in-toto+json","payload":B64.encode(&payload),"signatures":[{"keyid":hint,"sig":signature}]});
            let mut body = json!({"apiVersion":"0.0.1","kind":"dsse","spec":{"signatures":[{"signature":signature,"verifier":B64.encode(pem.as_bytes())}],"envelopeHash":{"algorithm":"sha256","value":hex(&Sha256::digest(serde_json::to_vec(&envelope).unwrap()))},"payloadHash":{"algorithm":"sha256","value":hex(&Sha256::digest(&payload))}}});
            change_body(artifact, &mut body);
            let body = serde_json::to_vec(&body).unwrap();
            let set = serde_json::to_vec(
                &json!({"body":B64.encode(&body),"integratedTime":120,"logID":hint,"logIndex":0}),
            )
            .unwrap();
            let mut leaf = vec![0];
            leaf.extend(&body);
            let root = Sha256::digest(&leaf);
            let checkpoint = format!("local-test-log\n1\n{}\n", B64.encode(root));
            let mut checkpoint_signature = key_id.get(..4).unwrap().to_vec();
            checkpoint_signature.extend(self.pair.sign(checkpoint.as_bytes()).as_ref());
            let checkpoint = format!(
                "{checkpoint}\n— local-test-log {}\n",
                B64.encode(checkpoint_signature)
            );
            let bundle = json!({"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"publicKey":{"hint":hint},"tlogEntries":[{"logIndex":"0","logId":{"keyId":B64.encode(key_id)},"kindVersion":{"kind":"dsse","version":"0.0.1"},"integratedTime":"120","canonicalizedBody":B64.encode(&body),"inclusionPromise":{"signedEntryTimestamp":B64.encode(self.pair.sign(&set).as_ref())},"inclusionProof":{"logIndex":"0","rootHash":B64.encode(root),"treeSize":"1","hashes":[],"checkpoint":{"envelope":checkpoint}}}]},"dsseEnvelope":envelope});
            std::fs::write(
                self.root.join("bundle").join(&artifact.publication.proof),
                serde_json::to_vec(&bundle).unwrap(),
            )
            .unwrap();
        }
        (signed, construction)
    }
}
