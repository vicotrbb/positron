//! Generated SBOM/provenance and canonical test-signing for staged qualification.
use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

impl Qualification {
    pub(super) fn artifact(
        &mut self,
        name: &str,
        surface: Surface,
        target: &str,
        bytes: &[u8],
        rebuilt: &[u8],
        packages: &Value,
    ) {
        let file = self.add(name, bytes);
        fs::write(self.rebuild.join(name), rebuilt).unwrap();
        let digest = hex(&FileIdentity::of(bytes).sha256);
        let version = format!(
            "{}.{}.{}",
            self.inventory.version.major,
            self.inventory.version.minor,
            self.inventory.version.patch
        );
        let mut spdx_packages = vec![
            json!({"SPDXID":"SPDXRef-Artifact","name":name,"versionInfo":version,"downloadLocation":"NOASSERTION","filesAnalyzed":false,"licenseConcluded":"MIT","licenseDeclared":"MIT","copyrightText":"NOASSERTION","checksums":[{"algorithm":"SHA256","checksumValue":digest}]}),
        ];
        let mut components = vec![
            json!({"type":"application","name":name,"version":version,"licenses":[{"license":{"id":"MIT"}}],"hashes":[{"alg":"SHA-256","content":digest}]}),
        ];
        for (index, package) in packages.as_array().unwrap().iter().enumerate() {
            let license = package["license"].as_str().unwrap_or("NOASSERTION");
            spdx_packages.push(json!({"SPDXID":format!("SPDXRef-Cargo-{index}"),"name":package["name"],"versionInfo":package["version"],"downloadLocation":package["source"].as_str().unwrap_or("NOASSERTION"),"filesAnalyzed":false,"licenseConcluded":"NOASSERTION","licenseDeclared":license,"copyrightText":"NOASSERTION"}));
            let mut component =
                json!({"type":"library","name":package["name"],"version":package["version"]});
            if license != "NOASSERTION" {
                component["licenses"] = json!([{"expression":license}]);
            }
            components.push(component);
        }
        let closure: Value =
            serde_json::from_slice(&fs::read(self.root.join("closure.json")).unwrap()).unwrap();
        for (index, (path, entry)) in closure.as_object().unwrap().iter().enumerate() {
            spdx_packages.push(json!({"SPDXID":format!("SPDXRef-Nix-{index}"),"name":path,"downloadLocation":"NOASSERTION","filesAnalyzed":false,"licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION","copyrightText":"NOASSERTION","comment":format!("Captured Nix runtime closure; NAR identity {}",entry["narHash"])}));
            components.push(json!({"type":"library","name":path,"properties":[{"name":"nix:narHash","value":entry["narHash"]},{"name":"nix:references","value":entry["references"].to_string()}]}));
        }
        let spdx = self.add(&format!("{name}.spdx.json"), &serde_json::to_vec(&json!({"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","dataLicense":"CC0-1.0","name":name,"documentNamespace":format!("https://positron.invalid/qualification/{digest}"),"creationInfo":{"created":fs::read_to_string(self.root.join("created.txt")).unwrap().trim(),"creators":["Tool: positron-nix-qualification"]},"packages":spdx_packages,"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-Artifact"}]})).unwrap());
        let cyclonedx = self.add(&format!("{name}.cdx.json"), &serde_json::to_vec(&json!({"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":components})).unwrap());
        let input_identities: Vec<_> = self
            .inventory
            .inputs
            .iter()
            .map(|input| (input, &self.inventory.file(&input.file).unwrap().identity))
            .collect();
        let inputs = hex(&FileIdentity::of(&serde_json::to_vec(&input_identities).unwrap()).sha256);
        let compatibility = hex(&FileIdentity::of(
            &serde_json::to_vec(&self.inventory.compatibility).unwrap(),
        )
        .sha256);
        let provenance = self.add(&format!("{name}.provenance.json"), &serde_json::to_vec(&json!({"_type":"https://in-toto.io/Statement/v1","subject":[{"name":name,"digest":{"sha256":digest}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"https://positron.invalid/nix-qualification/v1","externalParameters":{"source_commit":self.inventory.source_commit,"build_identity":self.inventory.build_identity,"api_version":self.inventory.api_version,"product_version":version,"target":target,"inputs_sha256":inputs,"schema_sha256":hex(&self.inventory.compatibility.schema),"compatibility_sha256":compatibility},"resolvedDependencies":self.inventory.inputs},"runDetails":{"builder":{"id":self.inventory.build_identity}}}})).unwrap());
        let evidence = self.add(&format!("{name}.qualification.json"), &serde_json::to_vec(&json!({"scope":"staged identity and independent functional bytes only; not full release acceptance","artifact_sha256":digest,"builder":self.inventory.build_identity,"independent_builder":self.independent_builder})).unwrap());
        let license_notices = self.add(
            &format!("{name}.LICENSE"),
            include_bytes!("../../../../LICENSE"),
        );
        self.inventory.artifacts.push(Artifact {
            file: file.clone(),
            surface,
            target: target.into(),
            payload: Some(file),
            spdx,
            cyclonedx,
            provenance,
            license_notices,
            evidence,
            publication: Publication {
                registry: "local-qualification".into(),
                immutable_identity: format!("sha256:{digest}"),
                native_subject: name.into(),
                native_revision: None,
                state: PublicationState::Staged,
                proof: format!("{name}.unpublished"),
            },
        });
    }
    pub(super) fn sign(&self) -> Vec<u8> {
        let bytes = self.inventory.canonical_bytes().unwrap();
        let compatibility = serde_json::to_vec(&self.inventory.compatibility).unwrap();
        let schema = self.inventory.compatibility.schema;
        let identity = |role, platform: String, file: &FileIdentity| ReleaseArtifact {
            role,
            platform,
            sha256: file.sha256,
            size: file.size,
            complete: true,
        };
        let mut artifacts = self
            .inventory
            .artifacts
            .iter()
            .filter(|artifact| artifact.surface == Surface::NativeExecutable)
            .map(|artifact| {
                identity(
                    ArtifactRole::NativeExecutable,
                    artifact.target.clone(),
                    &self.inventory.file(&artifact.file).unwrap().identity,
                )
            })
            .collect::<Vec<_>>();
        let api = self
            .inventory
            .artifacts
            .iter()
            .find(|artifact| artifact.surface == Surface::Api)
            .unwrap();
        assert_eq!(
            self.inventory.file(&api.file).unwrap().identity.sha256,
            schema
        );
        artifacts.push(identity(
            ArtifactRole::Schema,
            "any".into(),
            &self.inventory.file(&api.file).unwrap().identity,
        ));
        artifacts.push(identity(
            ArtifactRole::CompatibilityManifest,
            "any".into(),
            &FileIdentity::of(&compatibility),
        ));
        for (role, files) in [
            (
                ArtifactRole::Sbom,
                self.inventory
                    .artifacts
                    .iter()
                    .map(|artifact| (&artifact.spdx, &artifact.cyclonedx))
                    .collect::<Vec<_>>(),
            ),
            (
                ArtifactRole::Provenance,
                self.inventory
                    .artifacts
                    .iter()
                    .map(|artifact| (&artifact.provenance, &artifact.provenance))
                    .collect(),
            ),
        ] {
            let metadata = serde_json::to_vec(
                &files
                    .iter()
                    .map(|(first, second)| {
                        (
                            self.inventory.file(first).unwrap(),
                            self.inventory.file(second).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            let name = match role {
                ArtifactRole::Sbom => "sbom-index.json",
                _ => "provenance-index.json",
            };
            fs::write(self.root.join(name), &metadata).unwrap();
            artifacts.push(identity(role, "any".into(), &FileIdentity::of(&metadata)));
        }
        artifacts.push(identity(
            ArtifactRole::ReleaseInventory,
            "any".into(),
            &FileIdentity::of(&bytes),
        ));
        let manifest = ReleaseManifest {
            version: self.inventory.version,
            source_commit: self.inventory.source_commit.clone(),
            upgrade_from: vec![],
            artifacts,
            compatibility: self.inventory.compatibility.clone(),
        };
        let pair = Ed25519KeyPair::from_seed_unchecked(&[19; 32]).unwrap();
        let signed = SignedReleaseManifest::new(
            manifest.clone(),
            pair.sign(&manifest.signing_message().unwrap())
                .as_ref()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let signed_bytes = signed.to_bytes().unwrap();
        let verified = SignedReleaseManifest::from_bytes(&signed_bytes)
            .unwrap()
            .verify_signature(&ReleaseSigningPublicKey::new(
                pair.public_key().as_ref().try_into().unwrap(),
            ))
            .unwrap();
        assert_eq!(verified.manifest(), &manifest);
        let reference = verified
            .manifest()
            .artifacts
            .iter()
            .find(|artifact| artifact.role == ArtifactRole::ReleaseInventory)
            .unwrap();
        assert_eq!(reference.sha256, FileIdentity::of(&bytes).sha256);
        fs::write(self.root.join("inventory.json"), bytes).unwrap();
        fs::write(self.root.join("compatibility.json"), compatibility).unwrap();
        fs::write(
            self.root.join("test-signing-key.pub"),
            pair.public_key().as_ref(),
        )
        .unwrap();
        fs::write(self.root.join("manifest.signed"), &signed_bytes).unwrap();
        signed_bytes
    }
}
