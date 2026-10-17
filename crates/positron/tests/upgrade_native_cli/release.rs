//! Independently signed fixture metadata; no distribution qualification claim.
use super::*;
fn release(
    epoch: u32,
    version: ProductVersion,
    executable: &Path,
    key: &Ed25519KeyPair,
) -> Result<VerifiedReleaseManifest> {
    let bytes = fs::read(executable)?;
    let digest = Sha256::digest(&bytes).into();
    let backup = positron_backup::BackupFormatEpoch::NATIVE_WRITER.value();
    let manifest = ReleaseManifest {
        version,
        upgrade_from: vec![ProductVersion {
            major: 0,
            minor: 0,
            patch: 0,
        }],
        // Fixture metadata is signed independently; only executable bytes and
        // the compiled package version are real build identities in this test.
        source_commit: "9fd68fd9eaa72ed45e070412d30656fda1277d79".into(),
        artifacts: [
            ArtifactRole::NativeExecutable,
            ArtifactRole::Schema,
            ArtifactRole::CompatibilityManifest,
            ArtifactRole::Sbom,
            ArtifactRole::Provenance,
        ]
        .into_iter()
        .map(|role| ReleaseArtifact {
            role,
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            sha256: digest,
            size: bytes.len() as u64,
            complete: true,
        })
        .collect(),
        compatibility: ReleaseCompatibility {
            config_schema: 1,
            previous_config_schema: None,
            persistent: FormatCompatibility {
                readable_epochs: vec![epoch],
                writable_epoch: epoch,
                migrations: vec![],
            },
            backup: FormatCompatibility {
                readable_epochs: vec![backup],
                writable_epoch: backup,
                migrations: vec![],
            },
            receiver: [1; 32],
            api: [2; 32],
            query: [3; 32],
            schema: [4; 32],
            crd: [5; 32],
            operator: [6; 32],
        },
    };
    let mut signed = b"positron.release-manifest.v1\0".to_vec();
    signed.extend(manifest.canonical_bytes()?);
    let signature = key
        .sign(&signed)
        .as_ref()
        .try_into()
        .map_err(|_| "signature")?;
    Ok(
        SignedReleaseManifest::new(manifest, signature)?.verify(&ProjectTrustRoot::new(
            key.public_key()
                .as_ref()
                .try_into()
                .map_err(|_| "trust root")?,
        ))?,
    )
}
pub(super) fn configuration(
    root: &Path,
    epoch: u32,
    query: &str,
) -> Result<(positron_config::EffectiveConfiguration, [u8; 32])> {
    let key =
        Ed25519KeyPair::from_seed_unchecked(&[0x93; 32]).map_err(|_| "fixture signing key")?;
    let executable = std::env::current_exe()?;
    let source = release(
        epoch,
        ProductVersion::parse_exact(env!("CARGO_PKG_VERSION"))?,
        &executable,
        &key,
    )?;
    let target = release(
        epoch,
        ProductVersion {
            major: 0,
            minor: 0,
            patch: 1,
        },
        &executable,
        &key,
    )?;
    let export = root.join("export");
    let trust = export.join("project.pub");
    let current = export.join("current.manifest");
    let candidate = export.join("candidate.manifest");
    let credential = export.join("query.credential");
    for (path, bytes) in [
        (&trust, key.public_key().as_ref()),
        (&current, source.signed_bytes()),
        (&candidate, target.signed_bytes()),
        (&credential, query.as_bytes()),
    ] {
        fs::write(path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    let artifacts = target
        .manifest()
        .artifacts
        .iter()
        .map(|_| format!("{executable:?}"))
        .collect::<Vec<_>>()
        .join(",");
    let text = format!(
        "schema_version=1\n[storage]\ndata_directory={:?}\nsecrets_directory={:?}\n\
        [release.installation]\nproject_trust_root_file={trust:?}\ncurrent_manifest_file={current:?}\n\
        candidate_manifest_file={candidate:?}\ncandidate_artifact_files=[{artifacts}]\nquery_credential_file={credential:?}\n",
        root.join("data"),
        root.join("secrets")
    );
    let path = root.join("positron.toml");
    fs::write(&path, text)?;
    let effective = positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            Some(&path),
            [] as [(&str, &str); 0],
            [] as [(&str, &str); 0],
        )
        .map_err(|_| "fixture configuration inputs")?,
    )?;
    Ok((effective, target.digest()))
}
