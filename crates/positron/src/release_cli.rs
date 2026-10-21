//! Offline Release Trust commands. No database, network, signing key, or publication side effect.
use positron_kernel::release_manifest::{
    MAX_RELEASE_MANIFEST_BYTES, ProductVersion, ReleaseManifest, SignedReleaseManifest,
};
use positron_release::*;
use std::{collections::BTreeMap, io::Write, path::Path, process::ExitCode};

const HELP: &str = "positron release homebrew --inventory FILE --out NEW_FILE\npositron release archive --target TARGET --binary FILE --out NEW_FILE\npositron release rpm-payload --package FILE --out NEW_FILE\npositron release inspect --directory DIR --file NAME [--canaries FILE]\npositron release construct --inventory FILE --bundle DIR --rebuild DIR --out NEW_DIR [--upgrade-from FILE] [--canaries FILE]\npositron release attach --manifest FILE --signature FILE --trust FILE --out NEW_FILE\npositron release verify --manifest FILE --inventory FILE --trust FILE --bundle DIR --rebuild DIR [--target TARGET] [--canaries FILE]\npositron release trust-message --snapshot FILE --out NEW_FILE\npositron release trust-attach --snapshot FILE --signature FILE --root FILE --out NEW_FILE\nConstruction emits unsigned inputs. Only verify authenticates a complete published release set.\n";
pub(crate) fn run(arguments: impl Iterator<Item = String>) -> ExitCode {
    let output = execute(arguments).and_then(|bytes| {
        std::io::stdout()
            .lock()
            .write_all(&bytes)
            .map_err(|_| ReleaseError::Unavailable)
    });
    match output {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            match writeln!(std::io::stderr().lock(), "{error}") {
                Ok(()) | Err(_) => {},
            }
            ExitCode::from(2)
        },
    }
}
fn execute(mut arguments: impl Iterator<Item = String>) -> Result<Vec<u8>, ReleaseError> {
    let command = arguments.next().ok_or(ReleaseError::Invalid)?;
    if command == "--help" && arguments.next().is_none() {
        return Ok(HELP.as_bytes().to_vec());
    }
    let options = Options::parse(arguments)?;
    let canaries = options.canaries()?;
    let output = match command.as_str() {
        "homebrew" => {
            options.only(&["inventory", "out"])?;
            let inventory =
                ReleaseInventory::from_bytes(&options.read("inventory", MAX_INVENTORY_BYTES)?)?;
            let formula = homebrew_formula(&inventory)?;
            write_release_file(Path::new(options.get("out")?), formula.as_bytes())?;
            let identity = FileIdentity::of(formula.as_bytes());
            serde_json::json!({"state":"unsigned-homebrew-formula","sha256":hex(&identity.sha256),"size":identity.size})
        },
        "archive" => {
            options.only(&["target", "binary", "out"])?;
            let target = options.get("target")?.parse()?;
            let archive = native_archive(target, &options.read("binary", 500 << 20)?)?;
            write_release_file(Path::new(options.get("out")?), &archive)?;
            let identity = FileIdentity::of(&archive);
            serde_json::json!({"state":"unsigned-native-archive","sha256":hex(&identity.sha256),"size":identity.size})
        },
        "rpm-payload" => {
            options.only(&["package", "out"])?;
            let package = options.read("package", 64 << 20)?;
            let payload = rpm_functional_payload(&package)?;
            write_release_file(Path::new(options.get("out")?), payload)?;
            let identity = FileIdentity::of(payload);
            serde_json::json!({"state":"unsigned-rpm-functional-payload","sha256":hex(&identity.sha256),"size":identity.size})
        },
        "inspect" => {
            options.only(&["directory", "file", "canaries"])?;
            let identity = inspect_file(
                Path::new(options.get("directory")?),
                options.get("file")?,
                &canaries,
            )?;
            serde_json::json!({"sha256":hex(&identity.sha256),"size":identity.size})
        },
        "construct" => {
            options.only(&[
                "inventory",
                "bundle",
                "rebuild",
                "out",
                "upgrade-from",
                "canaries",
            ])?;
            let inventory =
                ReleaseInventory::from_bytes(&options.read("inventory", MAX_INVENTORY_BYTES)?)?;
            let upgrade_from: Vec<ProductVersion> = options
                .values
                .get("upgrade-from")
                .map(|path| {
                    read_release_file(Path::new(path), 4096).and_then(|bytes| {
                        serde_json::from_slice(&bytes).map_err(|_| ReleaseError::Invalid)
                    })
                })
                .transpose()?
                .unwrap_or_default();
            let construction = construct_release(
                &inventory,
                Path::new(options.get("bundle")?),
                Path::new(options.get("rebuild")?),
                &canaries,
                upgrade_from,
            )?;
            let directory = Path::new(options.get("out")?);
            create_directory(directory)?;
            write_release_file(
                &directory.join("inventory.json"),
                &construction.inventory_bytes,
            )?;
            write_release_file(
                &directory.join("compatibility.json"),
                &construction.compatibility_bytes,
            )?;
            write_release_file(
                &directory.join("signing-message.bin"),
                &construction.signing_message()?,
            )?;
            write_release_file(
                &directory.join("manifest.json"),
                &construction
                    .manifest
                    .canonical_bytes()
                    .map_err(|_| ReleaseError::Invalid)?,
            )?;
            serde_json::json!({"state":"unsigned-construction","artifacts":inventory.artifacts.len()})
        },
        "attach" => {
            options.only(&["manifest", "signature", "trust", "out"])?;
            let bytes = options.read("manifest", MAX_RELEASE_MANIFEST_BYTES)?;
            let manifest: ReleaseManifest =
                serde_json::from_slice(&bytes).map_err(|_| ReleaseError::Invalid)?;
            if manifest
                .canonical_bytes()
                .map_err(|_| ReleaseError::Invalid)?
                != bytes
            {
                return Err(ReleaseError::Invalid);
            }
            let signature = options
                .read("signature", 64)?
                .try_into()
                .map_err(|_| ReleaseError::Invalid)?;
            let signed = SignedReleaseManifest::new(manifest, signature)
                .and_then(|manifest| manifest.to_bytes())
                .map_err(|_| ReleaseError::Invalid)?;
            let trust = options.trust()?;
            let verified = trust.verify_manifest(&signed, now()?)?;
            write_release_file(Path::new(options.get("out")?), &signed)?;
            serde_json::json!({"state":"authenticated-manifest-only","manifest_sha256":hex(&verified.digest())})
        },
        "verify" => {
            options.only(&[
                "manifest",
                "inventory",
                "trust",
                "bundle",
                "rebuild",
                "target",
                "canaries",
            ])?;
            let installed = options.trust()?;
            let trust = installed.verify(now()?)?;
            let target =
                options.values.get("target").cloned().unwrap_or_else(|| {
                    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
                });
            let report = verify_release(
                &options.read("manifest", MAX_RELEASE_MANIFEST_BYTES + 64)?,
                &options.read("inventory", MAX_INVENTORY_BYTES)?,
                installed.release_signer,
                &trust,
                Path::new(options.get("bundle")?),
                Path::new(options.get("rebuild")?),
                &target,
                &canaries,
            )?;
            serde_json::json!({"state":"verified-complete-published-set","manifest_sha256":hex(&report.manifest().digest()),"artifacts":report.artifact_count(),"trust_sequence":report.trust_sequence(),"verified_at_unix_seconds":report.verified_at_unix_seconds()})
        },
        "trust-message" => {
            options.only(&["snapshot", "out"])?;
            let snapshot = TrustSnapshot::from_bytes(&options.read("snapshot", MAX_TRUST_BYTES)?)?;
            write_release_file(Path::new(options.get("out")?), &snapshot.signing_message()?)?;
            serde_json::json!({"state":"unsigned-trust-input","sequence":snapshot.sequence})
        },
        "trust-attach" => {
            options.only(&["snapshot", "signature", "root", "out"])?;
            let snapshot = TrustSnapshot::from_bytes(&options.read("snapshot", MAX_TRUST_BYTES)?)?;
            let mut signed = options.read("signature", 64)?;
            if signed.len() != 64 {
                return Err(ReleaseError::Invalid);
            }
            signed.extend(snapshot.canonical_bytes()?);
            let root: InstalledProjectTrustRoot = serde_json::from_slice(
                &read_installed_trust_file(Path::new(options.get("root")?), 4096)?,
            )
            .map_err(|_| ReleaseError::Invalid)?;
            let verified = root.verify(&signed, now()?)?;
            write_release_file(Path::new(options.get("out")?), &signed)?;
            serde_json::json!({"state":"authenticated-trust-snapshot","sequence":verified.sequence()})
        },
        _ => return Err(ReleaseError::Invalid),
    };
    let mut bytes = serde_json::to_vec(&output).map_err(|_| ReleaseError::Invalid)?;
    bytes.push(b'\n');
    Ok(bytes)
}
struct Options {
    values: BTreeMap<String, String>,
}
impl Options {
    fn parse(mut arguments: impl Iterator<Item = String>) -> Result<Self, ReleaseError> {
        let mut values = BTreeMap::new();
        while let Some(key) = arguments.next() {
            let key = key
                .strip_prefix("--")
                .filter(|key| !key.is_empty())
                .ok_or(ReleaseError::Invalid)?
                .to_owned();
            let value = arguments
                .next()
                .filter(|value| !value.is_empty() && value.len() <= 4096)
                .ok_or(ReleaseError::Invalid)?;
            if values.len() >= 16 || values.insert(key, value).is_some() {
                return Err(ReleaseError::Invalid);
            }
        }
        Ok(Self { values })
    }
    fn only(&self, allowed: &[&str]) -> Result<(), ReleaseError> {
        if self
            .values
            .keys()
            .any(|key| !allowed.contains(&key.as_str()))
        {
            return Err(ReleaseError::Invalid);
        }
        Ok(())
    }
    fn get(&self, key: &str) -> Result<&str, ReleaseError> {
        self.values
            .get(key)
            .map(String::as_str)
            .ok_or(ReleaseError::Invalid)
    }
    fn read(&self, key: &str, maximum: usize) -> Result<Vec<u8>, ReleaseError> {
        read_release_file(Path::new(self.get(key)?), maximum)
    }
    fn trust(&self) -> Result<InstalledReleaseTrust, ReleaseError> {
        InstalledReleaseTrust::from_bytes(&read_installed_trust_file(
            Path::new(self.get("trust")?),
            MAX_INSTALLED_TRUST_BYTES,
        )?)
    }
    fn canaries(&self) -> Result<zeroize::Zeroizing<Vec<Vec<u8>>>, ReleaseError> {
        let value = self
            .values
            .get("canaries")
            .map(|path| read_release_file(Path::new(path), 16_384))
            .transpose()?;
        let value = value.map(zeroize::Zeroizing::new);
        let value = value
            .as_ref()
            .map(|bytes| serde_json::from_slice(bytes).map_err(|_| ReleaseError::Invalid))
            .transpose()?
            .unwrap_or_default();
        Ok(zeroize::Zeroizing::new(value))
    }
}
fn now() -> Result<u64, ReleaseError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| ReleaseError::StaleTrust)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn create_directory(path: &Path) -> Result<(), ReleaseError> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| ReleaseError::Unavailable)
}
