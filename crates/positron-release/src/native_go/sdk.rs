//! Inspect generated module contents before signed release construction.
use super::*;
pub(crate) const MODULE: &str = "github.com/vicotrbb/positron/sdk/go";
pub(crate) fn inspect(
    bytes: &[u8],
    version: &str,
    source: &str,
    api: &str,
    schema: &[u8; 32],
) -> Result<(), ReleaseError> {
    if bytes.len() > MAX_ARCHIVE {
        return Err(ReleaseError::LimitExceeded);
    }
    let _hashes = module_hashes(bytes, MODULE, &format!("v{version}"))?;
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| ReleaseError::Invalid)?;
    let prefix = format!("{MODULE}@v{version}/");
    let mut read = |name: &str| -> Result<Vec<u8>, ReleaseError> {
        let index = archive
            .index_for_name(&format!("{prefix}{name}"))
            .ok_or(ReleaseError::IdentityMismatch)?;
        let mut entry = archive
            .by_index_raw(index)
            .map_err(|_| ReleaseError::Invalid)?;
        if entry.size() > 16 << 20 {
            return Err(ReleaseError::LimitExceeded);
        }
        let mut result = Vec::new();
        let mut reader: Box<dyn Read> = match entry.compression() {
            zip::CompressionMethod::Stored => Box::new(&mut entry),
            zip::CompressionMethod::DEFLATE => {
                Box::new(flate2::read::DeflateDecoder::new(&mut entry))
            },
            _ => return Err(ReleaseError::Unsupported),
        };
        reader
            .read_to_end(&mut result)
            .map_err(|_| ReleaseError::Invalid)?;
        Ok(result)
    };
    if read("go.mod")? != format!("module {MODULE}\n\ngo 1.24.0\n").as_bytes() {
        return Err(ReleaseError::IdentityMismatch);
    }
    let release: Value =
        serde_json::from_slice(&read("release.json")?).map_err(|_| ReleaseError::Invalid)?;
    for (key, expected) in [
        ("module", MODULE),
        ("version", version),
        ("source_commit", source),
        ("api_version", api),
        ("schema_digest", crate::inventory::hex(schema).as_str()),
        ("release_manifest_surface", "SdkGo"),
        ("registry", "https://proxy.golang.org"),
        (
            "generator",
            "positron-api=1,go=1.24.0,protoc-bin-vendored=3.2.0",
        ),
    ] {
        if release.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    if <[u8; 32]>::from(Sha256::digest(read("api/positron.proto")?)) != *schema
        || read("api/schema.sha256")? != format!("{}\n", crate::inventory::hex(schema)).as_bytes()
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    let contract: Value =
        serde_json::from_slice(&read("contract.json")?).map_err(|_| ReleaseError::Invalid)?;
    if contract["api_version"] != api || contract["schema_digest"] != crate::inventory::hex(schema)
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    for name in [
        "types.go",
        "methods.go",
        "codec.go",
        "client.go",
        "query.go",
        "README.md",
        "LICENSE",
    ] {
        if read(name)?.is_empty() {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    Ok(())
}
