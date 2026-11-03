//! Reproduce the standalone Rust SDK from the canonical public-interface owner.
use std::{error::Error, fs, path::Path};

fn copy_tree(source: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(destination)?;
    let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if entry.file_type()?.is_file() {
            let source_path = entry.path();
            if source_path
                .extension()
                .is_some_and(|extension| extension == "rs")
                && source.components().any(|part| part.as_os_str() == "tests")
            {
                let contents = fs::read_to_string(&source_path)?
                    .replace("positron_api", "positron_sdk")
                    .replace("../../../api/", "../api/")
                    .replace(
                        "../../positron-runtime/tests/native_transport/fixtures/api-test-cert.pem",
                        "fixtures/api-test-cert.pem",
                    )
                    .replace(
                        "../positron-runtime/tests/native_transport/fixtures/api-test-cert.pem",
                        "tests/fixtures/api-test-cert.pem",
                    )
                    .replace("../../deploy/nix", "tests/fixtures/nix");
                fs::write(&target, contents)?;
                let status = std::process::Command::new("rustfmt")
                    .args(["--edition", "2024", "--config-path"])
                    .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rustfmt.toml"))
                    .arg(&target)
                    .status()?;
                if !status.success() {
                    return Err("format generated SDK test".into());
                }
            } else {
                fs::copy(source_path, target)?;
            }
        } else {
            return Err("SDK source must contain only regular files and directories".into());
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let owner = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = owner
        .parent()
        .and_then(Path::parent)
        .ok_or("repository root")?;
    let output = std::env::args_os()
        .nth(1)
        .ok_or("usage: generate_rust_sdk OUTPUT")?;
    let output = Path::new(&output);
    fs::create_dir_all(output)?;
    copy_tree(&owner.join("src"), &output.join("src"))?;
    copy_tree(&owner.join("build_support"), &output.join("build_support"))?;
    copy_tree(&owner.join("tests"), &output.join("tests"))?;
    fs::create_dir_all(output.join("tests/fixtures/nix"))?;
    fs::copy(
        root.join("crates/positron-runtime/tests/native_transport/fixtures/api-test-cert.pem"),
        output.join("tests/fixtures/api-test-cert.pem"),
    )?;
    for filename in ["test_service_check.py", "service-check.py"] {
        fs::copy(
            root.join("deploy/nix").join(filename),
            output.join("tests/fixtures/nix").join(filename),
        )?;
    }
    fs::copy(root.join("LICENSE"), output.join("LICENSE"))?;
    copy_tree(&root.join("sdk/examples"), &output.join("examples"))?;
    copy_tree(
        &root.join("api/positron/v1"),
        &output.join("api/positron/v1"),
    )?;
    let build = fs::read_to_string(owner.join("build.rs"))?.replace("../../api", "api");
    fs::write(output.join("build.rs"), build)?;
    let manifest = fs::read_to_string(owner.join("Cargo.toml"))?;
    let manifest = manifest
        .replace("name = \"positron-api\"", "name = \"positron-sdk\"")
        .replace("description = \"Positron public-interface and transport boundary\"", "description = \"Generated typed Rust client for the Positron v1 public API\"")
        .replace("publish = false", "publish = true\nreadme = \"README.md\"\ninclude = [\"src/**\", \"api/**\", \"build_support/**\", \"build.rs\", \"Cargo.toml\", \"README.md\", \"LICENSE\", \"tests/**/*.rs\", \"tests/fixtures/**/*.json\", \"tests/fixtures/**/*.pem\", \"tests/fixtures/**/*.py\", \"examples/*.rs\"]");
    // Cargo resolves workspace metadata when packaging and preserves exact pinned inputs.
    let manifest = format!(
        "{manifest}\n[package.metadata.positron]\napi_version = \"positron.v1\"\nschema_digest = \"{}\"\nrelease_manifest_surface = \"SdkRust\"\nregistry = \"https://crates.io\"\ngenerator = \"prost=0.14.3,pbjson=0.9.0,protoc-bin-vendored=3.2.0\"\n",
        positron_api::generated::SchemaDigest::canonical().as_str()
    );
    fs::write(output.join("Cargo.toml"), manifest)?;
    fs::copy(root.join("sdk/rust.md"), output.join("README.md"))?;
    Ok(())
}
