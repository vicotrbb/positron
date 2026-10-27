//! Private build-time inputs for the actual Compose lifecycle integration.
#![cfg(unix)]
#[path = "support/upgrade_release.rs"]
mod release;
use age::secrecy::ExposeSecret;
use std::{fs, io::Read, os::unix::fs::PermissionsExt, path::PathBuf};

#[test]
#[ignore = "prepares private signed inputs for the actual same-image Compose deployment"]
fn prepare_compose_lifecycle_inputs() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(
        std::env::var_os("POSITRON_TEST_COMPOSE_FIXTURE_ROOT").ok_or("fixture root")?,
    );
    let source = PathBuf::from(
        std::env::var_os("POSITRON_TEST_COMPOSE_CURRENT_BINARY").ok_or("source executable")?,
    );
    let candidate = PathBuf::from(
        std::env::var_os("POSITRON_TEST_UPGRADE_BINARY").ok_or("candidate executable")?,
    );
    let export = root.join("export");
    fs::create_dir(&export)?;
    fs::set_permissions(&export, fs::Permissions::from_mode(0o700))?;
    let mut query = String::new();
    std::io::stdin().take(1025).read_to_string(&mut query)?;
    if query.is_empty() || query.len() > 1024 {
        return Err("bounded query credential required".into());
    }
    let current = export.join("current-executable");
    let target = export.join("candidate-executable");
    fs::copy(source, &current)?;
    fs::copy(candidate, &target)?;
    let (_, digest) = release::configuration(
        &root,
        positron_config::ExecutableDistribution::Native,
        positron_kernel::FormatEpoch::CATALOG_V2.value(),
        &query,
        (&current, &target),
        (
            &std::env::var("POSITRON_TEST_SOURCE_COMMIT")?,
            &std::env::var("POSITRON_TEST_CANDIDATE_COMMIT")?,
        ),
    )?;
    let request = positron_api::log_query::LogQueryRequest {
        pipeline: "logs | range query_time 0 100 | limit 16".into(),
        budget: Some(positron_api::log_query::LogQueryBudget {
            scanned_bytes: 1_048_576,
            decoded_records: 16,
            output_rows: 16,
            output_bytes: 16_384,
            memory_bytes: 1_048_576,
            cpu_work_units: 15,
            wall_seconds: 5,
            maximum_time_range_nanoseconds: 100,
        }),
    };
    fs::write(export.join("query.json"), request.encode()?)?;
    let identity = age::x25519::Identity::generate();
    fs::write(
        export.join("recovery.identity"),
        identity.to_string().expose_secret(),
    )?;
    fs::write(export.join("recipient"), identity.to_public().to_string())?;
    fs::write(
        export.join("candidate-digest"),
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )?;
    let archive = positron_release::native_archive(
        format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH).parse()?,
        &fs::read(&target)?,
    )?;
    fs::write(root.join("candidate.tar.gz"), archive)?;
    for file in fs::read_dir(&export)? {
        fs::set_permissions(file?.path(), fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
