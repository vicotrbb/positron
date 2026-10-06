#[test]
fn live_recipient_wire_round_trip_accepts_native_x25519_only() {
    let identity = age::x25519::Identity::generate();
    let encoded = match super::super::live_control::LiveBundleRequest::encode(&[identity
        .to_public()
        .to_string()])
    {
        Ok(encoded) => encoded,
        Err(_) => panic!("native recipient encodes"),
    };
    let request = super::super::live_control::LiveBundleRequest::parse(&encoded)
        .expect("native recipient decodes");
    assert_eq!(request.recipients.len(), 1);
    assert!(
        super::super::live_control::LiveBundleRequest::parse(
            b"version=1\nrecipient=ssh-ed25519 bad\n"
        )
        .is_err()
    );
}

#[test]
fn live_bundle_request_round_trips_the_explicit_data_directory_retention_choice() {
    let identity = age::x25519::Identity::generate();
    let encoded = super::super::live_control::LiveBundleRequest::encode_with_retention(
        &[identity.to_public().to_string()],
        super::super::privacy::IdentifierRetention::DataDirectory,
    )
    .unwrap_or_else(|_| panic!("typed retention request encodes"));
    let request = super::super::live_control::LiveBundleRequest::parse(&encoded)
        .expect("typed retention request decodes");
    assert_eq!(
        request.identifier_retention,
        super::super::privacy::IdentifierRetention::DataDirectory
    );
    assert!(
        super::super::live_control::LiveBundleRequest::parse(
            b"version=1\nretain_identifier=secrets_directory\nrecipient=age1invalid\n"
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn fenced_control_bundle_uses_current_administrator_facts_without_retired_runtime_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    use std::{
        io::{Cursor, Read, Write},
        net::TcpStream,
        os::unix::fs::PermissionsExt,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use age::{Decryptor, Identity};
    use positron_config::{
        CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve,
    };
    use positron_domain::identity::Scope;
    use positron_governance::{
        AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
        ResourceGeneration,
    };
    use positron_kernel::MountQualification;
    use positron_runtime::{
        ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, InitializationPlan,
        InstanceBootstrap, NativeBindings, NativeHost, ProcessPhase, ServeConfiguration,
        ShutdownTrigger,
    };

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-fenced-bundle-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    std::fs::create_dir_all(&data)?;
    std::fs::create_dir_all(&secrets)?;
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
    let control = std::path::Path::new("/tmp").join(format!("positron-fenced-bundle-{nonce}.sock"));
    let local_key = secrets.join("local-root-key.v1");
    let source = format!(
        "schema_version = 1\n[listener]\ncontrol_path = \"{}\"\noperations_bind_address = \"127.0.0.1:0\"\napi_bind_address = \"127.0.0.1:0\"\notlp_grpc_bind_address = \"127.0.0.1:0\"\notlp_http_bind_address = \"127.0.0.1:0\"\nloki_push_bind_address = \"127.0.0.1:0\"\noperations_transport = \"plaintext\"\napi_transport = \"plaintext\"\notlp_grpc_transport = \"plaintext\"\notlp_http_transport = \"plaintext\"\nloki_push_transport = \"plaintext\"\n[storage]\ndata_directory = \"{}\"\nsecrets_directory = \"{}\"\n[security]\nlocal_key_file = \"{}\"\n",
        control.display(),
        data.display(),
        secrets.display(),
        local_key.display(),
    );
    let effective = Arc::new(resolve(ConfigurationInputs::try_new(
        Some(&source),
        EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?)?);
    let paths = BootstrapPaths::with_local_key(
        &data,
        &secrets,
        effective.local_key_file().as_path(),
        MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let administrator = InstanceBootstrap::claim(&paths)?;
    let (revoked_credential, signature_identity) = {
        let instance = InstanceBootstrap::reopen(&paths)?;
        let actor = instance.attribute(
            PresentedCredential::parse(administrator.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?;
        let stale = instance.create_api_key(
            actor,
            Scope::Query,
            None,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x82; 16])?,
        )?;
        let secret = stale
            .secret()
            .ok_or("revoked credential secret")?
            .to_owned();
        let identity = instance.support_bundle_manifest_signer(actor)?.identity();
        instance.revoke_api_key(
            actor,
            stale.principal_id(),
            ResourceGeneration::new(2)?,
            AdministrativeIdempotencyKey::new([0x83; 16])?,
        )?;
        (secret, identity)
    };
    let host = NativeHost::new(NativeBindings::from_effective(&effective)?)
        .with_control_diagnostics(Arc::new(super::super::LiveSupportBundleCollector));
    let mut process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::clone(&effective)),
        HostInputs::new(&host, &host),
    )?;
    let operations = process
        .bound_endpoints()
        .iter()
        .find(|endpoint| endpoint.role() == positron_runtime::ListenerRole::Operations)
        .and_then(positron_runtime::BoundEndpoint::socket_address)
        .ok_or("operations endpoint")?;
    let mut status = TcpStream::connect(operations)?;
    status.write_all(
        format!(
            "GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            administrator.secret()
        )
        .as_bytes(),
    )?;
    let mut status_response = String::new();
    status.read_to_string(&mut status_response)?;
    assert!(
        status_response.starts_with("HTTP/1.1 200"),
        "{status_response}"
    );
    let identity = age::x25519::Identity::generate();
    let request = super::super::live_control::LiveBundleRequest::encode_with_retention(
        &[identity.to_public().to_string()],
        super::super::privacy::IdentifierRetention::DataDirectory,
    )
    .map_err(|_| "encode authorized live bundle request")?;
    let (head, ciphertext) = control_bundle(&control, administrator.secret(), &request)?;
    assert!(head.starts_with(b"HTTP/1.1 200 "), "{head:?}");
    let decryptor = Decryptor::new(Cursor::new(ciphertext))?;
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn Identity))?;
    let mut archive = Vec::new();
    reader.read_to_end(&mut archive)?;
    let archive = String::from_utf8_lossy(&archive);
    assert!(archive.contains("inspection_owner=maintenance_coordinator"));
    assert!(archive.contains(data.to_string_lossy().as_ref()));
    assert!(!archive.contains(secrets.to_string_lossy().as_ref()));
    assert!(archive.contains("retained_identifier_classes=data_directory"));
    assert!(archive.contains("identifier_pseudonymization=data_directory_retained"));
    for required in [
        "queued=",
        "clock_uncertain=",
        "running_no_durable_progress_slo_breaches=",
        "running_no_durable_progress_slo_unknown=",
        "checkpointed_tasks=",
        "paused_tasks=",
        "conflicted_tasks=",
        "durable_operations=",
        "active_durable_operations=",
        "snapshot_leases=",
    ] {
        assert!(
            archive.contains(required),
            "missing {required} from {archive}"
        );
    }
    assert!(!archive.contains("status=not_exported_by_current_diagnostics_contract"));
    process
        .services()
        .ok_or("services absent")?
        .request_integrity_fence();
    assert!(process.apply_pending_integrity_fence());
    assert_eq!(process.health().phase(), ProcessPhase::Fenced);
    assert!(process.configuration().is_none());

    let (head, ciphertext) = control_bundle(&control, administrator.secret(), &request)?;
    assert!(head.starts_with(b"HTTP/1.1 200 "), "{head:?}");
    assert!(
        !ciphertext.is_empty(),
        "fenced bundle must return archive bytes"
    );

    let decryptor = Decryptor::new(Cursor::new(ciphertext))?;
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn Identity))?;
    let mut archive = Vec::new();
    reader.read_to_end(&mut archive)?;
    super::super::SupportBundle::verify_signed_archive(&archive, signature_identity)
        .map_err(|_| "fenced manifest signature")?;
    let archive = String::from_utf8_lossy(&archive);
    assert!(archive.contains("process_phase=fenced"));
    assert!(archive.contains("DOCTOR_FENCED_OWNER_VERIFIED"));
    assert!(archive.contains("configuration_runtime=unavailable_retired_after_fence"));
    assert!(archive.contains("manifest-signature.txt"));
    assert!(archive.contains("requested_retained_identifier_classes=data_directory"));
    assert!(archive.contains("retained_identifier_classes=none"));
    assert!(
        archive.contains("identifier_retention_outcome=unavailable_retired_runtime_configuration")
    );
    assert!(archive.contains("identifier_pseudonymization=ephemeral_per_bundle"));
    assert!(!archive.contains(data.to_string_lossy().as_ref()));
    assert!(!archive.contains("status=healthy"));
    assert!(!archive.contains("process_phase=serving"));
    assert!(!archive.contains(administrator.secret()));

    for rejected in ["malformed bearer\n", revoked_credential.as_str()] {
        let (head, _) = control_bundle(&control, rejected, &request)?;
        assert!(head.starts_with(b"HTTP/1.1 401 "), "{head:?}");
    }
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
fn control_bundle(
    control: &std::path::Path,
    bearer: &str,
    body: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };

    let mut stream = UnixStream::connect(control)?;
    stream.write_all(
        format!(
            "POST /control/support-bundle HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {bearer}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len(),
        )
        .as_bytes(),
    )?;
    stream.write_all(body)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let separator = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or("control response separator")?;
    Ok((
        response[..separator].to_vec(),
        response[separator + 4..].to_vec(),
    ))
}
