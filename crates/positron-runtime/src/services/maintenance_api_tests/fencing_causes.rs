//! Real authenticated storage/key failures at the public startup boundary.
use super::*;

#[test]
fn missing_acknowledged_tail_exposes_durability_fence() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("acknowledged-tail").encode_to_vec())?;
    let active = fixture
        .sealed_segments_directory()
        .parent()
        .ok_or("segments")?
        .join("active");
    let mut segments = fs::read_dir(active)?.collect::<Result<Vec<_>, _>>()?;
    segments.retain(|entry| {
        entry
            .path()
            .extension()
            .is_some_and(|value| value == "segment")
    });
    segments.sort_by_key(|entry| entry.metadata().map(|value| value.len()).unwrap_or(0));
    let segment = segments.last().ok_or("acknowledged segment")?.path();
    let file = fs::OpenOptions::new().write(true).open(&segment)?;
    file.set_len(file.metadata()?.len().checked_sub(1).ok_or("tail")?)?;
    file.sync_all()?;
    let evidence = fs::read(&segment)?;
    drop(services);
    drop(initialized);
    assert_real_fence(
        &fixture,
        &administrator,
        "durability_frontier_ambiguity",
        crate::IntegrityFenceReason::DurabilityAmbiguity,
    )?;
    assert_eq!(
        fs::read(segment)?,
        evidence,
        "startup cannot repair acknowledged loss"
    );
    Ok(())
}

#[test]
fn mismatched_tenant_envelope_exposes_key_fence() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    substitute_tenant_envelope(&initialized)?;
    drop(initialized);
    assert_real_fence(
        &fixture,
        &administrator,
        "key_envelope_mismatch",
        crate::IntegrityFenceReason::KeyEnvelopeMismatch,
    )
}

fn assert_real_fence(
    fixture: &Fixture,
    administrator: &str,
    label: &str,
    reason: crate::IntegrityFenceReason,
) -> Result<(), Box<dyn std::error::Error>> {
    let control =
        std::env::temp_dir().join(format!("positron83-{}-{}.sock", std::process::id(), label));
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    for _ in 0..2 {
        let host = NativeHost::new(NativeBindings::new(
            control.clone(),
            loopback,
            loopback,
            loopback,
            loopback,
            loopback,
        )?);
        let process = ApplicationRuntime::start(
            ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly),
            HostInputs::new(&host, &host),
        )?;
        assert_eq!(process.health().phase(), crate::ProcessPhase::Fenced);
        assert_eq!(process.health().readiness(), crate::Readiness::NotReady);
        assert_eq!(process.health().integrity_fence_reason(), Some(reason));
        assert!(process.services().is_none());
        assert!(process.configuration().is_none());
        assert_eq!(
            process
                .bound_endpoints()
                .iter()
                .map(|endpoint| endpoint.role())
                .collect::<Vec<_>>(),
            [
                crate::ListenerRole::Control,
                crate::ListenerRole::Operations
            ]
            .into_iter()
            .collect::<Vec<_>>()
        );
        let mut socket = std::os::unix::net::UnixStream::connect(&control)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        write!(
            socket,
            "GET /control/fenced/inspection HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {administrator}\r\nConnection: close\r\n\r\n"
        )?;
        let mut response = String::new();
        socket.read_to_string(&mut response)?;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let (_, body) = response.split_once("\r\n\r\n").ok_or("inspection")?;
        let inspection: serde_json::Value = serde_json::from_str(body)?;
        assert_eq!(inspection["reason"], label);
        assert_eq!(inspection["readiness"], "not_ready");
        let outcome = process.shutdown(ShutdownTrigger::FirstSignal);
        let crate::ExitOutcome::InternalCleanupFailure(failure) = outcome else {
            panic!("damaged durable state cannot complete Drain: {outcome:?}");
        };
        assert_eq!(failure.primary(), crate::CleanupPrimary::Forced);
        assert_eq!(
            failure.failed_roles().collect::<Vec<_>>(),
            [crate::CleanupRole::DurableShutdown(
                crate::BootstrapFailureCode::CatalogUnavailable
            )]
        );
    }
    Ok(())
}

pub(super) fn substitute_tenant_envelope(
    initialized: &crate::InitializedInstance,
) -> Result<(), Box<dyn std::error::Error>> {
    let catalog = open_catalog(initialized)?;
    let basis = catalog.pin()?;
    let mut changed = false;
    let mut objects = Vec::new();
    for id in basis.object_identities() {
        let mut bytes = basis.object(id)?.ok_or("catalog object")?.to_vec();
        if bytes.starts_with(b"POSGOV") {
            let offset = bytes
                .windows(8)
                .position(|value| value == b"POSTKE01")
                .ok_or("tenant envelope")?;
            // Substituting the envelope's bound key identity preserves the
            // authenticated Catalog and envelope shape, but invalidates AEAD.
            *bytes.get_mut(offset + 8).ok_or("key identity")? ^= 1;
            changed = true;
        }
        objects.push(positron_kernel::CatalogObject::new(bytes)?);
    }
    assert!(changed);
    catalog.commit(
        basis.identity(),
        positron_kernel::CatalogProposal::new(
            positron_kernel::TransactionId::new([0xee; 16])?,
            basis.format_epoch().ok_or("epoch")?,
            objects,
        )?,
        None,
    )?;
    drop(catalog);
    Ok(())
}
