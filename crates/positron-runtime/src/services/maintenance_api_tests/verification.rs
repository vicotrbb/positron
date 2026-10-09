use super::*;

#[test]
fn authenticated_online_verification_uses_one_pinned_scope_and_rejects_a_stale_resume()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("online-verify-source").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    let generation = catalog.pin()?.number();
    drop(catalog);
    let request = OnlineVerificationRequest::new(
        initialized.default_tenant_id().to_canonical_text(),
        "logs".to_owned(),
        scope.shard_id().value(),
        None,
        None,
    );
    let verified = services
        .verify_online_integrity(&administrator, &request.encode()?)
        .map_err(|failure| format!("online verification: {failure:?}"))?;
    assert_eq!(
        verified.catalog_generation, generation,
        "the report names the immutable Catalog generation scanned by this request"
    );
    assert_eq!(verified.outcome, "verified");
    assert!(verified.verification_complete);
    assert!(verified.findings.is_empty());
    let stale = services
        .verify_online_integrity(
            &administrator,
            &OnlineVerificationRequest::new(
                initialized.default_tenant_id().to_canonical_text(),
                "logs".to_owned(),
                scope.shard_id().value(),
                Some(generation.checked_sub(1).ok_or("generation")?),
                None,
            )
            .encode()?,
        )
        .map_err(|failure| format!("stale online verification: {failure:?}"))?;
    assert_eq!(stale.outcome, "stale");
    assert!(!stale.verification_complete);
    assert!(stale.catalog_generation > generation);
    Ok(())
}

#[test]
fn post_admission_catalog_failure_terminalizes_the_scrub_and_releases_its_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(
        &ingest,
        request("online-verify-terminalization").encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    let scope = snapshot
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    let snapshot = catalog.pin()?;
    let task = super::online_verification_task_identity(scope, snapshot.identity().to_bytes(), 0)
        .map_err(|failure| format!("task identity: {failure:?}"))?;
    drop((snapshot, catalog));
    let body = OnlineVerificationRequest::new(
        initialized.default_tenant_id().to_canonical_text(),
        "logs".to_owned(),
        scope.shard_id().value(),
        None,
        None,
    )
    .encode()?;
    let failed =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 2, || {
            services.verify_online_integrity(&administrator, &body)
        });
    assert_eq!(
        failed,
        Err(MaintenanceServiceFailure::AdministrationUnavailable)
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(task)
            .map_err(|failure| format!("task status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Failed,
        "the admitted scrub persists a terminal successor rather than remaining Running"
    );
    let retried = services
        .verify_online_integrity(&administrator, &body)
        .map_err(|failure| format!("retry: {failure:?}"))?;
    assert!(retried.verification_complete);
    assert_eq!(retried.outcome, "verified");
    Ok(())
}

#[test]
fn online_verification_continuation_survives_its_own_durable_task_publications()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services
        .install_integrity_scrub_budget_for_test(1)
        .map_err(|failure| format!("install bounded test budget: {failure:?}"))?;
    services.ingest_otlp_logs(
        &ingest,
        request("online-verify-continuation-1").encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    drop(catalog);
    for ordinal in 2_u8..=2 {
        services.ingest_otlp_logs(
            &ingest,
            request(&format!("online-verify-continuation-{ordinal}")).encode_to_vec(),
        )?;
        let catalog = open_catalog(&initialized)?;
        let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            scope,
            initialized.tenant_segment_key_for_test(scope)?,
        )?;
        ledger.seal()?;
        drop(catalog);
    }
    let catalog = open_catalog(&initialized)?;
    let generation = catalog.pin()?.number();
    drop(catalog);

    let first = services
        .verify_online_integrity(
            &administrator,
            &OnlineVerificationRequest::new(
                initialized.default_tenant_id().to_canonical_text(),
                "logs".to_owned(),
                scope.shard_id().value(),
                Some(generation),
                None,
            )
            .encode()?,
        )
        .map_err(|failure| format!("first continuation pass: {failure:?}"))?;
    assert_eq!(first.outcome, "incomplete");
    assert!(!first.verification_complete);
    assert_eq!(first.examined_segments, 1);
    assert_eq!(
        first.catalog_generation, generation,
        "the first pass reports the immutable generation selected by the request"
    );
    let mut tampered = first.continuation.clone().ok_or("first continuation")?;
    let replacement = if tampered.as_bytes().get(16) == Some(&b'0') {
        "1"
    } else {
        "0"
    };
    tampered.replace_range(16..17, replacement);
    assert_eq!(
        services.verify_online_integrity(
            &administrator,
            &OnlineVerificationRequest::new(
                initialized.default_tenant_id().to_canonical_text(),
                "logs".to_owned(),
                scope.shard_id().value(),
                generation.checked_add(1),
                Some(tampered),
            )
            .encode()?,
        ),
        Err(MaintenanceServiceFailure::InvalidRequest),
        "changing the wrapper basis together with the expected generation must not rebind a continuation"
    );
    let mut resumed = first;
    for _ in 0..4 {
        if resumed.verification_complete {
            break;
        }
        let continuation = resumed.continuation.clone().ok_or("resumed continuation")?;
        resumed = services
            .verify_online_integrity(
                &administrator,
                &OnlineVerificationRequest::new(
                    initialized.default_tenant_id().to_canonical_text(),
                    "logs".to_owned(),
                    scope.shard_id().value(),
                    Some(generation),
                    Some(continuation),
                )
                .encode()?,
            )
            .map_err(|failure| format!("resumed continuation pass: {failure:?}"))?;
        assert_eq!(
            resumed.catalog_generation, generation,
            "every resumed pass must scan and report the original immutable Catalog generation"
        );
    }
    assert_eq!(resumed.outcome, "verified");
    assert!(resumed.verification_complete);
    assert_eq!(resumed.omitted_segments, 0);
    Ok(())
}

#[test]
fn online_verification_continuation_refuses_a_replaced_scope_source()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services
        .install_integrity_scrub_budget_for_test(1)
        .map_err(|failure| format!("install bounded test budget: {failure:?}"))?;
    for ordinal in 1_u8..=2 {
        services.ingest_otlp_logs(
            &ingest,
            request(&format!("online-verify-replaced-source-{ordinal}")).encode_to_vec(),
        )?;
        let catalog = open_catalog(&initialized)?;
        let scope = catalog
            .pin()?
            .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
            .into_iter()
            .next()
            .ok_or("log scope")?;
        ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            scope,
            initialized.tenant_segment_key_for_test(scope)?,
        )?
        .seal()?;
    }
    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    let scope = snapshot
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    let generation = snapshot.number();
    let source_before = snapshot.integrity_scope_source_identity(scope)?;
    drop((snapshot, catalog));

    let first = services
        .verify_online_integrity(
            &administrator,
            &OnlineVerificationRequest::new(
                initialized.default_tenant_id().to_canonical_text(),
                "logs".to_owned(),
                scope.shard_id().value(),
                Some(generation),
                None,
            )
            .encode()?,
        )
        .map_err(|failure| format!("first bounded pass: {failure:?}"))?;
    assert_eq!(first.outcome, "incomplete");
    let continuation = first.continuation.ok_or("continuation")?;

    services.ingest_otlp_logs(
        &ingest,
        request("online-verify-replaced-source-successor").encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    let current = catalog.pin()?;
    assert_ne!(
        current.integrity_scope_source_identity(scope)?,
        source_before,
        "the successor must carry a genuinely different authenticated scope source"
    );
    assert!(current.number() > generation);
    drop((current, catalog));

    let resumed = services
        .verify_online_integrity(
            &administrator,
            &OnlineVerificationRequest::new(
                initialized.default_tenant_id().to_canonical_text(),
                "logs".to_owned(),
                scope.shard_id().value(),
                Some(generation),
                Some(continuation),
            )
            .encode()?,
        )
        .map_err(|failure| format!("replaced-source resume: {failure:?}"))?;
    assert_eq!(resumed.outcome, "stale");
    assert!(!resumed.verification_complete);
    assert!(
        resumed.catalog_generation > generation,
        "a rejected historical continuation names the current authoritative generation"
    );
    Ok(())
}

#[test]
fn online_verification_continuation_publishes_a_localized_quarantine_after_its_first_pass()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services
        .install_integrity_scrub_budget_for_test(1)
        .map_err(|failure| format!("install bounded test budget: {failure:?}"))?;
    services.ingest_otlp_logs(
        &ingest,
        request("online-verify-resumed-quarantine-1").encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    drop(catalog);
    let sealed_directory = fixture.sealed_segments_directory();
    let before_second = fs::read_dir(&sealed_directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    services.ingest_otlp_logs(
        &ingest,
        request("online-verify-resumed-quarantine-2").encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    let generation = catalog.pin()?.number();
    drop(catalog);
    let damaged_segment = fs::read_dir(&sealed_directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| !before_second.contains(path))
        .ok_or("second sealed segment")?;
    let damaged_bytes = b"resumed online verification corruption";
    fs::write(&damaged_segment, damaged_bytes)?;

    let first = services
        .verify_online_integrity(
            &administrator,
            &OnlineVerificationRequest::new(
                initialized.default_tenant_id().to_canonical_text(),
                "logs".to_owned(),
                scope.shard_id().value(),
                Some(generation),
                None,
            )
            .encode()?,
        )
        .map_err(|failure| format!("first healthy pass: {failure:?}"))?;
    assert_eq!(first.outcome, "incomplete");
    assert_eq!(first.catalog_generation, generation);
    let mut resumed = first;
    for _ in 0..4 {
        let continuation = resumed.continuation.take().ok_or("resumed continuation")?;
        resumed = services
            .verify_online_integrity(
                &administrator,
                &OnlineVerificationRequest::new(
                    initialized.default_tenant_id().to_canonical_text(),
                    "logs".to_owned(),
                    scope.shard_id().value(),
                    Some(generation),
                    Some(continuation),
                )
                .encode()?,
            )
            .map_err(|failure| format!("resumed localized finding: {failure:?}"))?;
        if resumed.outcome != "incomplete" {
            break;
        }
    }
    assert_eq!(resumed.catalog_generation, generation);
    assert_eq!(resumed.outcome, "quarantined");
    assert!(!resumed.verification_complete);
    assert!(!resumed.findings.is_empty());
    assert_eq!(fs::read(&damaged_segment)?, damaged_bytes);
    assert!(
        !positron_kernel::integrity_quarantine_findings(&open_catalog(&initialized)?.pin()?)?
            .is_empty(),
        "a localized resumed finding must use the canonical durable quarantine publication"
    );
    Ok(())
}

#[test]
fn online_verification_continuation_refuses_foreign_catalog_mutation_before_quarantine()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services
        .install_integrity_scrub_budget_for_test(1)
        .map_err(|failure| format!("install bounded test budget: {failure:?}"))?;
    services.ingest_otlp_logs(
        &ingest,
        request("online-verify-foreign-cas-1").encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    drop(catalog);
    let sealed_directory = fixture.sealed_segments_directory();
    let before_second = fs::read_dir(&sealed_directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    services.ingest_otlp_logs(
        &ingest,
        request("online-verify-foreign-cas-2").encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    let generation = catalog.pin()?.number();
    drop(catalog);
    let damaged_segment = fs::read_dir(&sealed_directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| !before_second.contains(path))
        .ok_or("second sealed segment")?;
    let damaged_bytes = b"foreign-cas online verification corruption";
    fs::write(&damaged_segment, damaged_bytes)?;

    let first = services
        .verify_online_integrity(
            &administrator,
            &OnlineVerificationRequest::new(
                initialized.default_tenant_id().to_canonical_text(),
                "logs".to_owned(),
                scope.shard_id().value(),
                Some(generation),
                None,
            )
            .encode()?,
        )
        .map_err(|failure| format!("first healthy pass: {failure:?}"))?;
    assert_eq!(first.outcome, "incomplete");
    let continuation = first.continuation.ok_or("continuation")?;
    publish_unrelated(&initialized)?;
    let foreign_generation = open_catalog(&initialized)?.pin()?.number();

    let resumed = services
        .verify_online_integrity(
            &administrator,
            &OnlineVerificationRequest::new(
                initialized.default_tenant_id().to_canonical_text(),
                "logs".to_owned(),
                scope.shard_id().value(),
                Some(generation),
                Some(continuation),
            )
            .encode()?,
        )
        .map_err(|failure| format!("foreign-Catalog resume: {failure:?}"))?;
    assert_eq!(resumed.outcome, "stale");
    assert!(!resumed.verification_complete);
    assert_eq!(resumed.catalog_generation, foreign_generation);
    assert_eq!(
        open_catalog(&initialized)?.pin()?.number(),
        foreign_generation,
        "a foreign successor must reject the continuation before it admits or completes another durable scrub task"
    );
    assert_eq!(fs::read(&damaged_segment)?, damaged_bytes);
    assert!(
        positron_kernel::integrity_quarantine_findings(&open_catalog(&initialized)?.pin()?)?
            .is_empty(),
        "a foreign Catalog mutation must prevent durable quarantine publication"
    );
    Ok(())
}

#[test]
fn online_verification_observation_does_not_block_an_authenticated_query()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query, administrator) = fixture.initialized_with_admin()?;
    let services = Arc::new(ServiceHandle::new(Arc::clone(&initialized))?);
    services.ingest_otlp_logs(
        &ingest,
        request("online-verify-nonblocking").encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    let generation = catalog.pin()?.number();
    drop(catalog);

    let (captured_tx, captured_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    services.install_online_verification_test_hook(Arc::new(BlockingOnlineVerification {
        captured: captured_tx,
        release: Mutex::new(release_rx),
    }))?;
    let verifying = Arc::clone(&services);
    let tenant = initialized.default_tenant_id().to_canonical_text();
    let verification_administrator = administrator.clone();
    let verification = std::thread::spawn(move || {
        verifying.verify_online_integrity(
            &verification_administrator,
            &OnlineVerificationRequest::new(
                tenant,
                "logs".to_owned(),
                scope.shard_id().value(),
                None,
                None,
            )
            .encode()
            .expect("bounded request"),
        )
    });
    captured_rx.recv_timeout(Duration::from_secs(1))?;
    let query_result = services.query_log_bodies(
        &query,
        "logs | range query_time 0 100 | limit 2",
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 60)?.with_cpu_work_units(16)?,
    )?;
    assert!(
        !query_result.is_empty(),
        "safe query must complete during the immutable scan"
    );
    release_tx.send(())?;
    let report = verification
        .join()
        .map_err(|_| "verification thread panicked")?
        .map_err(|failure| format!("online verification: {failure:?}"))?;
    assert!(report.catalog_generation > generation);
    assert_eq!(report.outcome, "stale");
    assert!(!report.verification_complete);
    Ok(())
}

#[test]
fn online_verification_refuses_to_publish_against_a_successor_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = Arc::new(ServiceHandle::new(Arc::clone(&initialized))?);
    services.ingest_otlp_logs(
        &ingest,
        request("online-verify-stale-publication").encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    let generation = catalog.pin()?.number();
    drop(catalog);

    let (captured_tx, captured_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    services.install_online_verification_test_hook(Arc::new(BlockingOnlineVerification {
        captured: captured_tx,
        release: Mutex::new(release_rx),
    }))?;
    let verifying = Arc::clone(&services);
    let tenant = initialized.default_tenant_id().to_canonical_text();
    let verification_administrator = administrator.clone();
    let verification = std::thread::spawn(move || {
        verifying.verify_online_integrity(
            &verification_administrator,
            &OnlineVerificationRequest::new(
                tenant,
                "logs".to_owned(),
                scope.shard_id().value(),
                None,
                None,
            )
            .encode()
            .expect("bounded request"),
        )
    });
    captured_rx.recv_timeout(Duration::from_secs(1))?;
    let successor = services
        .bind_tenant_alias(
            &administrator,
            &TenantAliasBindRequest::new(
                initialized.default_tenant_id().to_canonical_text(),
                "verify-race".to_owned(),
                1,
                "00000000-0000-0000-0000-000000000082".to_owned(),
            )
            .encode()?,
        )
        .map_err(|_| "successor alias publication")?;
    assert_eq!(successor.alias_generation, 2);
    release_tx.send(())?;
    let report = verification
        .join()
        .map_err(|_| "verification thread panicked")?
        .map_err(|failure| format!("online verification: {failure:?}"))?;
    assert!(report.catalog_generation > generation);
    assert_eq!(report.outcome, "stale");
    assert!(!report.verification_complete);
    Ok(())
}

#[test]
fn expected_online_generation_never_rebases_after_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = Arc::new(ServiceHandle::new(Arc::clone(&initialized))?);
    services.ingest_otlp_logs(
        &ingest,
        request("online-verify-admission-generation").encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    let scope = snapshot
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    let snapshot = catalog.pin()?;
    let generation = snapshot.number();
    let task = super::online_verification_task_identity(scope, snapshot.identity().to_bytes(), 0)
        .map_err(|_| "online verification task identity")?;
    drop((snapshot, catalog));

    let (captured_tx, captured_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    services.install_online_verification_test_hook(Arc::new(
        BlockingOnlineVerificationAdmission {
            captured: captured_tx,
            release: Mutex::new(release_rx),
        },
    ))?;
    let verifying = Arc::clone(&services);
    let tenant = initialized.default_tenant_id().to_canonical_text();
    let verification_administrator = administrator.clone();
    let verification = std::thread::spawn(move || {
        verifying.verify_online_integrity(
            &verification_administrator,
            &OnlineVerificationRequest::new(
                tenant,
                "logs".to_owned(),
                scope.shard_id().value(),
                Some(generation),
                None,
            )
            .encode()
            .expect("bounded request"),
        )
    });
    captured_rx.recv_timeout(Duration::from_secs(1))?;
    services
        .bind_tenant_alias(
            &administrator,
            &TenantAliasBindRequest::new(
                initialized.default_tenant_id().to_canonical_text(),
                "verify-admission-race".to_owned(),
                1,
                "00000000-0000-0000-0000-000000000084".to_owned(),
            )
            .encode()?,
        )
        .map_err(|_| "successor alias publication")?;
    release_tx.send(())?;
    let report = verification
        .join()
        .map_err(|_| "verification thread panicked")?
        .map_err(|failure| format!("online verification: {failure:?}"))?;
    assert_eq!(report.outcome, "stale");
    assert!(!report.verification_complete);
    assert!(report.catalog_generation > generation);
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(task)
            .map_err(|_| "online verification task status")?
            .phase(),
        MaintenanceTaskPhase::Failed,
        "the admitted task is terminal rather than leaking after the stale basis check"
    );
    Ok(())
}

#[test]
fn authenticated_online_verification_quarantines_local_damage_without_rewriting_source()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    drop(initialized);
    static NEXT_CONTROL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let control = std::env::temp_dir().join(format!(
        "positron-online-verification-status-{}-{}.sock",
        std::process::id(),
        NEXT_CONTROL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    match fs::remove_file(&control) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => return Err(error.into()),
    }
    let host = NativeHost::new(NativeBindings::new(
        control,
        loopback(0),
        loopback(0),
        loopback(0),
        loopback(0),
        loopback(0),
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let services = process.services().ok_or("serving services")?;
    let initialized = Arc::clone(&services.instance);
    services.ingest_otlp_logs(
        &ingest,
        request("online-verify-corrupt-source").encode_to_vec(),
    )?;

    let sealed_directory = fixture.sealed_segments_directory();
    let before_seal = fs::read_dir(&sealed_directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    drop(catalog);
    let damaged_segment = fs::read_dir(&sealed_directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| !before_seal.contains(path))
        .ok_or("newly sealed block-bearing segment")?;
    let damaged_bytes = b"online verification corruption";
    fs::write(&damaged_segment, damaged_bytes)?;
    let mut report = None;
    let mut stale_bases = Vec::new();
    for _ in 0..4 {
        let expected_generation = open_catalog(&initialized)?.pin()?.number();
        let candidate = services
            .verify_online_integrity(
                &administrator,
                &OnlineVerificationRequest::new(
                    initialized.default_tenant_id().to_canonical_text(),
                    "logs".to_owned(),
                    scope.shard_id().value(),
                    Some(expected_generation),
                    None,
                )
                .encode()?,
            )
            .map_err(|failure| {
                format!(
                    "online quarantine failed at Catalog basis {expected_generation}: {failure:?}"
                )
            })?;
        if candidate.outcome != "stale" {
            report = Some((candidate, expected_generation));
            break;
        }
        stale_bases.push((expected_generation, candidate.catalog_generation));
    }
    let report = report.ok_or_else(|| {
        format!("online quarantine did not acquire a stable G0 basis: {stale_bases:?}")
    })?;

    assert_eq!(
        report.0.catalog_generation, report.1,
        "the quarantine report names the immutable Catalog generation scanned before publication"
    );
    let report = report.0;
    assert_eq!(report.outcome, "quarantined");
    assert!(!report.verification_complete);
    assert!(!report.findings.is_empty());
    assert_eq!(fs::read(&damaged_segment)?, damaged_bytes);
    assert_eq!(
        process.health().phase(),
        crate::health::ProcessPhase::Serving
    );
    assert!(process.health().integrity_degraded());
    let catalog = open_catalog(&initialized)?;
    assert!(
        !positron_kernel::integrity_quarantine_findings(&catalog.pin()?)?.is_empty(),
        "the authorized online result is a durable Catalog quarantine finding"
    );
    let audits = catalog
        .governance_audit_records()?
        .into_iter()
        .map(|record| GovernanceAuditEntry::decode(&record))
        .collect::<Result<Vec<_>, _>>()?;
    let quarantine_audit = audits
        .iter()
        .find_map(GovernanceAuditEntry::as_integrity_quarantine)
        .ok_or("trusted quarantine audit")?;
    assert_eq!(quarantine_audit.tenant(), initialized.default_tenant_id());
    assert_eq!(quarantine_audit.signal(), SignalKind::Logs);
    assert_eq!(quarantine_audit.shard(), scope.shard_id().value());
    drop(catalog);
    for value in 1_u8..=33 {
        initialized
            .maintenance_coordinator()
            .submit_at(
                MaintenanceTask::new(
                    MaintenanceTaskId::new([value; 16])
                        .map_err(|failure| format!("task identity: {failure:?}"))?,
                    MaintenanceTaskClass::SchemaStatistics,
                ),
                u64::from(value),
            )
            .map_err(|failure| format!("queued task: {failure:?}"))?;
    }
    let mut request = MaintenanceStatusRequest::default();
    let mut identities = BTreeSet::new();
    let mut expected_findings = None;
    let mut total = None;
    loop {
        let status = services
            .maintenance_status(&administrator, &serde_json::to_vec(&request)?)
            .map_err(|failure| format!("paged status: {failure:?}"))?;
        assert!(
            status.encode().is_ok(),
            "each status page remains within the canonical transport envelope"
        );
        assert!(status.returned > 0, "a task cursor page must advance");
        match &expected_findings {
            Some(expected) => assert_eq!(
                &status.integrity_findings, expected,
                "every cursor page repeats the current durable quarantine evidence"
            ),
            None => expected_findings = Some(status.integrity_findings.clone()),
        }
        total.get_or_insert(status.total);
        assert_eq!(total, Some(status.total));
        for task in &status.tasks {
            assert!(
                identities.insert(task.identity.clone()),
                "a status cursor must not repeat task identities"
            );
        }
        let Some(cursor) = status.next_cursor else {
            break;
        };
        request = MaintenanceStatusRequest::page_after(cursor, MAX_STATUS_PAGE_TASKS as u32);
    }
    assert_eq!(
        identities.len(),
        usize::try_from(total.ok_or("status total")?)?,
        "all tasks remain reachable while every page carries findings"
    );
    assert_eq!(
        expected_findings.as_ref(),
        Some(&report.findings),
        "the public status projection retains the quarantined segment descriptor"
    );
    let api = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("native API endpoint")?;
    let status = maintenance_status_over_http(api, &administrator)?;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(
        status.contains("\"base_position\":0"),
        "the origin quarantine finding must remain encodable over the public HTTP status route: {status}"
    );
    drop(services);
    drop(initialized);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    let reopened = fixture.reopen()?;
    assert!(
        open_catalog(&reopened)?
            .governance_audit_records()?
            .into_iter()
            .map(|record| GovernanceAuditEntry::decode(&record))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|entry| entry.as_integrity_quarantine().is_some())
    );
    drop(reopened);
    let offline = crate::verify_offline_integrity(&fixture.paths()?, 2)
        .map_err(|failure| format!("offline known-quarantine verification: {failure:?}"))?;
    assert!(offline.is_complete());
    assert!(!offline.is_verified());
    assert_eq!(
        offline.aggregate_outcome(),
        crate::OfflineIntegrityAggregateOutcome::Quarantined,
        "a durable, known sealed-segment quarantine degrades the aggregate without fencing the instance"
    );
    assert!(
        offline
            .aggregate_evidence()
            .iter()
            .any(|evidence| evidence.outcome()
                == positron_kernel::IntegrityVerificationOutcome::Quarantined)
    );
    assert!(
        offline
            .aggregate_evidence()
            .iter()
            .any(|evidence| evidence.outcome()
                == positron_kernel::IntegrityVerificationOutcome::Verified)
    );
    Ok(())
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

fn maintenance_status_over_http(
    address: SocketAddr,
    administrator: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let body = b"{}";
    let mut stream = TcpStream::connect(address)?;
    stream.write_all(
        format!(
            "POST /v1/maintenance:status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {administrator}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )?;
    stream.write_all(body)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[test]
fn authenticated_online_verification_fences_unavailable_sealed_source()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let health = crate::health::ProcessState::starting();
    health.transition(crate::health::ProcessPhase::Serving);
    services.attach_health(health.health());
    services.ingest_otlp_logs(
        &ingest,
        request("online-verify-fenced-source").encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    drop(catalog);
    let audit_before = open_catalog(&initialized)?.governance_audit_records()?;
    let missing_source = fs::read_dir(fixture.sealed_segments_directory())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "segment")
        })
        .ok_or("sealed segment")?;
    fs::remove_file(&missing_source)?;

    let report = services
        .verify_online_integrity(
            &administrator,
            &OnlineVerificationRequest::new(
                initialized.default_tenant_id().to_canonical_text(),
                "logs".to_owned(),
                scope.shard_id().value(),
                None,
                None,
            )
            .encode()?,
        )
        .map_err(|failure| format!("online fenced verification: {failure:?}"))?;
    assert_eq!(report.outcome, "fenced");
    assert!(!report.verification_complete);
    assert_eq!(
        health.health().phase(),
        crate::health::ProcessPhase::Serving,
        "verification requests a fence; the process owner performs its transition"
    );
    assert_eq!(
        health.health().readiness(),
        crate::health::Readiness::NotReady,
        "a queued process-owner fence closes admission before teardown runs"
    );
    assert_eq!(
        health.health().pending_integrity_fence_request(),
        Some(crate::IntegrityFenceReason::AmbiguousIntegrity)
    );
    assert!(
        !missing_source.exists(),
        "ambiguous source evidence must never be reconstructed or repaired"
    );
    let catalog = open_catalog(&initialized)?;
    assert!(
        positron_kernel::integrity_quarantine_findings(&catalog.pin()?)?.is_empty(),
        "an unavailable source cannot be guessed into a quarantine finding"
    );
    assert_eq!(catalog.governance_audit_records()?, audit_before);
    Ok(())
}
