use super::*;

#[test]
fn abandonment_jointly_records_loss_operation_and_audit_and_exactly_replays()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("abandoned-evidence").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("scope")?;
    let sealed = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    let file = fixture.sealed_segments_directory().join(format!(
        "{}.segment",
        super::hex(sealed.segment_id().to_bytes())
    ));
    fs::write(&file, b"corrupt evidence")?;
    drop(catalog);
    services
        .verify_online_integrity(
            &administrator,
            &OnlineVerificationRequest::new(
                scope.tenant_id().to_canonical_text(),
                "logs".into(),
                scope.shard_id().value(),
                None,
                None,
            )
            .encode()?,
        )
        .map_err(|e| format!("verify {e:?}"))?;
    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    let plan = positron_kernel::SegmentAbandonmentPlan::preflight(
        &catalog,
        &snapshot,
        scope,
        sealed.segment_id(),
    )?;
    let actor = services
        .authorize_system_administration(&administrator)
        .map_err(|e| format!("actor {e:?}"))?;
    let request = positron_governance::DurableOperationRequest::segment_abandonment(
        actor.principal_id(),
        scope.tenant_id(),
        positron_governance::AdministrativeIdempotencyKey::new([0xab; 16])?,
        sealed.segment_id().to_bytes(),
        snapshot.number(),
        17,
        plan.confirmation_digest(),
    )?;
    drop(plan);
    let before_audit = snapshot.governance_audit_frontier();
    let result = positron_governance::DurableOperationAdministration::abandon_segment(
        &catalog, actor, scope, request,
    )?;
    assert_eq!(
        result.status(),
        positron_governance::DurableOperationStatus::Succeeded
    );
    assert_eq!(
        result.irreversible_boundary(),
        positron_governance::DurableOperationBoundary::CatalogGenerationPublished
    );
    let current = catalog.pin()?;
    assert_eq!(current.governance_audit_frontier(), before_audit + 1);
    assert_eq!(
        positron_kernel::integrity_abandonment_findings(&current)?.len(),
        1
    );
    assert_eq!(fs::read(&file)?, b"corrupt evidence");
    let records = catalog.governance_audit_records()?;
    let entry = positron_governance::GovernanceAuditEntry::decode(
        records.last().ok_or("abandonment audit")?,
    )?;
    let positron_governance::GovernanceAuditEntry::DurableOperation(audit) = entry else {
        return Err("wrong audit".into());
    };
    assert_eq!(
        audit
            .abandonment_loss()
            .ok_or("missing audit range")?
            .segment(),
        sealed.segment_id()
    );

    let replay = positron_governance::DurableOperationAdministration::abandon_segment(
        &catalog, actor, scope, request,
    )?;
    assert_eq!(replay, result);
    assert_eq!(catalog.pin()?.number(), current.number());
    let changed = positron_governance::DurableOperationRequest::segment_abandonment(
        actor.principal_id(),
        scope.tenant_id(),
        request.idempotency_key(),
        sealed.segment_id().to_bytes(),
        snapshot.number(),
        17,
        [0xac; 32],
    )?;
    assert_eq!(
        positron_governance::DurableOperationAdministration::abandon_segment(
            &catalog, actor, scope, changed
        ),
        Err(positron_governance::DurableOperationFailure::IdempotencyConflict)
    );
    assert_eq!(
        positron_governance::DurableOperationAdministration::inspect_authorized(
            &catalog,
            actor,
            result.operation_id()
        )?,
        Some(result)
    );
    drop(catalog);
    let context = initialized.attribute(
        positron_governance::PresentedCredential::parse(&query)?,
        positron_governance::RequestedIntent::Query,
        positron_governance::CompatibilityHints::none(),
    )?;
    let outcome = super::super::super::query::query_events_for_test(
        &services,
        context,
        scope.shard_id(),
        "logs | range query_time 0 10 | limit 16",
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(16)?,
        None,
    )
    .map_err(|e| format!("query after abandonment {e:?}"))?;
    let super::super::super::query::QueryTestOutcome::Events(events) = outcome else {
        return Err(format!("missing terminal {outcome:?}").into());
    };
    assert!(events.iter().any(|event| matches!(
        event,
        positron_query::QueryEvent::Terminal(positron_query::QueryTerminal::Incomplete(_))
    )));
    assert!(!events.iter().any(|event| matches!(
        event,
        positron_query::QueryEvent::Terminal(positron_query::QueryTerminal::Complete(_))
    )));
    drop(services);
    drop(initialized);
    let reopened = fixture.reopen()?;
    let records = open_catalog(&reopened)?.governance_audit_records()?;
    assert!(records.iter().filter_map(|record| GovernanceAuditEntry::decode(record).ok()).any(|entry| matches!(entry, GovernanceAuditEntry::DurableOperation(audit) if audit.abandonment_loss().is_some())));
    Ok(())
}

#[test]
fn administrative_abandonment_preview_is_read_only_and_confirmation_reauthenticates()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("abandonment-preview").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("scope")?;
    let sealed = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    fs::write(
        fixture.sealed_segments_directory().join(format!(
            "{}.segment",
            super::hex(sealed.segment_id().to_bytes())
        )),
        b"corrupt evidence",
    )?;
    drop(catalog);
    services
        .verify_online_integrity(
            &administrator,
            &OnlineVerificationRequest::new(
                scope.tenant_id().to_canonical_text(),
                "logs".into(),
                scope.shard_id().value(),
                None,
                None,
            )
            .encode()?,
        )
        .map_err(|e| format!("verify {e:?}"))?;
    let body = positron_api::maintenance::SegmentAbandonmentRequest {
        tenant: scope.tenant_id().to_canonical_text(),
        signal: "logs".into(),
        shard: scope.shard_id().value(),
        segment: super::hex(sealed.segment_id().to_bytes()),
        expected_catalog_generation: None,
        confirmation: None,
        idempotency_key: None,
        accept_data_loss: false,
        operation_id: None,
    };
    fn exhaust_maintenance(
        authority: &positron_kernel::StorageKernelResourceAuthority,
    ) -> Result<Vec<positron_kernel::ResourceReservation<'_>>, Box<dyn std::error::Error>> {
        let governor = authority.governor();
        let maximum = governor.inspect()?.maximum_outstanding_reservations();
        let mut reservations = Vec::new();
        for _ in 0..maximum {
            let claim = positron_kernel::WorkClaim::system_diagnostics(
                positron_kernel::ResourceAmounts::new([1_048_576, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            )?;
            match governor.reserve(claim) {
                Ok(reservation) => reservations.push(reservation),
                Err(_) => return Ok(reservations),
            }
        }
        Err("maintenance pool did not exhaust".into())
    }
    let before = open_catalog(&initialized)?.pin()?.number();
    let blockers = exhaust_maintenance(&initialized._authority)?;
    assert!(matches!(
        services.abandon_segment(&administrator, &body.encode()?),
        Err(super::MaintenanceServiceFailure::AdministrationUnavailable)
    ));
    assert_eq!(open_catalog(&initialized)?.pin()?.number(), before);
    drop(blockers);
    let preview = services
        .abandon_segment(&administrator, &body.encode()?)
        .map_err(|e| format!("preview {e:?}"))?;
    assert_eq!(preview.status, "preview");
    assert_eq!(open_catalog(&initialized)?.pin()?.number(), before);
    let mut confirm = body;
    confirm.expected_catalog_generation = Some(preview.catalog_generation);
    confirm.confirmation = preview.confirmation;
    confirm.idempotency_key = Some("bcbcbcbc-bcbc-bcbc-bcbc-bcbcbcbcbcbc".into());
    confirm.accept_data_loss = true;
    let blockers = exhaust_maintenance(&initialized._authority)?;
    assert!(matches!(
        services.abandon_segment(&administrator, &confirm.encode()?),
        Err(super::MaintenanceServiceFailure::AdministrationUnavailable)
    ));
    assert_eq!(open_catalog(&initialized)?.pin()?.number(), before);
    drop(blockers);

    assert_eq!(
        services.abandon_segment(&ingest, &confirm.encode()?),
        Err(MaintenanceServiceFailure::AuthenticationRejected)
    );
    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            services.abandon_segment(
                &administrator,
                &confirm.encode().expect("confirmed request"),
            )
        });
    assert_eq!(
        failure,
        Err(MaintenanceServiceFailure::AdministrationUnavailable)
    );
    assert_eq!(
        open_catalog(&initialized)?.pin()?.number(),
        before,
        "an unpublished commit reports no loss or success"
    );
    let published = services
        .abandon_segment(&administrator, &confirm.encode()?)
        .map_err(|e| format!("confirm {e:?}"))?;
    assert_eq!(published.status, "succeeded");
    assert_eq!(
        published.irreversible_boundary,
        "catalog_generation_published"
    );
    assert_eq!(
        services
            .abandon_segment(&administrator, &confirm.encode()?)
            .map_err(|e| format!("retry {e:?}"))?,
        published
    );
    Ok(())
}
