//! Authenticate the source and accept exact offline target ownership before transfer.
use super::*;
impl InstanceBootstrap {
    pub(super) fn restore(
        paths: &BootstrapPaths,
        configuration: &positron_config::EffectiveConfiguration,
        request: &BackupRestoreRequest,
        unlock: RestoreUnlock<'_>,
    ) -> Result<BackupRestoreSession, BootstrapFailure> {
        let input::PreparedRestore {
            authority,
            access,
            layout: _,
            mut resources,
            runtime,
            repository,
            identity,
            custody,
            parameters,
            native,
            manifest,
        } = input::PreparedRestore::open(paths, configuration, request, unlock)?;
        let reader = runtime
            .block_on(BackupSnapshotReader::open(
                repository.as_ref(),
                &identity,
                request.pin.integrity(),
                ObjectId::from_checksum(request.source.manifest_checksum()),
                &resources,
                0,
            ))
            .map_err(|_| failure())?;
        if manifest.snapshot_id() != request.source.snapshot_id() {
            return Err(failure());
        }
        let (original, source_request) = manifest.capture_binding().ok_or_else(failure)?;
        let secret = custody
            .catalog_secret(request.pin.instance())
            .map_err(|_| failure())?;
        let index = runtime
            .block_on(reader.read_file(manifest.capture_index(), 8 * 1024 * 1024))
            .map_err(|_| failure())?;
        let mut verification = BackupCaptureVerification::open(
            request.pin.instance(),
            &secret,
            original,
            source_request,
            &index,
        )
        .map_err(|_| failure())?;
        let configuration_bytes = u64::try_from(configuration.redacted_effective().len())
            .map_err(|_| failure())?
            .checked_mul(3)
            .ok_or_else(failure)?;
        let retained = verification
            .prospective_memory_bytes()
            .map_err(|_| failure())?
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(configuration_bytes))
            .and_then(|bytes| bytes.checked_add(index.len() as u64))
            .and_then(|bytes| bytes.checked_add(manifest.retained_memory_bytes().ok()?))
            .ok_or_else(failure)?;
        let reader = reader
            .with_external_retained_memory(retained)
            .map_err(|_| failure())?;
        let files = verification.files().to_vec();
        for file in files.iter().filter(|file| {
            matches!(
                file.kind(),
                BackupCaptureFileKind::CatalogObject
                    | BackupCaptureFileKind::GovernanceAudit
                    | BackupCaptureFileKind::AuditCheckpoint
            )
        }) {
            let bytes = runtime
                .block_on(reader.read_file(file.identity(), 8 * 1024 * 1024))
                .map_err(|_| failure())?;
            verification
                .verify_protected_file(&secret, file.identity(), &bytes)
                .map_err(|_| failure())?;
        }
        let origin = verification
            .finish_restore_origin(
                request.source.manifest_checksum(),
                parameters.intent_digest(),
            )
            .map_err(|_| failure())?;
        let source = origin.snapshot();
        let (_, governance) = source.governance_object().map_err(|_| failure())?;
        let signer = custody
            .backup_control_signer(request.pin.instance(), governance.protected_integrity_key())
            .map_err(|_| failure())?;
        if signer.identity() != request.pin.integrity()
            || source.number() != manifest.catalog_generation()
            || source.identity().to_bytes() != manifest.catalog_identity()
            || source.governance_audit_frontier() != manifest.audit_frontier()
        {
            return Err(failure());
        }
        let (_, registration) = BackupRepositoryRegistration::find(
            source,
            request.pin.instance().to_bytes(),
            identity.repository_id(),
        )
        .map_err(|_| failure())?
        .ok_or_else(failure)?;
        if registration.identity() != &identity
            || registration.binding_identity().map_err(|_| failure())?
                != request.source.registration_identity()
        {
            return Err(failure());
        }
        let publisher = BackupPublisher::new(repository.as_ref(), &identity, &signer)
            .with_control_resources(&resources, retained)
            .map_err(|_| failure())?;
        let publisher = match registration.registry_generation() {
            Some(anchor) => publisher
                .with_trusted_generation(anchor)
                .map_err(|_| failure())?,
            None => publisher,
        };
        let mut registry = runtime
            .block_on(publisher.begin_registry_verification(
                request.idempotency.to_bytes(),
                parameters.intent_digest(),
            ))
            .map_err(|_| failure())?;
        while !registry.complete().map_err(|_| failure())? {
            runtime
                .block_on(publisher.registry_verification_step(&mut registry))
                .map_err(|_| failure())?;
        }
        let publisher = publisher
            .with_registry_verification(&registry)
            .map_err(|_| failure())?;
        let expected = TenantAdministration::backup_catalog_key_identities(source)
            .map_err(|_| failure())?
            .into_iter()
            .map(|(tenant, epoch, fingerprint)| {
                positron_backup::BackupKeyIdentity::new(tenant.to_bytes(), epoch, fingerprint)
                    .map_err(|_| failure())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut remote = runtime
            .block_on(publisher.begin_snapshot_restore_verification(
                manifest.snapshot_id(),
                request.idempotency.to_bytes(),
                parameters.intent_digest(),
                &expected,
            ))
            .map_err(|_| failure())?;
        publisher
            .validate_snapshot_inventory(&mut remote, &files)
            .map_err(|_| failure())?;
        let restored_publication = positron_governance::RestoredBackupPublication::new(
            &origin,
            request.source,
            request.idempotency,
            remote.registry_generation(),
            manifest.retain_until(),
        )
        .map_err(|_| failure())?;
        let source_catalog = source.clone();
        let tombstones = runtime
            .block_on(publisher.purge_tombstones())
            .map_err(|_| failure())?;
        let (origin, excluded) = purge::apply(
            origin,
            &tombstones,
            &identity,
            &signer,
            resources
                .granted()
                .get(positron_kernel::ResourceDimension::MemoryBytes),
            retained,
        )?;
        let required = TenantAdministration::restore_key_tenant_ids(origin.snapshot())
            .map_err(|_| failure())?;
        let mut envelopes = Vec::new();
        for index in 0..publisher.verification_key_count(&remote) {
            let envelope = runtime
                .block_on(publisher.read_verification_key(&remote, index))
                .map_err(|_| failure())?;
            let tenant = positron_domain::identity::TenantId::from_bytes(envelope.tenant())
                .map_err(|_| failure())?;
            if excluded.contains(&tenant) {
                continue;
            }
            if !required.contains(&tenant) {
                return Err(failure());
            }
            envelopes.push((tenant, envelope.protected().to_vec()));
        }
        let recovered_keys = envelopes.len();
        let files = files
            .into_iter()
            .filter_map(|file| {
                if !matches!(
                    file.kind(),
                    BackupCaptureFileKind::Segment | BackupCaptureFileKind::SegmentFrontier
                ) {
                    return Some(Ok(file));
                }
                match origin.retains_segment_file(file) {
                    Ok(true) => Some(Ok(file)),
                    Ok(false) => None,
                    Err(_) => Some(Err(failure())),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut objects =
            TenantAdministration::restore_catalog_objects(origin.snapshot(), &custody, &envelopes)
                .map_err(|_| failure())?;
        crate::configuration_catalog::bind_restored_configuration(
            &origin,
            &mut objects,
            configuration,
            &secret,
        )
        .map_err(|failure| {
            // This boundary's ResourceUnavailable is the existing configuration Vec reserve.
            if failure.code() == BootstrapFailureCode::ResourceUnavailable {
                failure.with_resource_context(BootstrapResourceContext::new(
                    BootstrapResourceStage::Catalog,
                    BootstrapResourceReason::AllocationUnavailable,
                    None,
                ))
            } else {
                failure
            }
        })?;
        let record = execution::record(request.pin, &custody, governance)?;
        let origin = origin
            .with_restored_objects(objects)
            .map_err(|_| failure())?;
        let planned_exclusions = TenantAdministration::restore_purge_exclusions(origin.snapshot())
            .map_err(|_| failure())?;
        drop(reader);
        drop(publisher);
        drop(index);
        drop(expected);
        drop(envelopes);
        drop(required);
        drop(tombstones);
        drop(excluded);
        // A small overlap grant keeps every retained source/target object charged
        // while the completed capture verifier and transport are surrendered.
        let carry_memory = retained
            .checked_add(remote.retained_memory_bytes().map_err(|_| failure())?)
            .and_then(|bytes| bytes.checked_add(manifest.retained_memory_bytes().ok()?))
            .and_then(|bytes| {
                bytes.checked_add(
                    (files.capacity() as u64)
                        .checked_mul(std::mem::size_of::<BackupCaptureFile>() as u64)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add((planned_exclusions.capacity() as u64).checked_mul(512)?)
            })
            .and_then(|bytes| bytes.checked_add(16 * 1024))
            .ok_or_else(failure)?;
        let phase_memory = carry_memory
            .checked_add(BackupPublisher::control_read_memory_bytes())
            .and_then(|bytes| {
                bytes.checked_add(native.get(positron_kernel::ResourceDimension::MemoryBytes))
            })
            .ok_or_else(failure)?;
        let phase_base = ResourceAmounts::new([phase_memory, 1, 1, 0, 8, 0, 1, 1, 1, 16, 0]);
        let phase_amounts = ResourceAmounts::new(
            positron_kernel::ResourceDimension::ALL
                .map(|dimension| phase_base.get(dimension).max(native.get(dimension))),
        );
        handoff_resources(
            &authority,
            &mut resources,
            repository,
            carry_memory,
            phase_amounts,
        )?;
        let (reopened_identity, repository) = runtime
            .block_on(
                crate::services::repository_administration::open_for_recovery(
                    request.pin.instance(),
                    request.source.repository(),
                    resources.clone(),
                ),
            )
            .map_err(|_| failure())?;
        if reopened_identity != identity {
            return Err(failure());
        }
        let fence = BackupPublisher::new(repository.as_ref(), &identity, &signer)
            .with_control_resources(&resources, carry_memory)
            .map_err(|_| failure())?
            .with_registry_verification(&registry)
            .map_err(|_| failure())?;
        runtime
            .block_on(fence.purge_tombstones())
            .map_err(|_| failure())?;
        drop(fence);
        access
            .claim_restore_target(
                request.pin.instance(),
                &custody
                    .catalog_secret(request.pin.instance())
                    .map_err(|_| failure())?,
                parameters.intent_digest(),
            )
            .map_err(storage::storage_failure)?;
        let catalog = Catalog::open(
            &authority,
            request.pin.instance(),
            custody
                .catalog_secret(request.pin.instance())
                .map_err(|_| failure())?,
        )
        .map_err(|_| failure())?;
        if catalog
            .restore_origin_intent()
            .map_err(|_| failure())?
            .is_none()
        {
            catalog
                .install_restore_origin(origin)
                .map_err(|_| failure())?;
        } else if catalog.restore_origin_intent().map_err(|_| failure())?
            != Some(parameters.intent_digest())
        {
            return Err(failure());
        }
        let basis = catalog.pin().map_err(|_| failure())?;
        let actor = Identity::authorize_backup_restore(&basis, &custody, request.pin, now()?)
            .map_err(|_| failure())?;
        // Resolve the exact accepted restore binding before any historical
        // operation transition. A changed key/request cannot reconcile state.
        if let Some(existing) =
            DurableOperationAdministration::inspect_by_idempotency(&catalog, request.idempotency)
                .map_err(|_| failure())?
            && (existing.backup_restore_parameters() != Some(parameters)
                || existing.request().principal() != actor.principal_id())
        {
            return Err(failure());
        }
        if TenantAdministration::restore_purge_exclusions(&basis).map_err(|_| failure())?
            == planned_exclusions
        {
            let mut publication = restored_publication;
            if let Some(previous) = DurableOperationAdministration::inspect(
                &catalog,
                positron_governance::OperationId::from_bytes(publication.capture_operation())
                    .map_err(|_| failure())?,
            )
            .map_err(|_| failure())?
            .and_then(|operation| operation.restored_backup_publication())
                && previous != publication
            {
                if !previous.same_restore_binding(publication) {
                    return Err(failure());
                }
                // Preserve both the source registration anchor and the stronger
                // first committed observation. A signed older head is a rollback.
                let anchored = BackupPublisher::new(repository.as_ref(), &identity, &signer)
                    .with_control_resources(&resources, carry_memory)
                    .map_err(|_| failure())?
                    .with_trusted_generation(previous.current_registry_generation())
                    .map_err(|_| failure())?;
                let mut proof = runtime
                    .block_on(anchored.begin_registry_verification(
                        request.idempotency.to_bytes(),
                        parameters.intent_digest(),
                    ))
                    .map_err(|_| failure())?;
                while !proof.complete().map_err(|_| failure())? {
                    runtime
                        .block_on(anchored.registry_verification_step(&mut proof))
                        .map_err(|_| failure())?;
                }
                if proof.verified_head().map_err(|_| failure())?
                    != publication.current_registry_generation()
                {
                    return Err(failure());
                }
                publication = previous;
            }
            DurableOperationAdministration::reconcile_restored_backup(
                &catalog,
                actor,
                publication,
                now()?,
            )
            .map_err(|_| failure())?;
        }
        let basis = catalog.pin().map_err(|_| failure())?;
        let stale_plan_failure = if TenantAdministration::restore_purge_exclusions(&basis)
            .map_err(|_| failure())?
            != planned_exclusions
        {
            let operation = DurableOperationAdministration::inspect_by_idempotency(
                &catalog,
                request.idempotency,
            )
            .map_err(|_| failure())?
            .ok_or_else(failure)?;
            if operation.backup_restore_parameters() != Some(parameters)
                || operation.request().principal() != actor.principal_id()
            {
                return Err(failure());
            }
            if operation.status().is_terminal() {
                if operation.status() != positron_governance::DurableOperationStatus::Failed {
                    return Err(BootstrapFailure::new(
                        BootstrapFailureCode::IdentityMismatch,
                    ));
                }
                Some(operation)
            } else {
                if operation.status() == positron_governance::DurableOperationStatus::Pending {
                    DurableOperationAdministration::begin(
                        &catalog,
                        actor,
                        operation.operation_id(),
                        now()?,
                    )
                    .map_err(|_| failure())?;
                }
                Some(
                    DurableOperationAdministration::fail_backup_restore(
                        &catalog,
                        actor,
                        operation.operation_id(),
                        now()?,
                    )
                    .map_err(|_| failure())?,
                )
            }
        } else {
            None
        };
        let (registration, _) = BackupRepositoryRegistration::find(
            &basis,
            request.pin.instance().to_bytes(),
            identity.repository_id(),
        )
        .map_err(|_| failure())?
        .ok_or_else(failure)?;
        let accepted = match DurableOperationAdministration::inspect_by_idempotency(
            &catalog,
            request.idempotency,
        )
        .map_err(|_| failure())?
        {
            Some(operation) => {
                if operation.backup_restore_parameters() != Some(parameters)
                    || operation.request().principal() != actor.principal_id()
                {
                    return Err(failure());
                }
                operation.request()
            },
            None => DurableOperationRequest::backup_restore(
                actor.principal_id(),
                request.idempotency,
                request.pin.instance().to_bytes(),
                basis.number(),
                now()?,
                parameters.intent_digest(),
            )
            .map_err(|_| failure())?,
        };
        let operation = match stale_plan_failure {
            Some(operation) => operation,
            None => DurableOperationAdministration::accept_backup_restore_registered(
                &catalog,
                actor,
                accepted,
                parameters,
                registration,
            )
            .map_err(|_| failure())?,
        };
        catalog.prepare_restore_segments().map_err(|_| failure())?;
        if !matches!(
            operation.status(),
            positron_governance::DurableOperationStatus::Failed
                | positron_governance::DurableOperationStatus::Cancelled
        ) {
            super::local_rotation::adopt_restored_route(
                &authority,
                &catalog,
                &custody,
                request.pin.instance(),
                operation,
            )
            .map_err(|_| failure())?;
        }
        let mut native_scopes = Vec::new();
        for tenant in TenantAdministration::restore_key_tenant_ids(&basis).map_err(|_| failure())? {
            for signal in [
                positron_domain::routing::SignalKind::Logs,
                positron_domain::routing::SignalKind::Traces,
            ] {
                let scopes = basis
                    .reachable_ledger_scopes(tenant, signal)
                    .map_err(|_| failure())?;
                if native_scopes.len() + scopes.len() > 4096 {
                    return Err(failure());
                }
                native_scopes.extend(scopes);
            }
        }
        drop(catalog);
        Ok(BackupRestoreSession {
            authority,
            access,
            custody,
            pin: request.pin,
            operation,
            runtime,
            repository,
            identity,
            signer,
            resources,
            registry,
            remote,
            manifest,
            source_catalog,
            recovered_keys,
            files,
            next_file: 0,
            offset: 0,
            record,
            native_scopes,
            native_index: 0,
            native_cursor: None,
        })
    }
}

pub(super) fn handoff_resources(
    authority: &StorageKernelResourceAuthority,
    resources: &mut Arc<NativeAwsResources>,
    repository: Box<dyn Repository>,
    carry_memory: u64,
    phase_amounts: ResourceAmounts,
) -> Result<(), BootstrapFailure> {
    // Close the completed transport before asking for exclusive ownership. The
    // original grant continues charging all retained restore state throughout.
    drop(repository);
    if phase_amounts.is_at_most(resources.granted())
        && let Some(owner) = Arc::get_mut(resources)
    {
        owner
            .try_resize_preserving_capacity(authority.governor(), phase_amounts)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        return Ok(());
    }
    let carry = authority
        .governor()
        .reserve(
            WorkClaim::backup_repository_read(ResourceAmounts::new([
                carry_memory,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]))
            .map_err(|_| failure())?,
        )
        .map_err(|failure| grant_failure(BootstrapResourceStage::RestoreCarryGrant, failure))?;
    // Keep the charge in the caller's early binding, including on phase refusal.
    // No transport opens while this memory-only carry grant is installed.
    *resources = NativeAwsResources::new(carry.transfer());
    let phase = NativeAwsResources::new(
        authority
            .governor()
            .reserve(WorkClaim::backup_repository_read(phase_amounts).map_err(|_| failure())?)
            .map_err(|failure| grant_failure(BootstrapResourceStage::RestorePhaseGrant, failure))?
            .transfer(),
    );
    *resources = phase;
    Ok(())
}
