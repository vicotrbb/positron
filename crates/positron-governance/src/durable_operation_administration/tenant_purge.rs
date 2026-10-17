//! Durable purge intent is tenant-scoped and cannot be cancelled after admission closes.
use super::*;
use positron_domain::identity::TenantId;
impl DurableOperationRequest {
    pub fn tenant_purge(
        principal: positron_domain::identity::PrincipalId,
        tenant: TenantId,
        idempotency: AdministrativeIdempotencyKey,
        accepted_generation: u64,
        accepted_at_unix_seconds: u64,
        confirmation: [u8; 32],
    ) -> Result<Self, DurableOperationFailure> {
        if accepted_generation == 0 || accepted_at_unix_seconds == 0 || confirmation == [0; 32] {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let kind = DurableOperationKind::TenantPurge;
        let id = Self::operation_id_for_audit(
            principal,
            idempotency,
            kind,
            Some(tenant.to_bytes()),
            accepted_generation,
            Some(tenant),
            Some(confirmation),
        )?;
        let mut hash = Sha256::new();
        hash.update(types::REQUEST_DOMAIN);
        hash.update(principal.to_bytes());
        hash.update(idempotency.to_bytes());
        hash.update([kind.code()]);
        hash.update(tenant.to_bytes());
        hash.update(accepted_generation.to_be_bytes());
        hash.update(confirmation);
        let request = Self {
            principal,
            idempotency,
            kind,
            target_identity: Some(tenant.to_bytes()),
            applicable_tenant: Some(tenant),
            accepted_generation,
            accepted_at_unix_seconds,
            operation_request_digest: Some(confirmation),
            digest: hash.finalize().into(),
        };
        if request.operation_id() != id {
            return Err(DurableOperationFailure::InvalidInput);
        }
        Ok(request)
    }
}
impl DurableOperationAdministration {
    pub fn resume_tenant_purge_actor(
        catalog: &Catalog<'_>,
        id: OperationId,
        now: u64,
    ) -> Result<crate::AuthorizedContext, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation =
            find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
        if operation.kind() != DurableOperationKind::TenantPurge {
            return Err(DurableOperationFailure::InvalidState);
        }
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        crate::Identity::open(&snapshot)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?
            .resume_system_operation_actor(operation.request.principal, governance.instance(), now)
            .map_err(|_| DurableOperationFailure::Unauthorized)
    }
    pub fn publish_tenant_purge_boundary(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let mut operation =
            find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        if operation.kind() != DurableOperationKind::TenantPurge
            || operation.phase != DurableOperationPhase::Draining
            || now < operation.updated_at_unix_seconds
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        let tenant = operation
            .request
            .applicable_tenant
            .ok_or(DurableOperationFailure::InvalidState)?;
        if crate::TenantAdministration::lifecycle_state(&snapshot, tenant)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?
            .0
            != positron_domain::lifecycle::TenantLifecycleState::Purging
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        if operation.boundary == DurableOperationBoundary::CatalogGenerationPublished {
            return Ok(operation);
        }
        operation.boundary = DurableOperationBoundary::CatalogGenerationPublished;
        operation.updated_at_unix_seconds = now;
        operation.revision = operation
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        publish(catalog, &snapshot, operation)
    }

    pub fn accept_tenant_purge(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
        if request.kind() != DurableOperationKind::TenantPurge {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if let Some(existing) = find_by_key(&snapshot, request.idempotency)? {
            return match existing {
                OperationKeyLookup::Operation(operation) => exact_replay(*operation, request),
                OperationKeyLookup::Expired(binding) => {
                    binding.exact_replay(request)?;
                    Err(DurableOperationFailure::CompletedLookupExpired)
                },
            };
        }
        if snapshot.number() != request.accepted_generation {
            return Err(DurableOperationFailure::StaleGeneration);
        }
        let tenant = request
            .applicable_tenant
            .ok_or(DurableOperationFailure::InvalidInput)?;
        if !crate::TenantAdministration::list(&snapshot)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?
            .iter()
            .any(|current| current.tenant_id() == tenant)
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        publish(catalog, &snapshot, DurableOperation::accepted(request))
    }
    pub fn reject_tenant_purge(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation =
            find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        if operation.kind() != DurableOperationKind::TenantPurge
            || operation.boundary != DurableOperationBoundary::NotCrossed
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        publish(
            catalog,
            &snapshot,
            operation.failed(now, DurableOperationTerminalError::HandlerRejected)?,
        )
    }
    pub fn next_tenant_purge(
        catalog: &Catalog<'_>,
    ) -> Result<Option<DurableOperation>, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let mut selected: Option<DurableOperation> = None;
        for id in snapshot.object_identities() {
            let bytes = snapshot
                .object(id)
                .map_err(map_catalog)?
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
            if let Some(operation) = decode_operation(bytes)?
                && operation.kind() == DurableOperationKind::TenantPurge
                && !operation.status().is_terminal()
                && selected.is_none_or(|current| {
                    operation.operation_id().to_bytes() < current.operation_id().to_bytes()
                })
            {
                selected = Some(operation);
            }
        }
        Ok(selected)
    }
    pub fn publish_tenant_purge_repository(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        previous: CatalogObjectId,
        replacement: CatalogObject,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let mut operation =
            find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        if operation.kind() != DurableOperationKind::TenantPurge
            || operation.phase != DurableOperationPhase::CatalogPublication
            || now < operation.updated_at_unix_seconds
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        operation.updated_at_unix_seconds = now;
        operation.revision = operation
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        publish_with_objects(
            catalog,
            &snapshot,
            operation,
            vec![replacement],
            Some(previous),
        )
    }
    /// Commits the owning modules' purge transformation with the operation transition and audit.
    pub fn publish_tenant_purge_progress(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        objects: Vec<CatalogObject>,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation =
            find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        if operation.kind() != DurableOperationKind::TenantPurge
            || operation.boundary != DurableOperationBoundary::CatalogGenerationPublished
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        let next = if operation.phase == DurableOperationPhase::CatalogPublication
            && now >= operation.updated_at_unix_seconds
        {
            let mut next = operation;
            next.updated_at_unix_seconds = now;
            next.revision = next
                .revision
                .checked_add(1)
                .ok_or(DurableOperationFailure::CapacityExceeded)?;
            next
        } else {
            operation.drained(now)?
        };
        publish_purge_objects(catalog, &snapshot, next, objects)
    }
    /// The Runtime's repository owner must prove its complete registered scope
    /// under the same Catalog gate. Governance additionally requires the live
    /// owner's private exact-generation proof and constructs terminal records.
    pub fn complete_tenant_purge(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        proof: &positron_kernel::TenantKeyReclamationProof,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation =
            find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        if operation.kind() != DurableOperationKind::TenantPurge
            || operation.phase != DurableOperationPhase::CatalogPublication
            || operation.boundary != DurableOperationBoundary::CatalogGenerationPublished
            || operation.request.applicable_tenant != Some(proof.tenant_id())
            || snapshot.identity() != proof.catalog_generation()
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        let objects = crate::TenantAdministration::complete_live_purge_objects(
            &snapshot,
            proof.tenant_id(),
            proof,
        )
        .map_err(|_| DurableOperationFailure::InvalidState)?;
        publish_purge_objects(catalog, &snapshot, operation.succeeded(now)?, objects)
    }
}

fn publish_purge_objects(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    next: DurableOperation,
    mut objects: Vec<CatalogObject>,
) -> Result<DurableOperation, DurableOperationFailure> {
    let id = next.operation_id();
    let mut retained = Vec::new();
    for object in objects.drain(..) {
        if decode_operation(object.canonical_bytes())?
            .is_some_and(|value| value.operation_id() == id)
        {
            continue;
        }
        retained.push(object);
    }
    retained.push(CatalogObject::new(encode_operation(next)).map_err(map_catalog)?);
    let proposal = CatalogProposal::new(
        transition_transaction(next)?,
        snapshot
            .format_epoch()
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        retained,
    )
    .map_err(map_catalog)?;
    let commit = catalog
        .commit_prepared(
            snapshot.identity(),
            proposal,
            AuditIntent::new(encode_audit(next)?).map_err(map_catalog)?,
            transition_request_digest(next),
        )
        .map_err(map_catalog)?;
    operation_from_snapshot(commit.snapshot(), id)
}
