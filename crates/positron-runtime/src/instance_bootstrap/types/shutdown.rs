use super::*;

const MAGIC: &[u8; 8] = b"POSSHUT1";
const RECORD_BYTES: usize = 156;

pub(crate) enum ShutdownPublicationFailure {
    Interrupted,
    Publication(BootstrapFailure),
}
impl From<BootstrapFailure> for ShutdownPublicationFailure {
    fn from(failure: BootstrapFailure) -> Self {
        Self::Publication(failure)
    }
}

/// Authenticated historical evidence of the last completed durable Drain.
/// Later Catalog publications do not make this a clean-startup assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GracefulShutdownRecord {
    transaction: TransactionId,
    catalog_generation: u64,
    predecessor: [u8; 32],
    governance_position: u64,
    governance_hash: [u8; 32],
    frontier_digest: [u8; 32],
    sealed_scopes: u32,
}

impl GracefulShutdownRecord {
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }
    #[must_use]
    pub const fn governance_position(&self) -> u64 {
        self.governance_position
    }
    #[must_use]
    pub const fn sealed_scopes(&self) -> u32 {
        self.sealed_scopes
    }
}

impl InitializedInstance {
    pub(crate) fn publish_graceful_shutdown(
        &self,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<(), ShutdownPublicationFailure> {
        if cancelled() {
            return Err(ShutdownPublicationFailure::Interrupted);
        }
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| unavailable())?;
        let catalog =
            Catalog::open(&self._authority, self.instance, secret).map_err(|_| unavailable())?;
        let basis = catalog.pin().map_err(|_| unavailable())?;
        let identity = positron_governance::Identity::open(&basis).map_err(|_| unavailable())?;
        let tenants = positron_governance::TenantAdministration::registered_tenant_ids(&basis)
            .map_err(|_| unavailable())?;

        for tenant in tenants {
            for signal in [SignalKind::Logs, SignalKind::Traces] {
                for scope in basis
                    .reachable_ledger_scopes(tenant, signal)
                    .map_err(|_| unavailable())?
                {
                    if cancelled() {
                        return Err(ShutdownPublicationFailure::Interrupted);
                    }
                    let protection = crate::services::tenant_segment_key(self, &identity, scope)
                        .map_err(|_| unavailable())?;
                    let ledger = positron_kernel::ActiveSegmentLedger::open_for_maintenance_with_retention_time(
                        &self._authority, &self.retention_time, &catalog, scope, protection,
                    ).map_err(|_| unavailable())?;
                    ledger.seal().map_err(|_| unavailable())?;
                    if cancelled() {
                        return Err(ShutdownPublicationFailure::Interrupted);
                    }
                }
            }
        }
        drop(basis);
        drop(catalog);
        if cancelled() {
            return Err(ShutdownPublicationFailure::Interrupted);
        }
        let checkpoint = self.checkpoint_governance(None)?;
        if cancelled() {
            return Err(ShutdownPublicationFailure::Interrupted);
        }
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| unavailable())?;
        let catalog =
            Catalog::open(&self._authority, self.instance, secret).map_err(|_| unavailable())?;
        let basis = catalog.pin().map_err(|_| unavailable())?;
        let transaction =
            TransactionId::new(self.key.random_identifier().map_err(|_| unavailable())?)
                .map_err(|_| unavailable())?;
        let mut encoded = Vec::with_capacity(RECORD_BYTES);
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&self.instance.to_bytes());
        encoded.extend_from_slice(&transaction.to_bytes());
        encoded.extend_from_slice(
            &basis
                .number()
                .checked_add(1)
                .ok_or_else(unavailable)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&basis.identity().to_bytes());
        encoded.extend_from_slice(&checkpoint.position().to_be_bytes());
        encoded.extend_from_slice(&checkpoint.record_hash());
        let (frontier_digest, sealed_scopes) = final_frontier_binding(&basis)?;
        encoded.extend_from_slice(&frontier_digest);
        encoded.extend_from_slice(&sealed_scopes.to_be_bytes());
        let mut objects = shutdown_objects(&basis)?;
        objects.push(positron_kernel::CatalogObject::new(encoded).map_err(|_| unavailable())?);
        let proposal = CatalogProposal::new(
            transaction,
            basis.format_epoch().ok_or_else(unavailable)?,
            objects,
        )
        .map_err(|_| unavailable())?;
        if cancelled() {
            return Err(ShutdownPublicationFailure::Interrupted);
        }
        // Ordinary work is closed and fully reconciled before the final
        // protected durability transaction. Its marker is Drain completion.
        self.begin_shutdown()?;
        match catalog
            .commit_interruptibly(basis.identity(), proposal, cancelled)
            .map_err(|_| unavailable())?
        {
            Some(_) => Ok(()),
            None => Err(ShutdownPublicationFailure::Interrupted),
        }
    }

    /// Inspects the last authenticated Drain record while holding local storage
    /// ownership. Existing publication durability is confirmed before returning
    /// evidence; its generation explicitly distinguishes historical state.
    pub fn graceful_shutdown_record(
        &self,
    ) -> Result<Option<GracefulShutdownRecord>, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| unavailable())?;
        let view = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| unavailable())?;
        let snapshot = view.snapshot();
        let mut record = None;
        for object in snapshot.object_identities() {
            let bytes = snapshot
                .object(object)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            if !bytes.starts_with(MAGIC) {
                continue;
            }
            if record.is_some()
                || bytes.len() != RECORD_BYTES
                || bytes.get(8..24) != Some(self.instance.to_bytes().as_slice())
            {
                return Err(unavailable());
            }
            let generation = decode_u64(bytes, 40)?;
            if generation > snapshot.number() {
                return Err(unavailable());
            }
            record = Some(GracefulShutdownRecord {
                transaction: TransactionId::new(decode_array(bytes, 24)?)
                    .map_err(|_| unavailable())?,
                catalog_generation: generation,
                predecessor: decode_array(bytes, 48)?,
                governance_position: decode_u64(bytes, 80)?,
                governance_hash: decode_array(bytes, 88)?,
                frontier_digest: decode_array(bytes, 120)?,
                sealed_scopes: u32::from_be_bytes(decode_array(bytes, 152)?),
            });
        }
        if let Some(record) = &record {
            let checkpoint = view
                .latest_audit_checkpoint()
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            let (_, governance) = snapshot.governance_object().map_err(|_| unavailable())?;
            checkpoint
                .verify(governance.integrity_public_key())
                .map_err(|_| unavailable())?;
            let checkpoint_matches = checkpoint.position() == record.governance_position
                && checkpoint.record_hash() == record.governance_hash;
            let historical_matches = view.governance_audit_records().iter().any(|audit| {
                audit.position() == record.governance_position
                    && audit.record_hash() == record.governance_hash
            });
            if !checkpoint_matches && !historical_matches {
                return Err(unavailable());
            }
            let secret = self
                .key
                .catalog_secret(self.instance)
                .map_err(|_| unavailable())?;
            let catalog = Catalog::open(&self._authority, self.instance, secret)
                .map_err(|_| unavailable())?;
            let committed = catalog
                .confirm_committed_transaction(record.transaction)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            if committed.number() != record.catalog_generation
                || committed.predecessor().to_bytes() != record.predecessor
            {
                return Err(unavailable());
            }
            let (digest, scopes) = final_frontier_binding(committed.snapshot())?;
            if digest != record.frontier_digest || scopes != record.sealed_scopes {
                return Err(unavailable());
            }
        }
        Ok(record)
    }
}

fn decode_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], BootstrapFailure> {
    bytes
        .get(offset..offset.saturating_add(N))
        .and_then(|value| value.try_into().ok())
        .ok_or_else(unavailable)
}
fn decode_u64(bytes: &[u8], offset: usize) -> Result<u64, BootstrapFailure> {
    decode_array(bytes, offset).map(u64::from_be_bytes)
}
fn unavailable() -> BootstrapFailure {
    BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable)
}

fn shutdown_objects(
    basis: &positron_kernel::CatalogSnapshot,
) -> Result<Vec<positron_kernel::CatalogObject>, BootstrapFailure> {
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(basis.object_count().saturating_add(1))
        .map_err(|_| unavailable())?;
    for object in basis.object_identities() {
        let bytes = basis
            .object(object)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if bytes.starts_with(MAGIC) {
            continue;
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(bytes.len())
            .map_err(|_| unavailable())?;
        retained.extend_from_slice(bytes);
        objects.push(positron_kernel::CatalogObject::new(retained).map_err(|_| unavailable())?);
    }
    Ok(objects)
}

fn final_frontier_binding(
    snapshot: &positron_kernel::CatalogSnapshot,
) -> Result<([u8; 32], u32), BootstrapFailure> {
    let tenants = positron_governance::TenantAdministration::registered_tenant_ids(snapshot)
        .map_err(|_| unavailable())?;
    let mut digest = Sha256::new();
    digest.update(b"positron.graceful-shutdown.frontiers.v1\0");
    let mut scopes = 0_u32;
    for tenant in tenants {
        for signal in [SignalKind::Logs, SignalKind::Traces] {
            for scope in snapshot
                .reachable_ledger_scopes(tenant, signal)
                .map_err(|_| unavailable())?
            {
                scopes = scopes.checked_add(1).ok_or_else(unavailable)?;
                digest.update(tenant.to_bytes());
                digest.update([match signal {
                    SignalKind::Logs => 1,
                    SignalKind::Traces => 2,
                }]);
                digest.update(scope.shard_id().value().to_be_bytes());
                digest.update(
                    snapshot
                        .integrity_scope_source_identity(scope)
                        .map_err(|_| unavailable())?,
                );
            }
        }
    }
    Ok((digest.finalize().into(), scopes))
}
