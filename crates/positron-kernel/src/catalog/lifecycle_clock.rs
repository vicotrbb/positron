//! Retain genuine trusted elapsed time without changing operation or data state.
use super::*;
use crate::RetentionTimeAuthority;

impl Catalog<'_> {
    /// Checkpoints only the existing Lifecycle Clock authority. No caller time
    /// or segment scope is accepted, and unpublished intents remain untouched.
    pub fn checkpoint_lifecycle_time(
        &self,
        clock: &RetentionTimeAuthority,
    ) -> Result<CatalogCommit, CatalogFailure> {
        if self.has_prepared_transaction()? {
            return Err(CatalogFailure::new(CatalogFailureCode::ConcurrentWriter));
        }
        let basis = self.pin()?;
        let _copy = self.reserve_catalog_proposal_copy(&basis)?;
        clock
            .recover_catalog_anchor(&basis)
            .map_err(clock_failure)?;
        let mut staged = clock.stage_catalog_anchor().map_err(clock_failure)?;
        let record = staged
            .governance_anchor_record(&basis)
            .map_err(clock_failure)?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(
                basis
                    .object_count()
                    .checked_add(1)
                    .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
            )
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let mut seen = false;
        let mut unchanged = false;
        for bytes in basis.plaintext_objects() {
            if crate::retention_time::validate_catalog_anchor_singleton(bytes, &mut seen)
                .map_err(clock_failure)?
            {
                unchanged = bytes == record;
            } else {
                objects.push(CatalogObject::new(bytes.to_vec())?);
            }
        }
        if unchanged {
            let current = self.confirm_current_publication()?;
            if current.identity() != basis.identity() {
                return Err(CatalogFailure::stale(current.identity()));
            }
            staged.commit();
            return Ok(current);
        }
        let anchor = CatalogObject::new(record.clone())?;
        let mut binding = Vec::new();
        binding
            .try_reserve_exact(96)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        binding.extend_from_slice(b"positron.lifecycle.checkpoint.v1");
        binding.extend_from_slice(&basis.identity().to_bytes());
        binding.extend_from_slice(&anchor.identity().to_bytes());
        let digest = CatalogObject::new(binding)?.identity().to_bytes();
        let transaction = TransactionId::new(
            digest
                .get(..16)
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?
                .try_into()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
        )?;
        objects.push(anchor);
        let proposal = CatalogProposal::new(
            transaction,
            basis
                .format_epoch()
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::UnsupportedFormat))?,
            objects,
        )?;
        let claim = RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            commit_resource_claim(&proposal, None)?,
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let reservation = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(CatalogFailure::admission)?;
        let result = {
            let _operation = self
                .operation
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            {
                let secret = self
                    .secret
                    .lock()
                    .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
                let state = self
                    .state
                    .lock()
                    .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
                if self.storage.has_prepared_transaction(
                    &secret,
                    self.instance,
                    state.current.identity(),
                )? {
                    return Err(CatalogFailure::new(CatalogFailureCode::ConcurrentWriter));
                }
            }
            self.commit_unreserved_interruptibly(
                basis.identity(),
                proposal,
                None,
                None,
                &mut || false,
            )
        };
        drop(reservation);
        let committed = match result {
            Ok(commit) => commit,
            Err(failure) => {
                let Some(exact) = self.confirm_committed_transaction(transaction)? else {
                    return Err(failure);
                };
                let current = self.confirm_current_publication()?;
                if current.identity() != exact.identity()
                    || exact.predecessor() != basis.identity()
                    || !exact
                        .snapshot()
                        .plaintext_objects()
                        .any(|bytes| bytes == record)
                {
                    return Err(failure);
                }
                exact
            },
        };
        staged.commit();
        Ok(committed)
    }
}

fn clock_failure(_: crate::LifecycleClockFailure) -> CatalogFailure {
    CatalogFailure::new(CatalogFailureCode::StorageUnavailable)
}
