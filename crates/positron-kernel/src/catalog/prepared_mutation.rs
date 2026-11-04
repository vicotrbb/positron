use super::*;

impl Catalog<'_> {
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn prepare_and_commit_for_test<T, E>(
        &self,
        prepare: impl FnOnce(&CatalogSnapshot) -> Result<(T, Option<CatalogProposal>), E>,
    ) -> Result<(T, Option<CatalogCommit>), E>
    where
        E: From<CatalogFailure>,
    {
        self.prepare_and_commit(prepare)
    }

    /// Builds one mutation from freshly recovered state while retaining the
    /// Catalog's existing operation, state, and key exclusion through publication.
    /// Preparation must not reenter Catalog or acquire another owner lock.
    pub(crate) fn prepare_and_commit<T, E>(
        &self,
        prepare: impl FnOnce(&CatalogSnapshot) -> Result<(T, Option<CatalogProposal>), E>,
    ) -> Result<(T, Option<CatalogCommit>), E>
    where
        E: From<CatalogFailure>,
    {
        let claim = RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            recovery_resource_claim(),
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let reservation = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(CatalogFailure::admission)?;
        let (value, result) = {
            let _operation = self
                .operation
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            let mut state = self
                .state
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            let secret = self
                .secret
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            {
                let recovered = recover(&self.storage, &secret, self.instance)?;
                if recovered.current.number() > state.current.number() {
                    *state = recovered;
                }
            }
            // Recovery's transient buffers are gone. Retained lease growth and
            // proposal preparation keep the caller's ordinary admission; they
            // must not compete with the completed recovery's peak claim.
            drop(reservation);
            let expected = state.current.identity();
            let (value, proposal) = prepare(&state.current)?;
            let result = proposal
                .map(|proposal| {
                    if !proposal.format_epoch.is_catalog_writable() {
                        return Err(CatalogFailure::new(CatalogFailureCode::UnsupportedFormat));
                    }
                    let claim = RecoveryWorkClaim::system(
                        RecoveryWorkKind::DurabilityCompletion,
                        commit_resource_claim(&proposal, None)?,
                    )
                    .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
                    let _durability = self
                        .authority
                        .recovery()
                        .reserve(claim)
                        .map_err(CatalogFailure::admission)?;
                    self.commit_recovered_interruptibly(
                        (&mut state, &secret),
                        expected,
                        proposal,
                        None,
                        None,
                        &mut || false,
                    )
                })
                .transpose();
            (value, result)
        };
        #[cfg(any(test, feature = "test-support"))]
        if result
            .as_ref()
            .is_err_and(|failure| failure.code() == CatalogFailureCode::StorageUnavailable)
        {
            storage::after_ambiguous_publication(self);
        }
        Ok((value, result?))
    }
}
