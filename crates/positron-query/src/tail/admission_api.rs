use super::{QueryFailure, QueryService, TailCursor, TailSession, TailSourceSet, TailStart};

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub fn tail(
        &self,
        query: crate::PlannedQuery<'kernel>,
        start: TailStart,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let reader = self
            .ledger
            .reader()
            .map_err(crate::execution_support::map_ledger_failure)?;
        self.tail_with_sources(query, start, TailSourceSet::single(reader)?)
    }

    pub fn tail_with_sources(
        &self,
        query: crate::PlannedQuery<'kernel>,
        start: TailStart,
        sources: TailSourceSet<'kernel, 'catalog, 'ledger>,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        self.admit_tail(query, start, None, sources)
    }

    pub fn resume_tail(
        &self,
        query: crate::PlannedQuery<'kernel>,
        cursor: &TailCursor,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let reader = self
            .ledger
            .reader()
            .map_err(crate::execution_support::map_ledger_failure)?;
        self.resume_tail_with_sources(query, cursor, TailSourceSet::single(reader)?)
    }

    pub fn resume_tail_with_sources(
        &self,
        query: crate::PlannedQuery<'kernel>,
        cursor: &TailCursor,
        sources: TailSourceSet<'kernel, 'catalog, 'ledger>,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let state = TailCursor::decode(&self.ledger.control_tokens(), cursor)?;
        let (tenant, _, _generation) = self.current_query_catalog(query.context)?;
        super::validate_tail_shape(&query, &sources, tenant, self.ledger.scope())?;
        let signal_digest = sources.digest(&self.ledger.control_tokens())?;
        state.validate_for_resume(
            query.context.principal_id(),
            tenant,
            query.context.authorization_generation(),
            query.plan_digest,
            signal_digest,
            self.now()?,
        )?;
        super::resume::validate_resume_history(&state, &sources)?;
        self.admit_tail(
            query,
            TailStart::Now,
            Some((state, cursor.clone())),
            sources,
        )
    }
}

impl QueryService<'_, '_, '_> {
    /// Releases the authenticated standalone tail cursor's original source lease.
    pub fn cancel_tail_cursor(
        &self,
        context: positron_governance::AuthorizedContext,
        cursor: &TailCursor,
    ) -> Result<(), crate::QueryCancellationFailure> {
        let (tenant, _, _) = self.current_query_catalog(context)?;
        let state = TailCursor::decode(&self.ledger.control_tokens(), cursor)?;
        crate::execution_state::validate_authorization(
            state.principal(),
            state.tenant(),
            state.authorization_generation(),
            context.principal_id(),
            tenant,
            context.authorization_generation(),
        )?;
        let bindings = state
            .source_bindings()
            .ok_or_else(|| QueryFailure::new(crate::QueryFailureCode::InvalidCursor))?;
        if bindings.len() != 1
            || bindings
                .first()
                .is_none_or(|binding| binding.shard() != self.ledger.scope().shard_id())
        {
            return Err(QueryFailure::new(crate::QueryFailureCode::StoreUnavailable).into());
        }
        for binding in bindings {
            // An explicit command reports this attempt's outcome. A temporary
            // session owner would retry release from Drop after an error.
            crate::execution::release_cancelled_lease(
                self.ledger,
                self.maintenance,
                binding.lease(),
            )?;
        }
        Ok(())
    }
}
