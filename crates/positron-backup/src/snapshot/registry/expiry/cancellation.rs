use super::*;
impl BackupPublisher<'_> {
    /// Locate only this operation's authenticated unpublished candidate. A
    /// published snapshot cannot be cancelled through this command.
    pub async fn cancellation_candidate(
        &self,
        snapshot: [u8; 16],
    ) -> Result<Option<BackupReceipt>, RepositoryFailure> {
        self.require_identity().await?;
        let (head, generation, _) = self.current().await?;
        let candidate = if let Some(generation) = generation {
            if generation
                .snapshots
                .iter()
                .any(|receipt| receipt.snapshot == snapshot)
                || generation
                    .claims
                    .iter()
                    .any(|claim| claim.receipt.snapshot == snapshot)
            {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            generation
                .reservations
                .iter()
                .find(|receipt| receipt.snapshot == snapshot)
                .copied()
        } else {
            None
        };
        if self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
            .map(|head| head.version())
            != head
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        Ok(candidate)
    }
    /// Only an unpublished exact signed reservation may enter cancellation.
    pub async fn prepare_cancellation(
        &self,
        snapshot: [u8; 16],
        expected_manifest: [u8; 32],
    ) -> Result<BackupCleanupPlan, RepositoryFailure> {
        self.prepare_cleanup(
            snapshot,
            snapshot,
            expected_manifest,
            BackupCleanupReason::Cancellation,
        )
        .await
    }
    /// Reconcile/abort one native multipart upload while every candidate object
    /// remains protected by its reservation. Native capabilities stay in Kernel.
    pub async fn scan_cancellation_step(
        &self,
        plan: &mut BackupCleanupPlan,
    ) -> Result<bool, RepositoryFailure> {
        if plan.reason != BackupCleanupReason::Cancellation {
            return Err(RepositoryFailure::InvalidInput);
        }
        self.ensure_control_memory(0, plan.retained_memory_bytes()?)?;
        self.require_head(plan.head).await?;
        if let Some(object) = plan.uploads.get(plan.next_upload) {
            let upload = crate::UploadPlan::new(object.object(), object.length)?;
            if self.repository.inspect_upload(upload.id()).await?.is_some() {
                self.repository.abort_upload(upload.id()).await?;
            }
            plan.next_upload += 1;
            self.require_head(plan.head).await?;
            return Ok(false);
        }
        self.scan_expiry_step(plan).await
    }
    pub async fn claim_cancellation(
        &self,
        plan: &BackupCleanupPlan,
    ) -> Result<BackupCleanupProgress, RepositoryFailure> {
        if plan.reason != BackupCleanupReason::Cancellation {
            return Err(RepositoryFailure::InvalidInput);
        }
        self.claim_cleanup(plan).await
    }
}
