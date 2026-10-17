use super::*;
impl OfflineUpgradeSession {
    /// Requalifies the complete installed candidate before the durable release
    /// pointer is published. Staging or replacing the executable stays external.
    pub fn publish_installed(
        &mut self,
        configuration: &EffectiveConfiguration,
    ) -> Result<DurableOperation, UpgradeFailure> {
        self.require_recovered_clock()?;
        let operation = self.status()?;
        let parameters = operation
            .upgrade_parameters()
            .ok_or(UpgradeFailure::UnsafeState)?;
        let request = crate::upgrade::installed_upgrade_request(
            configuration,
            parameters.target().manifest_digest(),
            parameters.backup().repository().repository_id(),
            parameters.backup().retention_seconds(),
            operation.request().idempotency_key(),
            operation.request().accepted_generation(),
        )?;
        let plan = request.verify_payload(
            &self.instance,
            configuration.schema_version(),
            parameters.format_epoch(),
        )?;
        self.publish(plan.target())
    }

    /// Attests this operator-selected source artifact before the audited
    /// format-neutral rollback selection. Deployment replacement is external.
    pub fn rollback_installed(
        &mut self,
        configuration: &EffectiveConfiguration,
        key: AdministrativeIdempotencyKey,
        revision: u64,
    ) -> Result<DurableOperation, UpgradeFailure> {
        self.require_recovered_clock()?;
        let verification = super::super::installed_upgrade_startup(configuration)?
            .ok_or(UpgradeFailure::AuthenticationFailed)?;
        let executable =
            std::env::current_exe().map_err(|_| UpgradeFailure::ArtifactUnavailable)?;
        self.rollback(&verification.release, &executable, key, revision)
    }
}
