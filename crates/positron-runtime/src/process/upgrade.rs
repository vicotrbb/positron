use super::*;
mod preflight;
use crate::upgrade::{UpgradeFailure, UpgradeRequest};
pub(crate) use preflight::accept_preflight;

use positron_governance::{
    AuthorizedContext, CompatibilityHints, DurableOperation, DurableOperationAdministration,
    DurableOperationRequest, OperationId, PresentedCredential, RequestedIntent, UpgradeParameters,
    UpgradeReleaseIdentity, UpgradeStage,
};
use positron_kernel::{Catalog, ResourceAmounts, ResourceDimension, WorkClaim};

/// Unforgeable local handoff from accepted intent to the real Process Drain.
#[derive(Debug)]
pub struct AcceptedUpgrade {
    operation: DurableOperation,
}
impl AcceptedUpgrade {
    pub const fn operation(&self) -> DurableOperation {
        self.operation
    }
}

/// The ordinary Drain owner remains responsible for deadlines and forced exits.
pub struct DrainingUpgrade {
    process: DrainingProcess,
    operation: OperationId,
}
impl DrainingUpgrade {
    pub fn health(&self) -> HealthState {
        self.process.health()
    }
    pub fn finish_with_termination_probe(
        self,
        trigger: ShutdownTrigger,
        probe: impl FnMut() -> bool,
    ) -> Result<OperationId, ExitOutcome> {
        match self.process.finish_with_termination_probe(trigger, probe) {
            ExitOutcome::Graceful => Ok(self.operation),
            outcome => Err(outcome),
        }
    }
    pub fn finish(self, trigger: ShutdownTrigger) -> Result<OperationId, ExitOutcome> {
        match self.process.finish(trigger) {
            ExitOutcome::Graceful => Ok(self.operation),
            outcome => Err(outcome),
        }
    }
}

impl RunningProcess {
    /// Performs signed, physical and capacity preflight while Serving. A refusal
    /// leaves admission open and publishes no Upgrade operation.
    pub fn accept_upgrade(
        &self,
        bearer: &str,
        request: UpgradeRequest,
    ) -> Result<AcceptedUpgrade, UpgradeFailure> {
        let instance = self.instance.as_ref().ok_or(UpgradeFailure::UnsafeState)?;
        let actor = instance
            .attribute(
                PresentedCredential::parse(bearer)
                    .map_err(|_| UpgradeFailure::AuthenticationFailed)?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| UpgradeFailure::AuthenticationFailed)?;
        if self.health().phase() != ProcessPhase::Serving {
            return Err(UpgradeFailure::UnsafeState);
        }
        let configuration = self
            .configuration
            .as_ref()
            .ok_or(UpgradeFailure::UnsafeState)?
            .observed()
            .map_err(|_| UpgradeFailure::UnsafeState)?;
        let configuration = configuration.effective();
        let services = self.services.as_ref().ok_or(UpgradeFailure::UnsafeState)?;
        let operation = accept_preflight(instance, services, configuration, actor, request)?;
        Ok(AcceptedUpgrade { operation })
    }

    /// The native Process owner observes only accepted pre-Drain intent.
    pub fn pending_upgrade_operation(&self) -> Result<Option<DurableOperation>, UpgradeFailure> {
        let instance = self.instance.as_ref().ok_or(UpgradeFailure::UnsafeState)?;
        let _gate = self
            .services
            .as_ref()
            .map(|services| services.catalog_operation())
            .transpose()
            .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| UpgradeFailure::UnsafeState)?,
        )
        .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
        Ok(
            DurableOperationAdministration::next_upgrade_operation(&catalog, None)
                .map_err(|_| UpgradeFailure::PersistenceUnavailable)?
                .filter(|operation| {
                    matches!(
                        operation.upgrade_stage(),
                        Some(UpgradeStage::Preflight | UpgradeStage::Draining)
                    )
                }),
        )
    }

    /// Cold pre-Drain recovery keeps data admission closed and authenticates
    /// the executing source against the installed Project Trust authority.
    pub fn resume_configured_upgrade_drain(
        &self,
        configuration: &EffectiveConfiguration,
    ) -> Result<Option<AcceptedUpgrade>, UpgradeFailure> {
        let Some(operation) = self.pending_upgrade_operation()? else {
            return Ok(None);
        };
        let instance = self.instance.as_ref().ok_or(UpgradeFailure::UnsafeState)?;
        let verification = crate::upgrade::installed_upgrade_startup(configuration)?
            .ok_or(UpgradeFailure::AuthenticationFailed)?;
        let gate = self
            .services
            .as_ref()
            .map(|services| services.catalog_operation())
            .transpose()
            .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| UpgradeFailure::UnsafeState)?,
        )
        .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
        DurableOperationAdministration::resume_upgrade_actor(
            &catalog,
            operation.operation_id(),
            instance
                .retention_time
                .security_time_seconds()
                .map_err(|_| UpgradeFailure::UnsafeState)?,
        )
        .map_err(|_| UpgradeFailure::AuthenticationFailed)?;
        let now = instance
            .retention_time
            .governance_now_seconds()
            .map_err(|_| UpgradeFailure::CapacityUnavailable)?;
        if now < operation.updated_at_unix_seconds() {
            return Err(UpgradeFailure::CapacityUnavailable);
        }
        drop(catalog);
        drop(gate);
        verification.attest(
            instance,
            operation
                .upgrade_parameters()
                .ok_or(UpgradeFailure::UnsafeState)?
                .source(),
        )?;
        Ok(Some(AcceptedUpgrade { operation }))
    }

    /// Consumes the live owner only after intent has durably committed. The
    /// ordinary shutdown marker, never a phase label, proves successful Drain.
    pub fn begin_upgrade(self, accepted: AcceptedUpgrade) -> Result<DrainingUpgrade, ExitOutcome> {
        let id = accepted.operation.operation_id();
        {
            let instance = self
                .instance
                .as_ref()
                .ok_or(ExitOutcome::StartupUnavailable(
                    BootstrapFailureCode::CatalogUnavailable,
                ))?;
            if accepted.operation.target_identity() != Some(instance.instance.to_bytes()) {
                return Err(ExitOutcome::StartupUnavailable(
                    BootstrapFailureCode::CatalogUnavailable,
                ));
            }
            let _gate = self
                .services
                .as_ref()
                .map(|services| services.catalog_operation())
                .transpose()
                .map_err(|_| {
                    ExitOutcome::StartupUnavailable(BootstrapFailureCode::CatalogUnavailable)
                })?;
            let catalog = Catalog::open(
                &instance._authority,
                instance.instance,
                instance
                    .key
                    .catalog_secret(instance.instance)
                    .map_err(|_| {
                        ExitOutcome::StartupUnavailable(BootstrapFailureCode::CatalogUnavailable)
                    })?,
            )
            .map_err(|_| {
                ExitOutcome::StartupUnavailable(BootstrapFailureCode::CatalogUnavailable)
            })?;
            let now = instance
                .retention_time
                .governance_now_seconds()
                .map_err(|_| {
                    ExitOutcome::StartupUnavailable(BootstrapFailureCode::CatalogUnavailable)
                })?;
            let actor = DurableOperationAdministration::resume_upgrade_actor(
                &catalog,
                id,
                instance
                    .retention_time
                    .security_time_seconds()
                    .map_err(|_| {
                        ExitOutcome::StartupUnavailable(BootstrapFailureCode::CatalogUnavailable)
                    })?,
            )
            .map_err(|_| {
                ExitOutcome::StartupUnavailable(BootstrapFailureCode::CatalogUnavailable)
            })?;
            let operation = DurableOperationAdministration::inspect_authorized(&catalog, actor, id)
                .map_err(|_| {
                    ExitOutcome::StartupUnavailable(BootstrapFailureCode::CatalogUnavailable)
                })?
                .ok_or(ExitOutcome::StartupUnavailable(
                    BootstrapFailureCode::CatalogUnavailable,
                ))?;
            if operation.status() == positron_governance::DurableOperationStatus::Pending {
                DurableOperationAdministration::begin(&catalog, actor, id, now).map_err(|_| {
                    ExitOutcome::StartupUnavailable(BootstrapFailureCode::CatalogUnavailable)
                })?;
            }
            if operation.upgrade_stage() != Some(UpgradeStage::Draining) {
                DurableOperationAdministration::advance_upgrade(
                    &catalog,
                    actor,
                    id,
                    UpgradeStage::Draining,
                    now,
                )
                .map_err(|_| {
                    ExitOutcome::StartupUnavailable(BootstrapFailureCode::CatalogUnavailable)
                })?;
            }
        }
        Ok(DrainingUpgrade {
            process: self.begin_shutdown(),
            operation: id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use positron_governance::AdministrativeIdempotencyKey;
    use positron_kernel::release_manifest::ProductVersion;
    #[test]
    fn invalid_upgrade_authority_does_not_close_live_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let roots = crate::process_lifecycle::TestRoots::new("upgrade-auth")?;
        let listeners = crate::process_lifecycle::ObservingListeners::default();
        let tasks = crate::process_lifecycle::ObservingTasks::default();
        let process = ApplicationRuntime::start(
            ServeConfiguration::new(
                roots.bootstrap_paths()?,
                InitializationMode::InitializeIfEmpty,
            ),
            HostInputs::new(&listeners, &tasks),
        )?;
        let source = crate::upgrade::signed_fixture_release(
            ProductVersion {
                major: 0,
                minor: 0,
                patch: 0,
            },
            [0x73; 32],
            15,
        )?;
        let target = crate::upgrade::signed_fixture_release(
            ProductVersion {
                major: 0,
                minor: 0,
                patch: 1,
            },
            [0x74; 32],
            15,
        )?;
        let request = UpgradeRequest::new(
            (source, target),
            vec![],
            [0x75; 16],
            3600,
            1,
            AdministrativeIdempotencyKey::new([0x76; 16])?,
        )?;
        assert!(matches!(
            process.accept_upgrade("invalid", request),
            Err(UpgradeFailure::AuthenticationFailed)
        ));
        assert_eq!(process.health().phase(), ProcessPhase::Serving);
        assert_eq!(
            process.shutdown(ShutdownTrigger::FirstSignal),
            ExitOutcome::Graceful
        );
        Ok(())
    }
}
