//! Offline upgrade bridge to the existing Backup owner.
use super::ServiceHandle;
use crate::upgrade::UpgradeFailure;
use positron_governance::BackupSnapshotParameters;
impl ServiceHandle {
    pub(crate) fn accept_upgrade_snapshot(
        &self,
        actor: positron_governance::AuthorizedContext,
        parameters: BackupSnapshotParameters,
        key: positron_governance::AdministrativeIdempotencyKey,
        expected: u64,
    ) -> Result<positron_governance::DurableOperation, UpgradeFailure> {
        let resolved = self.upgrade_backup_parameters(
            parameters.repository().repository_id(),
            parameters.retention_seconds(),
        )?;
        if resolved != parameters {
            return Err(UpgradeFailure::InvalidRequest);
        }
        self.accept_backup(
            actor,
            parameters.repository(),
            parameters.retention_seconds(),
            expected,
            key,
        )
        .map_err(|_| UpgradeFailure::SnapshotUnavailable)
    }
    pub(crate) fn accept_upgrade_verification(
        &self,
        actor: positron_governance::AuthorizedContext,
        snapshot: positron_governance::DurableOperation,
        key: positron_governance::AdministrativeIdempotencyKey,
        expected: u64,
    ) -> Result<positron_governance::DurableOperation, UpgradeFailure> {
        if snapshot.kind() != positron_governance::DurableOperationKind::BackupSnapshot
            || snapshot.status() != positron_governance::DurableOperationStatus::Succeeded
            || snapshot.target_identity() != Some(self.instance.instance.to_bytes())
        {
            return Err(UpgradeFailure::InvalidRequest);
        }
        let parameters = snapshot
            .backup_parameters()
            .ok_or(UpgradeFailure::InvalidRequest)?;
        let receipt = snapshot
            .backup_receipt()
            .ok_or(UpgradeFailure::InvalidRequest)?;
        self.accept_backup_snapshot_action(
            true,
            actor,
            parameters.repository().repository_id(),
            (snapshot.operation_id().to_bytes(), receipt.manifest()),
            expected,
            key,
        )
        .map_err(|_| UpgradeFailure::VerificationFailed)
    }

    pub(crate) fn drive_upgrade_backup_operation(
        &self,
        id: positron_governance::OperationId,
        deadline: std::time::Instant,
    ) -> Result<positron_governance::DurableOperation, UpgradeFailure> {
        super::maintenance::drive_upgrade_backup(self, id, deadline)
    }

    pub(crate) fn upgrade_backup_parameters(
        &self,
        repository: [u8; 16],
        retention: u64,
    ) -> Result<BackupSnapshotParameters, UpgradeFailure> {
        let gate = self
            .catalog_operation()
            .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
        self.upgrade_backup_parameters_under_gate(repository, retention, &gate)
    }

    pub(crate) fn upgrade_backup_parameters_under_gate(
        &self,
        repository: [u8; 16],
        retention: u64,
        gate: &std::sync::MutexGuard<'_, ()>,
    ) -> Result<BackupSnapshotParameters, UpgradeFailure> {
        let (_, registration, parameters, _) =
            super::backup_administration::registered::registered_under_gate(self, repository, gate)
                .map_err(|_| UpgradeFailure::SnapshotUnavailable)?;
        BackupSnapshotParameters::new(
            parameters,
            retention,
            registration
                .binding_identity()
                .map_err(|_| UpgradeFailure::SnapshotUnavailable)?,
        )
        .map_err(|_| UpgradeFailure::InvalidRequest)
    }
}
#[cfg(test)]
pub(in crate::services) mod tests {
    pub(super) fn generation(
        instance: &crate::InitializedInstance,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        Ok(
            crate::services::tests::schema_maintenance::open_catalog(instance)?
                .pin()?
                .number(),
        )
    }
    fn query_result(
        services: &super::super::ServiceHandle,
        query: &str,
    ) -> Result<Vec<String>, crate::ServiceFailure> {
        services.query_log_bodies(
            query,
            "logs | range query_time 0 100 | limit 16",
            positron_query::QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)
                .expect("query budget"),
        )
    }
    #[inline(never)]
    pub(super) fn reopen_with_trusted_test_clock(
        fixture: &crate::services::tests::schema_maintenance::Fixture,
    ) -> Result<
        (
            std::sync::Arc<crate::InitializedInstance>,
            positron_kernel::ManualRetentionTime,
            u64,
        ),
        Box<dyn std::error::Error>,
    > {
        let reopened = fixture.reopen()?;
        let recovered_services = super::super::ServiceHandle::new(reopened.clone())?;
        let trusted = reopened.retention_time.governance_now_seconds()?;
        drop(recovered_services);
        let mut reopened =
            std::sync::Arc::try_unwrap(reopened).map_err(|_| "exclusive reopened instance")?;
        let nanos = i64::try_from(trusted)?
            .checked_mul(1_000_000_000)
            .ok_or("trusted clock range")?;
        let (clock, elapsed) =
            positron_kernel::RetentionTimeAuthority::establish_with_manual_elapsed(
                positron_domain::time::UnixNanoseconds::new(nanos),
            );
        reopened.install_retention_time_for_test(clock)?;
        let instance = std::sync::Arc::new(reopened);
        Ok((instance, elapsed, trusted))
    }
    #[inline(never)]
    fn drive_to_terminal(
        services: &super::super::ServiceHandle,
        id: positron_governance::OperationId,
    ) -> Result<positron_governance::DurableOperation, crate::upgrade::UpgradeFailure> {
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(60);
        loop {
            let operation = match services.drive_upgrade_backup_operation(id, deadline) {
                Ok(operation) => operation,
                Err(failure) => {
                    let trusted_now = services
                        .instance
                        .retention_time
                        .governance_now_seconds()
                        .ok();
                    let operation_context = (|| {
                        let _gate = services.catalog_operation().ok()?;
                        let catalog = services.open_maintenance_catalog().ok()?;
                        let operation =
                            positron_governance::DurableOperationAdministration::inspect(
                                &catalog, id,
                            )
                            .ok()??;
                        Some((
                            operation.updated_at_unix_seconds(),
                            operation.revision(),
                            operation.status(),
                        ))
                    })();
                    let task_context = positron_kernel::MaintenanceTaskId::new(id.to_bytes())
                        .ok()
                        .and_then(|task| {
                            services
                                .instance
                                .maintenance_coordinator()
                                .status(task)
                                .ok()
                        })
                        .map(|status| {
                            (
                                status.phase(),
                                status
                                    .checkpoint()
                                    .map(|checkpoint| checkpoint.opaque_progress().len()),
                            )
                        });
                    eprintln!(
                        "upgrade-backup-driver failure={failure:?} elapsed_millis={} trusted_now={trusted_now:?} operation_updated_revision_status={operation_context:?} task_phase_checkpoint_len={task_context:?}",
                        started.elapsed().as_millis()
                    );
                    return Err(failure);
                },
            };
            if operation.status().is_terminal() || std::time::Instant::now() >= deadline {
                return Ok(operation);
            }
        }
    }
    #[test]
    fn missing_registered_repository_is_refused_before_any_backup_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = crate::services::tests::schema_maintenance::Fixture::new()?;
        let (instance, _, _, _) = fixture.initialized_with_admin()?;
        let services = super::super::ServiceHandle::new(instance)?;
        assert!(matches!(
            services.upgrade_backup_parameters([8; 16], 3600),
            Err(crate::upgrade::UpgradeFailure::SnapshotUnavailable)
        ));
        Ok(())
    }
    #[test]
    fn exact_driver_rejects_unknown_operation_without_running_other_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = crate::services::tests::schema_maintenance::Fixture::new()?;
        let (instance, _, _, _) = fixture.initialized_with_admin()?;
        let services = super::super::ServiceHandle::new(instance)?;
        let id = positron_governance::OperationId::from_bytes([8; 16])?;
        assert!(matches!(
            services.drive_upgrade_backup_operation(id, std::time::Instant::now()),
            Err(crate::upgrade::UpgradeFailure::InvalidRequest)
        ));
        Ok(())
    }
    #[inline(never)]
    pub(in crate::services) fn initialize_registered_repository(
        instance: &std::sync::Arc<crate::InitializedInstance>,
        services: &super::super::ServiceHandle,
        administrator: &str,
        export: &std::path::Path,
    ) -> Result<positron_governance::DurableOperation, Box<dyn std::error::Error>> {
        use crate::services::repository_administration::{RepositoryAdmission, RepositoryLocation};
        use positron_governance::{
            AdministrativeIdempotencyKey, DurableOperationStatus, RepositoryAction,
        };
        let repository = export.join("repository");
        std::fs::create_dir(&repository)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&repository, std::fs::Permissions::from_mode(0o700))?;
        }
        let operation = services
            .accept_repository_operation(
                administrator,
                RepositoryAdmission {
                    action: RepositoryAction::Initialize,
                    locator: RepositoryLocation::Local(&repository),
                    repository: [44; 16],
                    expected_generation: generation(instance)?,
                    idempotency: AdministrativeIdempotencyKey::new([21; 16])?,
                },
            )
            .map_err(|failure| format!("repository admission: {failure:?}"))?;
        for _ in 0..30 {
            crate::services::maintenance::wake_runtime_maintenance(services, None)?;
            let catalog = crate::services::tests::schema_maintenance::open_catalog(instance)?;
            if positron_governance::DurableOperationAdministration::inspect(
                &catalog,
                operation.operation_id(),
            )?
            .is_some_and(|operation| operation.status().is_terminal())
            {
                break;
            }
        }
        let catalog = crate::services::tests::schema_maintenance::open_catalog(instance)?;
        let operation = positron_governance::DurableOperationAdministration::inspect(
            &catalog,
            operation.operation_id(),
        )?
        .ok_or("repository operation")?;
        assert_eq!(
            operation.status(),
            DurableOperationStatus::Succeeded,
            "{:?}",
            operation.terminal_error()
        );
        drop(catalog);
        let actor = services
            .authorize_system_administration(administrator)
            .map_err(|failure| format!("authorization: {failure:?}"))?;
        let repository_parameters = operation
            .repository_parameters()
            .ok_or("repository params")?;
        let backup_parameters = positron_governance::RepositoryOperationParameters::local(
            RepositoryAction::Verify,
            repository_parameters.locator()?,
            repository_parameters.repository_id(),
            repository_parameters.integrity_fingerprint(),
            repository_parameters.prefix_commitment(),
        )?;
        let first = services
            .accept_backup(
                actor,
                backup_parameters,
                3600,
                generation(instance)?,
                AdministrativeIdempotencyKey::new([22; 16])?,
            )
            .map_err(|failure| format!("initial backup: {failure:?}"))?;
        let paused = services
            .drive_upgrade_backup_operation(
                first.operation_id(),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .map_err(|failure| format!("initial one-second backup pause: {failure:?}"))?;
        assert!(!paused.status().is_terminal());
        let task = positron_kernel::MaintenanceTaskId::new(first.operation_id().to_bytes())
            .map_err(|failure| format!("first task: {failure:?}"))?;
        assert_eq!(
            instance
                .maintenance_coordinator()
                .status(task)
                .map_err(|failure| format!("first status: {failure:?}"))?
                .phase(),
            positron_kernel::MaintenanceTaskPhase::Queued
        );
        let first = services.drive_upgrade_backup_operation(
            first.operation_id(),
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        )?;
        assert_eq!(first.status(), DurableOperationStatus::Succeeded);
        Ok(operation)
    }
    #[test]
    fn registered_local_snapshot_and_independent_verification_use_the_existing_backup_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_governance::{AdministrativeIdempotencyKey, DurableOperationStatus};
        let _serial =
            crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
        let fixture = crate::services::tests::schema_maintenance::Fixture::new()?;
        let (instance, ingest, query, administrator) = fixture.initialized_with_admin()?;
        let export = fixture.recovery_export_directory()?;
        let identity = age::x25519::Identity::generate();
        let recipients =
            positron_kernel::RecoveryRecipients::parse(&[identity.to_public().to_string()])?;
        let bundle = export.join("recovery.age");
        instance.create_recovery_bundle(&bundle, &recipients)?;
        instance.verify_recovery_bundle(
            &bundle,
            positron_kernel::RecoveryUnlock::Identity(&identity),
        )?;
        let services = super::super::ServiceHandle::new(instance.clone())?;
        use prost::Message;
        services.ingest_otlp_logs(
            &ingest,
            crate::services::tests::schema_maintenance::request("upgrade-preserved")
                .encode_to_vec(),
        )?;
        assert_eq!(query_result(&services, &query)?, ["upgrade-preserved"]);

        let operation =
            initialize_registered_repository(&instance, &services, &administrator, &export)?;
        let actor = services
            .authorize_system_administration(&administrator)
            .map_err(|failure| format!("actor: {failure:?}"))?;
        let parameters = services.upgrade_backup_parameters([44; 16], 3600)?;
        let pending = services
            .accept_upgrade_snapshot(
                actor,
                parameters,
                AdministrativeIdempotencyKey::new([23; 16])?,
                generation(&instance)?,
            )
            .map_err(|failure| format!("snapshot acceptance: {failure:?}"))?;
        let pending = services
            .drive_upgrade_backup_operation(pending.operation_id(), std::time::Instant::now())
            .map_err(|failure| format!("deadline driver: {failure:?}"))?;
        assert!(!pending.status().is_terminal());
        let task = positron_kernel::MaintenanceTaskId::new(pending.operation_id().to_bytes())
            .map_err(|failure| format!("task identity: {failure:?}"))?;
        assert_eq!(
            instance
                .maintenance_coordinator()
                .status(task)
                .map_err(|failure| format!("task status: {failure:?}"))?
                .phase(),
            positron_kernel::MaintenanceTaskPhase::Queued
        );
        drop(services);
        drop(instance);
        let (instance, elapsed, trusted) = reopen_with_trusted_test_clock(&fixture)?;
        let services = super::super::ServiceHandle::new(instance.clone())?;
        let actor = services
            .authorize_system_administration(&administrator)
            .map_err(|failure| format!("reopened actor: {failure:?}"))?;

        let before_generation = generation(&instance)?;
        let before_task = instance
            .maintenance_coordinator()
            .status(task)
            .map_err(|failure| format!("cold task before deadline: {failure:?}"))?;
        let delayed = services.drive_upgrade_backup_operation(
            pending.operation_id(),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        assert!(
            matches!(
                delayed,
                Err(crate::upgrade::UpgradeFailure::CapacityUnavailable)
            ),
            "ineligible cold driver: {delayed:?}"
        );
        let catalog = crate::services::tests::schema_maintenance::open_catalog(&instance)?;
        assert_eq!(
            positron_governance::DurableOperationAdministration::inspect(
                &catalog,
                pending.operation_id()
            )?,
            Some(pending)
        );
        assert_eq!(
            instance
                .maintenance_coordinator()
                .status(task)
                .map_err(|failure| format!("cold task after deadline: {failure:?}"))?,
            before_task
        );
        assert_eq!(catalog.pin()?.number(), before_generation);
        drop(catalog);
        assert!(trusted < pending.updated_at_unix_seconds());
        elapsed.advance(
            pending
                .updated_at_unix_seconds()
                .checked_sub(trusted)
                .and_then(|seconds| seconds.checked_add(1))
                .and_then(|seconds| seconds.checked_mul(1_000_000_000))
                .ok_or("elapsed range")?,
        )?;
        let snapshot = services
            .drive_upgrade_backup_operation(
                pending.operation_id(),
                std::time::Instant::now() + std::time::Duration::from_secs(60),
            )
            .map_err(|failure| format!("cold snapshot driver: {failure:?}"))?;
        assert_eq!(snapshot.status(), DurableOperationStatus::Succeeded);
        let verify = services.accept_upgrade_verification(
            actor,
            snapshot,
            AdministrativeIdempotencyKey::new([24; 16])?,
            generation(&instance)?,
        )?;
        let verified = drive_to_terminal(&services, verify.operation_id())
            .map_err(|failure| format!("independent verification driver: {failure:?}"))?;
        assert_eq!(verified.status(), DurableOperationStatus::Succeeded);
        assert!(verified.backup_verification_report().is_some());
        assert_eq!(query_result(&services, &query)?, ["upgrade-preserved"]);
        assert!(matches!(
            services.drive_upgrade_backup_operation(
                operation.operation_id(),
                std::time::Instant::now()
            ),
            Err(crate::upgrade::UpgradeFailure::InvalidRequest)
        ));

        assert!(
            services
                .accept_upgrade_verification(
                    actor,
                    operation,
                    AdministrativeIdempotencyKey::new([25; 16])?,
                    generation(&instance)?
                )
                .is_err()
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "upgrade_backup_bounded_tests.rs"]
mod bounded_tests;
