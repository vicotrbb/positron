use super::super::repository_administration::{RepositoryAdmission, RepositoryLocation};
use super::*;
use crate::operational::{BackupReadStage, OperationalEvent};
use positron_api::backup::{BackupRequest, BackupResponse, BackupSnapshotReceipt};
use positron_domain::identity::TenantId;
impl ServiceHandle {
    pub(crate) fn manage_backup(
        &self,
        bearer: &str,
        bytes: &[u8],
    ) -> Result<BackupResponse, MaintenanceServiceFailure> {
        let mut stage = BackupReadStage::AdministratorIdentity;
        let result = self.manage_backup_observed(bearer, bytes, &mut stage);
        if let Err(failure @ MaintenanceServiceFailure::AdministrationUnavailable) = result {
            // The inner operation has returned and released all Catalog/gate owners.
            self.record_backup_read_failure(stage, failure);
        }
        result
    }

    fn manage_backup_observed(
        &self,
        bearer: &str,
        bytes: &[u8],
        stage: &mut BackupReadStage,
    ) -> Result<BackupResponse, MaintenanceServiceFailure> {
        let actor = {
            let _gate = self
                .catalog_operation()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            self.authorize_system_administration(bearer)?
        };
        let request =
            BackupRequest::decode(bytes).map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        *stage = BackupReadStage::OtherAction;
        let operation = match request.action.as_str() {
            "create" => {
                let fingerprint = {
                    let _gate = self
                        .catalog_operation()
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                    self.open_maintenance_catalog()?
                        .pin()
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                        .governance_object()
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                        .1
                        .integrity_key_fingerprint()
                };
                let aws = request
                    .aws_s3
                    .as_ref()
                    .map(|target| {
                        positron_backup::AwsS3Target::new(
                            &target.bucket,
                            &target.region,
                            &target.endpoint,
                            &target.expected_owner,
                            &target.prefix,
                        )
                    })
                    .transpose()
                    .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
                let google = request
                    .google_cloud_storage
                    .as_ref()
                    .map(|target| {
                        positron_backup::GoogleCloudStorageTarget::new(
                            &target.bucket,
                            &target.project_number,
                            &target.location,
                            &target.prefix,
                        )
                    })
                    .transpose()
                    .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
                let azure = request
                    .azure_blob
                    .as_ref()
                    .map(|target| {
                        positron_backup::AzureBlobTarget::new(
                            &target.account,
                            &target.container,
                            &target.prefix,
                        )
                    })
                    .transpose()
                    .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
                let locator = match (&aws, &google, &azure) {
                    (Some(target), None, None) => RepositoryLocation::AwsS3(target),
                    (None, Some(target), None) => RepositoryLocation::GoogleCloudStorage(target),
                    (None, None, Some(target)) => RepositoryLocation::AzureBlob(target),
                    (None, None, None) => RepositoryLocation::Local(std::path::Path::new(
                        request
                            .locator
                            .as_deref()
                            .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                    )),
                    _ => return Err(MaintenanceServiceFailure::InvalidRequest),
                };
                let admission = RepositoryAdmission {
                    action: RepositoryAction::Verify,
                    locator,
                    repository: TenantId::parse_canonical(
                        request
                            .repository_id
                            .as_deref()
                            .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                    )
                    .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?
                    .to_bytes(),
                    expected_generation: request
                        .expected_catalog_generation
                        .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                    idempotency: idempotency(request.idempotency_key.as_deref())?,
                };
                let parameters = super::super::repository_administration::parameters_for_location(
                    admission,
                    self.instance.instance.to_bytes(),
                    fingerprint,
                )?;
                self.accept_backup(
                    actor,
                    parameters,
                    request
                        .retention_seconds
                        .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                    admission.expected_generation,
                    admission.idempotency,
                )?
            },
            "expire" | "verify" => self.accept_backup_snapshot_action(
                request.action == "verify",
                actor,
                TenantId::parse_canonical(
                    request
                        .repository_id
                        .as_deref()
                        .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                )
                .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?
                .to_bytes(),
                (
                    super::super::maintenance_verification::decode_fixed_hex(
                        request
                            .snapshot_id
                            .as_deref()
                            .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                    )
                    .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                    super::super::maintenance_verification::decode_fixed_hex(
                        request
                            .expected_manifest_checksum
                            .as_deref()
                            .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                    )
                    .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                ),
                request
                    .expected_catalog_generation
                    .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                idempotency(request.idempotency_key.as_deref())?,
            )?,
            "status" | "lookup" | "cancel" => {
                *stage = BackupReadStage::OperationCatalogOpen;
                let _gate = self
                    .catalog_operation()
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                let catalog = self.open_maintenance_catalog()?;
                *stage = BackupReadStage::OperationInspect;
                let operation = if request.action == "lookup" {
                    DurableOperationAdministration::inspect_by_idempotency(
                        &catalog,
                        idempotency(request.idempotency_key.as_deref())?,
                    )
                    .map_err(super::super::provider_migration::operation_failure)?
                } else {
                    DurableOperationAdministration::inspect_authorized(
                        &catalog,
                        actor,
                        operation_id(
                            request
                                .operation_id
                                .as_deref()
                                .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                        )?,
                    )
                    .map_err(super::super::provider_migration::operation_failure)?
                }
                .ok_or(MaintenanceServiceFailure::SourceUnavailable)?;
                require_operation(operation, self.instance.instance.to_bytes())
                    .map_err(|_| MaintenanceServiceFailure::SourceUnavailable)?;
                let operation = DurableOperationAdministration::inspect_authorized(
                    &catalog,
                    actor,
                    operation.operation_id(),
                )
                .map_err(super::super::provider_migration::operation_failure)?
                .ok_or(MaintenanceServiceFailure::SourceUnavailable)?;
                if request.action == "cancel" {
                    *stage = BackupReadStage::OtherAction;
                    if operation.kind() == DurableOperationKind::BackupVerification {
                        DurableOperationAdministration::cancel_backup_verification(
                            &catalog,
                            actor,
                            operation.operation_id(),
                            idempotency(request.idempotency_key.as_deref())?,
                            request
                                .expected_operation_revision
                                .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                            self.maintenance_status_now()?,
                        )
                        .map_err(super::super::provider_migration::operation_failure)?
                    } else {
                        DurableOperationAdministration::cancel_backup(
                            &catalog,
                            actor,
                            operation.operation_id(),
                            idempotency(request.idempotency_key.as_deref())?,
                            request
                                .expected_operation_revision
                                .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                            self.maintenance_status_now()?,
                        )
                        .map_err(super::super::provider_migration::operation_failure)?
                    }
                } else {
                    operation
                }
            },
            _ => return Err(MaintenanceServiceFailure::InvalidRequest),
        };
        self.notify_maintenance_worker();
        response(self, operation, self.instance.instance.to_bytes(), stage)
    }
}
fn response(
    services: &ServiceHandle,
    operation: DurableOperation,
    instance: [u8; 16],
    stage: &mut BackupReadStage,
) -> Result<BackupResponse, MaintenanceServiceFailure> {
    *stage = BackupReadStage::Response;
    let parameters = operation
        .backup_binding()
        .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?
        .repository();
    let hex = super::super::maintenance_api::hex;
    let repository = repository_response(parameters, instance)?;
    let verification = operation.kind() == DurableOperationKind::BackupVerification;
    let report = operation
        .backup_verification_report()
        .map(|checksum| {
            *stage = BackupReadStage::VerificationReport;
            let _gate = services
                .catalog_operation()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let catalog = services.open_maintenance_catalog()?;
            let basis = catalog
                .pin()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let identity = basis
                .object_identities()
                .find(|identity| identity.to_bytes() == checksum)
                .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?;
            let bytes = basis
                .object(identity)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?;
            Ok::<_, MaintenanceServiceFailure>(
                bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
        })
        .transpose()?;
    let retention = operation.kind() == DurableOperationKind::BackupRetention;
    let cleanup_pending = if verification {
        false
    } else if retention {
        operation.phase() == positron_governance::DurableOperationPhase::BackupRetentionCleanup
            || operation.phase() == positron_governance::DurableOperationPhase::BackupCancellation
    } else if operation.status() == positron_governance::DurableOperationStatus::Cancelled {
        false
    } else if operation.phase() == positron_governance::DurableOperationPhase::BackupCancellation {
        true
    } else if operation.status() == positron_governance::DurableOperationStatus::Failed {
        *stage = BackupReadStage::TaskStatus;
        let task = positron_kernel::MaintenanceTaskId::new(operation.operation_id().to_bytes())
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let status = services
            .instance
            .maintenance_coordinator()
            .status(task)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        matches!(
            status.phase(),
            positron_kernel::MaintenanceTaskPhase::Queued
                | positron_kernel::MaintenanceTaskPhase::Running
                | positron_kernel::MaintenanceTaskPhase::Deferred
        )
    } else {
        *stage = BackupReadStage::CaptureExists;
        positron_kernel::BackupCapture::exists(
            &services.instance._authority,
            operation.operation_id().to_bytes(),
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
    };
    *stage = BackupReadStage::Response;
    Ok(BackupResponse {
        verification_report: report,
        verification_report_checksum: operation.backup_verification_report().map(hex),
        terminal_error_code: match operation.terminal_error() {
            None => None,
            Some(positron_governance::DurableOperationTerminalError::HandlerRejected) => {
                Some("handler_rejected".into())
            },
            Some(positron_governance::DurableOperationTerminalError::LegacyUnknown) => {
                Some("legacy_unknown".into())
            },
            Some(positron_governance::DurableOperationTerminalError::BackupRetentionNotDue) => {
                Some("backup_retention_not_due".into())
            },
            Some(positron_governance::DurableOperationTerminalError::QueryFailure(_)) => {
                return Err(MaintenanceServiceFailure::AdministrationUnavailable);
            },
        },
        operation_revision: operation.revision(),
        kind: if verification {
            "verification"
        } else if retention {
            "retention"
        } else {
            "snapshot"
        }
        .into(),
        cleanup_pending,
        retention_receipt: if retention {
            operation.backup_cleanup_receipt().map(|receipt| {
                positron_api::backup::BackupRetentionReceipt {
                    snapshot_id: super::super::maintenance_api::hex(receipt.snapshot_id()),
                    manifest_checksum: hex(receipt.manifest_checksum()),
                    registry_generation_checksum: hex(receipt.registry_generation()),
                    deleted_objects: receipt.deleted_objects(),
                    already_absent_objects: receipt.already_absent_objects(),
                    retained_shared_objects: receipt.retained_shared_objects(),
                }
            })
        } else {
            None
        },
        operation: super::super::provider_migration::operation_response(operation),
        repository: Some(repository),
        restored_publication: operation.restored_backup_publication().map(|evidence| {
            positron_api::backup::BackupRestoredPublication {
                manifest_checksum: hex(evidence.manifest()),
                current_registry_generation_checksum: hex(evidence.current_registry_generation()),
                source_catalog_identity: hex(evidence.source_catalog_identity()),
                source_catalog_generation: evidence.source_catalog_generation(),
                retain_until_unix_seconds: evidence.retain_until(),
                restore_origin_transaction: super::super::maintenance_api::hex(
                    evidence.origin_transaction(),
                ),
                restore_intent_digest: hex(evidence.restore_intent()),
                capture_operation_id: super::super::maintenance_api::hex(
                    evidence.capture_operation(),
                ),
                capture_request_digest: hex(evidence.capture_request()),
                restore_idempotency_key: super::super::maintenance_api::hex(
                    evidence.restore_idempotency_key(),
                ),
            }
        }),
        receipt: operation
            .backup_receipt()
            .map(|receipt| BackupSnapshotReceipt {
                manifest_checksum: hex(receipt.manifest()),
                registry_generation_checksum: hex(receipt.registry_generation()),
                catalog_generation: receipt.catalog_generation(),
                catalog_identity: hex(receipt.catalog_identity()),
                uploaded_bytes: receipt.uploaded_bytes(),
                reused_bytes: receipt.reused_bytes(),
                retain_until_unix_seconds: receipt.retain_until(),
            }),
    })
}
fn operation_id(text: &str) -> Result<OperationId, MaintenanceServiceFailure> {
    OperationId::from_bytes(
        super::super::maintenance_verification::decode_fixed_hex(text)
            .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
    )
    .map_err(super::super::provider_migration::operation_failure)
}
fn idempotency(
    text: Option<&str>,
) -> Result<AdministrativeIdempotencyKey, MaintenanceServiceFailure> {
    AdministrativeIdempotencyKey::new(
        TenantId::parse_canonical(text.ok_or(MaintenanceServiceFailure::InvalidRequest)?)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?
            .to_bytes(),
    )
    .map_err(|_| MaintenanceServiceFailure::InvalidRequest)
}

pub(super) fn repository_response(
    parameters: RepositoryOperationParameters,
    instance: [u8; 16],
) -> Result<positron_api::repository::RepositoryIdentity, MaintenanceServiceFailure> {
    let hex = super::super::maintenance_api::hex;
    Ok(positron_api::repository::RepositoryIdentity {
        repository_id: TenantId::from_bytes(parameters.repository_id())
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
            .to_string(),
        instance_id: TenantId::from_bytes(instance)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
            .to_string(),
        provider_kind: match parameters.provider_kind() {
            RepositoryProviderKind::LocalFilesystem => "local_filesystem",
            RepositoryProviderKind::AwsS3 => "aws_s3",
            RepositoryProviderKind::GoogleCloudStorage => "google_cloud_storage",
            RepositoryProviderKind::AzureBlob => "azure_blob",
        }
        .into(),
        format_epoch: 1,
        integrity_fingerprint: hex(parameters.integrity_fingerprint()),
        prefix_commitment: hex(parameters.prefix_commitment()),
    })
}

impl ServiceHandle {
    fn record_backup_read_failure(
        &self,
        stage: BackupReadStage,
        failure: MaintenanceServiceFailure,
    ) {
        use std::sync::atomic::{AtomicU8, Ordering};
        static REMAINING: AtomicU8 = AtomicU8::new(32);
        if REMAINING
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_err()
        {
            return;
        }
        let health = match self.integrity_health.lock() {
            Ok(owner) => owner.clone(),
            Err(_) => None,
        };
        if let Some(health) = health {
            health
                .operational_telemetry()
                .record(OperationalEvent::BackupReadFailure { stage, failure });
        }
    }
}
