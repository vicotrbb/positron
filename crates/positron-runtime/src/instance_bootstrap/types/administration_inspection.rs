use super::*;

impl InitializedInstance {
    /// Opens the kernel-owned sanitized crash-record boundary while this
    /// initialized instance still retains Primary Data Volume ownership.
    pub fn crash_records(&self) -> Result<positron_kernel::CrashRecordStore, BootstrapFailure> {
        positron_kernel::CrashRecordStore::from_authenticated_authority(
            &self._authority,
            &self.key,
            self.instance,
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
    }

    /// Verifies the current authenticated bootstrap, Catalog, and opaque key
    /// custody binding for Doctor. This inspection never publishes Catalog
    /// state, creates a key, or exports key material.
    pub fn doctor_runtime_facts(
        &self,
        actor: positron_governance::AuthorizedContext,
    ) -> Result<DoctorRuntimeFacts, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let view = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let identity = positron_governance::Identity::open(view.snapshot())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        identity
            .inspect(actor, &[])
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ApiKeyUnauthorized))?;
        let (_, governance) = view
            .snapshot()
            .governance_object()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        if governance.integrity_key_fingerprint() != self.integrity_key_fingerprint {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        let signer = self
            .key
            .export_manifest_signer(self.instance, governance.protected_integrity_key())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        if signer.identity().public_key() != governance.integrity_public_key() {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        let backup_repository =
            BackupRepositoryInspection::from_authenticated_catalog(view.snapshot())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        view.verify_audit_chain(governance.integrity_public_key(), None)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let catalog_manifest_objects = u32::try_from(view.snapshot().object_count())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let mut catalog_reachable_ledger_scopes = 0_u32;
        for tenant in
            positron_governance::TenantAdministration::registered_tenant_ids(view.snapshot())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
        {
            for signal in [
                positron_domain::routing::SignalKind::Logs,
                positron_domain::routing::SignalKind::Traces,
            ] {
                let scopes = view
                    .snapshot()
                    .reachable_ledger_scopes(tenant, signal)
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
                let count = u32::try_from(scopes.len())
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
                catalog_reachable_ledger_scopes =
                    catalog_reachable_ledger_scopes.checked_add(count).ok_or(
                        BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable),
                    )?;
            }
        }
        let catalog_quarantine_findings = u32::try_from(
            positron_kernel::integrity_quarantine_findings(view.snapshot())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
                .len(),
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let mut operations = Vec::new();
        for record in view.governance_audit_records() {
            let entry = positron_governance::GovernanceAuditEntry::decode(record)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
            let positron_governance::GovernanceAuditEntry::DurableOperation(operation) = entry
            else {
                continue;
            };
            if let Some((_, outcome)) = operations
                .iter_mut()
                .find(|(identity, _)| *identity == operation.operation_id())
            {
                *outcome = operation.outcome();
            } else {
                operations.try_reserve(1).map_err(|_| {
                    BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable)
                })?;
                operations.push((operation.operation_id(), operation.outcome()));
            }
        }
        let durable_operations = u32::try_from(operations.len())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let active_durable_operations = u32::try_from(
            operations
                .iter()
                .filter(|(_, outcome)| !outcome.is_terminal())
                .count(),
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let maintenance_statuses = self
            .maintenance
            .statuses()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let snapshot_leases = u32::try_from(
            maintenance_statuses
                .iter()
                .filter(|status| {
                    status.task().class()
                        == positron_kernel::MaintenanceTaskClass::SnapshotLeaseExpiry
                        && !matches!(
                            status.phase(),
                            positron_kernel::MaintenanceTaskPhase::Cancelled
                                | positron_kernel::MaintenanceTaskPhase::Succeeded
                                | positron_kernel::MaintenanceTaskPhase::Failed
                        )
                })
                .count(),
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let integrity_scrub_tasks = u32::try_from(
            maintenance_statuses
                .iter()
                .filter(|status| {
                    status.task().class() == positron_kernel::MaintenanceTaskClass::IntegrityScrub
                })
                .count(),
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let integrity_scrub_checkpoints = u32::try_from(
            maintenance_statuses
                .iter()
                .filter(|status| {
                    status.task().class() == positron_kernel::MaintenanceTaskClass::IntegrityScrub
                        && status.checkpoint().is_some()
                })
                .count(),
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        Ok(DoctorRuntimeFacts::verified(VerifiedDoctorFacts {
            catalog_generation: view.snapshot().number(),
            catalog_audit_frontier: view.snapshot().governance_audit_frontier(),
            catalog_manifest_objects,
            catalog_reachable_ledger_scopes,
            catalog_quarantine_findings,
            integrity_scrub_tasks,
            integrity_scrub_checkpoints,
            backup_repository,
            durable_operations,
            active_durable_operations,
            snapshot_leases,
        }))
    }

    /// Opens the existing Instance Integrity Key only as an opaque signer for
    /// an authenticated operator export. The wrapped seed never crosses this
    /// boundary.
    pub fn support_bundle_manifest_signer(
        &self,
        actor: positron_governance::AuthorizedContext,
    ) -> Result<positron_kernel::ExportManifestSigner, BootstrapFailure> {
        if actor.principal_id() != self.administrator {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::ApiKeyUnauthorized,
            ));
        }
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let view = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let snapshot = view.snapshot();
        let (_, governance) = snapshot
            .governance_object()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        if governance.integrity_key_fingerprint() != self.integrity_key_fingerprint {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        let signer = self
            .key
            .export_manifest_signer(self.instance, governance.protected_integrity_key())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        (signer.identity().public_key() == governance.integrity_public_key())
            .then_some(signer)
            .ok_or(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ))
    }

    /// Returns the bounded, decoded Governance Audit history visible to this
    /// authenticated principal. System administrators receive the complete
    /// retained history; tenant administrators receive only entries with an
    /// explicit matching tenant attribution.
    pub fn inspect_governance_audit_history(
        &self,
        actor: positron_governance::AuthorizedContext,
    ) -> Result<GovernanceAuditHistory, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let view = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let identity = positron_governance::Identity::open(view.snapshot())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let audit = view
            .governance_audit_records()
            .iter()
            .map(positron_governance::GovernanceAuditEntry::decode)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let inspection = identity
            .inspect_audit(actor, &audit)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ApiKeyUnauthorized))?;
        Ok(GovernanceAuditHistory {
            records: inspection.audit_records().cloned().collect(),
            retention_anchor_position: view
                .audit_retention_anchor()
                .map(positron_kernel::AuditRetentionAnchor::position),
        })
    }

    /// Publishes a signed checkpoint for the complete currently visible
    /// Governance Audit chain. Only the authenticated system administrator may
    /// request this system-governance maintenance action. When an equivalent
    /// worker-owned task is running before its signed artifact is durable, the
    /// authenticated request returns `GovernanceAuditCheckpointInProgress`
    /// with that task's stable identity; retrying the same request returns the
    /// exact artifact once it is durable.
    pub fn publish_governance_audit_checkpoint(
        &self,
        actor: positron_governance::AuthorizedContext,
    ) -> Result<positron_kernel::GovernanceAuditCheckpoint, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let _checkpoint_request = self
            .governance_audit_checkpoint_gate
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        // The coordinator serializes public requests from their read-only
        // attachment decision through execution. This prevents a concurrent
        // reader from racing the selected caller's Catalog writer. A worker
        // has released the coordinator before its handler, so a worker-owned
        // request below returns immediately rather than waiting on it.
        let coordinator = self.maintenance_coordinator();
        // A worker's live durability reservation intentionally prevents a
        // second Catalog Writer from attaching to its task. Inspect the
        // authenticated read view first so an equivalent public request can
        // return the worker's exact durable signed artifact without waiting
        // under the coordinator or competing for that reservation.
        let view = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let identity = positron_governance::Identity::open(view.snapshot())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        identity
            .inspect(actor, &[])
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ApiKeyUnauthorized))?;
        let (_, governance) = view
            .snapshot()
            .governance_object()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        if governance.integrity_key_fingerprint() != self.integrity_key_fingerprint {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        let signer = self
            .key
            .audit_checkpoint_signer(self.instance, governance.protected_integrity_key())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        if signer.public_key() != governance.integrity_public_key() {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        let frontier = view
            .governance_audit_records()
            .iter()
            .next_back()
            .cloned()
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let (task, binding) = Catalog::governance_audit_checkpoint_task(
            &frontier,
            governance.integrity_key_fingerprint(),
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let requested = task.identity();
        if let Some(checkpoint) = view
            .latest_audit_checkpoint()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
            && checkpoint.instance() == self.instance
            && checkpoint.position() == frontier.position()
            && checkpoint.record_hash() == frontier.record_hash()
        {
            checkpoint
                .verify(signer.public_key())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            return Ok(checkpoint);
        }
        drop(view);
        match coordinator.status(requested) {
            Ok(status) if status.phase() == MaintenanceTaskPhase::Running => {
                return Err(BootstrapFailure::governance_audit_checkpoint_in_progress(
                    requested,
                ));
            },
            Ok(_) | Err(MaintenanceFailure::UnknownTask) => {},
            Err(_) => {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::CatalogUnavailable,
                ));
            },
        }
        let now = self
            .retention_time
            .governance_now_seconds()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = match Catalog::open(&self._authority, self.instance, secret) {
            Ok(catalog) => catalog,
            Err(_) => {
                if coordinator
                    .status(requested)
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
                    .phase()
                    == MaintenanceTaskPhase::Running
                {
                    return Err(BootstrapFailure::governance_audit_checkpoint_in_progress(
                        requested,
                    ));
                }
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::CatalogUnavailable,
                ));
            },
        };
        coordinator
            .submit_governance_audit_checkpoint_and_persist(&catalog, task, binding, now)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let existing = catalog
            .latest_audit_checkpoint()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if let Some(checkpoint) = existing
            && checkpoint.instance() == self.instance
            && checkpoint.position() == frontier.position()
            && checkpoint.record_hash() == frontier.record_hash()
        {
            checkpoint
                .verify(signer.public_key())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            return Ok(checkpoint);
        }
        let execution = coordinator
            .start_task_with_reservation_and_persist(
                &catalog,
                &self._authority,
                now,
                false,
                requested,
            )
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let execution = match execution {
            Some(execution) => execution,
            None if coordinator
                .status(requested)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
                .phase()
                == MaintenanceTaskPhase::Running =>
            {
                return Err(BootstrapFailure::governance_audit_checkpoint_in_progress(
                    requested,
                ));
            },
            None => {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::CatalogUnavailable,
                ));
            },
        };
        self.complete_governance_audit_checkpoint_execution_with_coordinator(
            &catalog,
            &execution,
            coordinator,
        )
    }

    pub(crate) fn complete_governance_audit_checkpoint_execution(
        &self,
        catalog: &Catalog<'_>,
        execution: &positron_kernel::MaintenanceExecution<'_>,
    ) -> Result<positron_kernel::GovernanceAuditCheckpoint, BootstrapFailure> {
        let coordinator = self.maintenance_coordinator();
        self.complete_governance_audit_checkpoint_execution_with_coordinator(
            catalog,
            execution,
            coordinator,
        )
    }

    pub(in crate::instance_bootstrap) fn complete_governance_audit_checkpoint_execution_with_coordinator(
        &self,
        catalog: &Catalog<'_>,
        execution: &positron_kernel::MaintenanceExecution<'_>,
        coordinator: &positron_kernel::MaintenanceCoordinator,
    ) -> Result<positron_kernel::GovernanceAuditCheckpoint, BootstrapFailure> {
        let snapshot = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let (_, governance) = snapshot
            .governance_object()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        if governance.integrity_key_fingerprint() != self.integrity_key_fingerprint {
            return self.fail_governance_audit_checkpoint_execution(
                catalog,
                execution,
                coordinator,
                BootstrapFailureCode::IdentityMismatch,
            );
        }
        let binding = positron_kernel::GovernanceAuditCheckpointBinding::from_checkpoint(
            execution.task_checkpoint(),
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        if binding.integrity_key_fingerprint() != governance.integrity_key_fingerprint() {
            return self.fail_governance_audit_checkpoint_execution(
                catalog,
                execution,
                coordinator,
                BootstrapFailureCode::IdentityMismatch,
            );
        }
        let signer = self
            .key
            .audit_checkpoint_signer(self.instance, governance.protected_integrity_key())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        if signer.public_key() != governance.integrity_public_key() {
            return self.fail_governance_audit_checkpoint_execution(
                catalog,
                execution,
                coordinator,
                BootstrapFailureCode::IdentityMismatch,
            );
        }
        let checkpoint = catalog
            .publish_admitted_audit_checkpoint(
                execution,
                &signer,
                governance.integrity_key_fingerprint(),
            )
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        // The signed artifact is idempotent. Retry the exact terminal record
        // once while its reservation remains live. If storage still refuses
        // it, put the same binding back in the durable queue before releasing
        // that reservation; a same-process attach or restart can then resume.
        if execution
            .complete_and_persist(coordinator, catalog, true)
            .is_err()
            && execution
                .complete_and_persist(coordinator, catalog, true)
                .is_err()
        {
            if execution.requeue_and_persist(coordinator, catalog).is_err() {
                execution
                    .release_for_same_process_recovery(coordinator)
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            }
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::CatalogUnavailable,
            ));
        }
        Ok(checkpoint)
    }

    fn fail_governance_audit_checkpoint_execution(
        &self,
        catalog: &Catalog<'_>,
        execution: &positron_kernel::MaintenanceExecution<'_>,
        coordinator: &positron_kernel::MaintenanceCoordinator,
        failure: BootstrapFailureCode,
    ) -> Result<positron_kernel::GovernanceAuditCheckpoint, BootstrapFailure> {
        execution
            .fail_and_persist(
                coordinator,
                catalog,
                positron_kernel::MaintenanceTerminalFailure::IdentityMismatch,
            )
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        Err(BootstrapFailure::new(failure))
    }

    /// Verifies the complete visible Governance Audit chain against the
    /// bootstrap-pinned Instance Integrity Key and an optional external trusted
    /// checkpoint anchor.
    pub fn verify_governance_audit_history(
        &self,
        actor: positron_governance::AuthorizedContext,
        trusted_checkpoint: Option<&positron_kernel::GovernanceAuditCheckpoint>,
    ) -> Result<(), BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let view = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let identity = positron_governance::Identity::open(view.snapshot())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        identity
            .inspect(actor, &[])
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ApiKeyUnauthorized))?;
        let (_, governance) = view
            .snapshot()
            .governance_object()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        if governance.integrity_key_fingerprint() != self.integrity_key_fingerprint {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        if let Some(anchor) = view.audit_retention_anchor() {
            view.verify_retained_audit_suffix(view.governance_audit_records())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            if let Some(checkpoint) = trusted_checkpoint {
                checkpoint
                    .verify(governance.integrity_public_key())
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
                if checkpoint.instance() != self.instance {
                    return Err(BootstrapFailure::new(
                        BootstrapFailureCode::CatalogUnavailable,
                    ));
                }
                let checkpoint_hash = if checkpoint.position() == anchor.position() {
                    Some(anchor.record_hash())
                } else {
                    checkpoint
                        .position()
                        .checked_sub(anchor.position())
                        .and_then(|offset| offset.checked_sub(1))
                        .and_then(|offset| usize::try_from(offset).ok())
                        .and_then(|offset| {
                            view.governance_audit_records()
                                .get(offset)
                                .map(positron_kernel::GovernanceAuditRecord::record_hash)
                        })
                };
                if checkpoint_hash != Some(checkpoint.record_hash()) {
                    return Err(BootstrapFailure::new(
                        BootstrapFailureCode::CatalogUnavailable,
                    ));
                }
            }
            return Ok(());
        }
        let stored = view
            .latest_audit_checkpoint()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let checkpoint = trusted_checkpoint.or(stored.as_ref());
        view.verify_audit_chain(governance.integrity_public_key(), checkpoint)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
    }

    /// Borrows the initialized instance's ordinary resource-admission authority.
    #[must_use]
    pub const fn resource_governor(&self) -> positron_kernel::ResourceGovernor<'_> {
        self._authority.governor()
    }

    #[cfg(any(test, fuzzing))]
    pub fn inspect_governance_for_fixture(
        &self,
        context: positron_governance::AuthorizedContext,
    ) -> Result<
        positron_governance::GovernanceInspection<'_, '_>,
        positron_governance::AttributionFailure,
    > {
        self.identity.inspect(context, &self.audit)
    }

    #[must_use]
    pub const fn instance_id(&self) -> InstanceId {
        self.instance
    }

    #[must_use]
    pub const fn default_tenant_id(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub fn default_tenant_slug(&self) -> &TenantSlug {
        &self.tenant_slug
    }

    #[must_use]
    pub const fn system_administrator_id(&self) -> PrincipalId {
        self.administrator
    }

    #[must_use]
    pub const fn integrity_key_fingerprint(&self) -> [u8; 32] {
        self.integrity_key_fingerprint
    }

    #[must_use]
    pub fn catalog_generation(&self) -> u64 {
        self.catalog_generation
            .load(std::sync::atomic::Ordering::Acquire)
    }

    #[must_use]
    pub const fn governance_audit_frontier(&self) -> u64 {
        self.governance_audit_frontier
    }

    pub(super) fn current_catalog_snapshot(
        &self,
    ) -> Result<positron_kernel::CatalogSnapshot, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        Catalog::read_current_snapshot(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
    }

    pub(super) fn authorize_tenant_inspection(
        &self,
        actor: AuthorizedContext,
    ) -> Result<(), BootstrapFailure> {
        let snapshot = self.current_catalog_snapshot()?;
        let identity = positron_governance::Identity::open(&snapshot)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        identity
            .inspect(actor, &[])
            .map(|_| ())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ApiKeyUnauthorized))
    }

    #[must_use]
    pub const fn claim_available(&self) -> bool {
        self.claim_available
    }
}
