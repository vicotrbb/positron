//! Current live-segment progress is separate from verification and retirement proof.
use super::{InitializedInstance, LocalKeyRotationFailure};
use positron_domain::identity::TenantId;
use positron_governance::{
    AuthorizedContext, Identity, TenantKeyRotationStage, tenant_key_rotation_audit_intent,
};
use positron_kernel::{ActiveSegmentLedger, RootRewrapSession};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantKeyMigrationProgress {
    migrated_segment: bool,
    remaining_segments: bool,
}
impl TenantKeyMigrationProgress {
    pub const fn migrated_segment(self) -> bool {
        self.migrated_segment
    }
    /// Current live Catalog references only; this is not retirement authorization.
    pub const fn remaining_segments(self) -> bool {
        self.remaining_segments
    }
}
impl InitializedInstance {
    pub fn advance_tenant_key_migration(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<TenantKeyMigrationProgress, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        self.inspect_tenant(actor, tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let catalog = self.rotation_catalog(&session)?;
        let basis = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let identity =
            Identity::open(&basis).map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let envelope = identity
            .tenant_key_envelope(tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        if self
            .key
            .pending_tenant_key_epoch(self.instance, tenant, envelope)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?
            .is_some()
        {
            return Err(LocalKeyRotationFailure::Busy);
        }
        let epoch = self
            .key
            .tenant_key_epoch(self.instance, tenant, envelope)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let Some(scope) = basis
            .next_unmigrated_ledger_scope(tenant, epoch)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?
        else {
            return Ok(TenantKeyMigrationProgress {
                migrated_segment: false,
                remaining_segments: false,
            });
        };
        let protection = session
            .tenant_segment_key(&self.key, self.instance, scope, envelope)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let audit = tenant_key_rotation_audit_intent(
            TenantKeyRotationStage::Migrating,
            tenant,
            epoch,
            actor.principal_id(),
        )
        .map_err(|_| LocalKeyRotationFailure::InvalidInput)?;
        let migrated_segment = ActiveSegmentLedger::migrate_next_envelope(
            &self._authority,
            &catalog,
            scope,
            protection,
            self.rotation_transaction()?,
            Some(audit),
        )
        .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let current = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        self.record_catalog_generation(current.number());
        let remaining_segments = current
            .next_unmigrated_ledger_scope(tenant, epoch)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?
            .is_some();
        Ok(TenantKeyMigrationProgress {
            migrated_segment,
            remaining_segments,
        })
    }
}
