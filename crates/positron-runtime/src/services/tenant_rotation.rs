use super::{ServiceFailure, ServiceHandle};
use crate::{LocalKeyRotationFailure, TenantKeyRotationStatus};
use positron_domain::identity::TenantId;
impl ServiceHandle {
    pub fn retire_tenant_key_predecessors(
        &self,
        bearer: &str,
        tenant: TenantId,
    ) -> Result<(), ServiceFailure> {
        let _gate = self.catalog_operation()?;
        let actor = self.rotation_actor(bearer)?;
        self.instance
            .retire_tenant_key_predecessors(actor, tenant)
            .map_err(rotation_failure)
    }
    fn rotation_actor(
        &self,
        bearer: &str,
    ) -> Result<positron_governance::AuthorizedContext, ServiceFailure> {
        let _admission = positron_kernel::RootRewrapSession::admit(&self.instance._authority)
            .map_err(|_| ServiceFailure::CapacityUnavailable)?;
        self.authorize_system_administration(bearer)
            .map_err(|_| ServiceFailure::Unauthorized)
    }
    pub fn advance_tenant_key_verification(
        &self,
        bearer: &str,
        tenant: TenantId,
    ) -> Result<crate::TenantKeyVerificationProgress, ServiceFailure> {
        let _gate = self.catalog_operation()?;
        let actor = self.rotation_actor(bearer)?;
        self.instance
            .inspect_tenant(actor, tenant)
            .map_err(|_| ServiceFailure::Unauthorized)?;
        self.publish_rotation_schema_checkpoint()?;
        self.instance
            .advance_tenant_key_verification(actor, tenant)
            .map_err(rotation_failure)
    }
    pub fn restart_tenant_key_verification(
        &self,
        bearer: &str,
        tenant: TenantId,
    ) -> Result<(), ServiceFailure> {
        let _gate = self.catalog_operation()?;
        let actor = self.rotation_actor(bearer)?;
        self.instance
            .inspect_tenant(actor, tenant)
            .map_err(|_| ServiceFailure::Unauthorized)?;
        self.publish_rotation_schema_checkpoint()?;
        self.instance
            .restart_tenant_key_verification(actor, tenant)
            .map_err(rotation_failure)
    }
    fn publish_rotation_schema_checkpoint(&self) -> Result<(), ServiceFailure> {
        if let Some(session) = self.schema_session_with_checkpoint_changes()? {
            let capacity = super::schema_maintenance::reserve_shutdown_capacity(&self.instance)?;
            let checkpoint = session.checkpoint().map_err(|_| ServiceFailure::Internal)?;
            super::schema_maintenance::publish_with_capacity(
                &self.instance,
                checkpoint,
                capacity,
                None,
            )?;
        }
        Ok(())
    }
    pub fn advance_tenant_key_migration(
        &self,
        bearer: &str,
        tenant: TenantId,
    ) -> Result<crate::TenantKeyMigrationProgress, ServiceFailure> {
        let _gate = self.catalog_operation()?;
        let actor = self.rotation_actor(bearer)?;
        self.instance
            .advance_tenant_key_migration(actor, tenant)
            .map_err(rotation_failure)
    }
    pub fn tenant_key_rotation_status(
        &self,
        bearer: &str,
        tenant: TenantId,
    ) -> Result<TenantKeyRotationStatus, ServiceFailure> {
        let _gate = self.catalog_operation()?;
        let actor = self.rotation_actor(bearer)?;
        self.instance
            .tenant_key_rotation_status(actor, tenant)
            .map_err(rotation_failure)
    }
    pub fn begin_tenant_key_rotation(
        &self,
        bearer: &str,
        tenant: TenantId,
    ) -> Result<TenantKeyRotationStatus, ServiceFailure> {
        let _gate = self.catalog_operation()?;
        let actor = self.rotation_actor(bearer)?;
        self.instance
            .begin_tenant_key_rotation(actor, tenant)
            .map_err(rotation_failure)
    }
    pub fn advance_tenant_key_rotation(
        &self,
        bearer: &str,
        tenant: TenantId,
    ) -> Result<TenantKeyRotationStatus, ServiceFailure> {
        let _gate = self.catalog_operation()?;
        let actor = self.rotation_actor(bearer)?;
        self.instance
            .advance_tenant_key_rotation(actor, tenant)
            .map_err(rotation_failure)
    }
}

pub(super) fn rotation_failure(failure: LocalKeyRotationFailure) -> ServiceFailure {
    match failure {
        LocalKeyRotationFailure::Custody => ServiceFailure::KeyUnavailable,
        LocalKeyRotationFailure::Authentication => ServiceFailure::KeyEnvelopeMismatch,
        LocalKeyRotationFailure::LimitExceeded => ServiceFailure::CapacityUnavailable,
        LocalKeyRotationFailure::Storage => ServiceFailure::CatalogUnavailable,
        LocalKeyRotationFailure::Busy => ServiceFailure::CatalogBusy,
        LocalKeyRotationFailure::InvalidInput => ServiceFailure::InvalidRequest,
    }
}
