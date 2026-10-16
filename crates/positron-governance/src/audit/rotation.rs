use crate::identity::IdentityFailure;

use super::ROOT_ROTATION_MAGIC;
pub(super) const ROOT_MIGRATION_MAGIC: &[u8] = b"catalog-root-migration-v1\0";

/// Closed stages durably published by one Catalog root rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogRootRotationStage {
    Started,
    Cutover,
    Verified,
    RetirementPrepared,
    RetirementRefused,
    Completed,
    Cancelled,
    Resumed,
    Restored,
}

impl CatalogRootRotationStage {
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Started => "catalog.root-rotation.started",
            Self::Cutover => "catalog.root-rotation.cutover",
            Self::Verified => "catalog.root-rotation.verified",
            Self::RetirementPrepared => "catalog.root-rotation.retirement-prepared",
            Self::RetirementRefused => "catalog.root-rotation.retirement-refused",
            Self::Completed => "catalog.root-rotation.completed",
            Self::Cancelled => "catalog.root-rotation.cancelled",
            Self::Resumed => "catalog.root-rotation.resumed",
            Self::Restored => "catalog.root-rotation.restored",
        }
    }
}

/// Typed, redacted meaning of one committed Catalog root-rotation position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogRootRotationAuditEntry {
    position: u64,
    stage: CatalogRootRotationStage,
    provider_key_reference: [u8; 16],
    key_epoch: u64,
    transaction_id: [u8; 16],
    requesting_principal: Option<positron_domain::identity::PrincipalId>,
    operation_id: Option<crate::OperationId>,
}

impl CatalogRootRotationAuditEntry {
    pub(super) fn decode_intent(
        position: u64,
        transaction_id: [u8; 16],
        intent: &[u8],
    ) -> Result<Self, IdentityFailure> {
        let migration = intent.starts_with(ROOT_MIGRATION_MAGIC);
        let remaining = intent
            .strip_prefix(if migration {
                ROOT_MIGRATION_MAGIC
            } else {
                ROOT_ROTATION_MAGIC
            })
            .ok_or(IdentityFailure)?;
        let stage_end = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(IdentityFailure)?;
        let stage = match remaining.get(..stage_end).ok_or(IdentityFailure)? {
            b"started" => CatalogRootRotationStage::Started,
            b"cutover" => CatalogRootRotationStage::Cutover,
            b"verified" => CatalogRootRotationStage::Verified,
            b"retirement-prepared" => CatalogRootRotationStage::RetirementPrepared,
            b"retirement-refused" => CatalogRootRotationStage::RetirementRefused,
            b"completed" => CatalogRootRotationStage::Completed,
            b"cancelled" => CatalogRootRotationStage::Cancelled,
            b"resumed" => CatalogRootRotationStage::Resumed,
            b"restored" => CatalogRootRotationStage::Restored,
            _ => return Err(IdentityFailure),
        };
        let body = remaining
            .get(stage_end.checked_add(1).ok_or(IdentityFailure)?..)
            .ok_or(IdentityFailure)?;
        let provider_key_reference: [u8; 16] = body
            .get(..16)
            .ok_or(IdentityFailure)?
            .try_into()
            .map_err(|_| IdentityFailure)?;
        let key_epoch = body
            .get(16..24)
            .ok_or(IdentityFailure)?
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| IdentityFailure)?;
        let administration_intent = body.get(24..).ok_or(IdentityFailure)?;
        if provider_key_reference.iter().all(|byte| *byte == 0)
            || key_epoch == 0
            || administration_intent.is_empty()
        {
            return Err(IdentityFailure);
        }
        let (requesting_principal, operation_id) = if migration {
            if administration_intent.len() != 32 {
                return Err(IdentityFailure);
            }
            let actor = administration_intent
                .get(..16)
                .ok_or(IdentityFailure)?
                .try_into()
                .map_err(|_| IdentityFailure)?;
            let operation = administration_intent
                .get(16..)
                .ok_or(IdentityFailure)?
                .try_into()
                .map_err(|_| IdentityFailure)?;
            (
                Some(
                    positron_domain::identity::PrincipalId::from_bytes(actor)
                        .map_err(|_| IdentityFailure)?,
                ),
                Some(crate::OperationId::from_bytes(operation).map_err(|_| IdentityFailure)?),
            )
        } else {
            (None, None)
        };
        Ok(Self {
            position,
            stage,
            provider_key_reference,
            key_epoch,
            transaction_id,
            requesting_principal,
            operation_id,
        })
    }

    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    #[must_use]
    pub const fn stage(&self) -> CatalogRootRotationStage {
        self.stage
    }

    #[must_use]
    pub const fn action(&self) -> &'static str {
        self.stage.action()
    }

    #[must_use]
    pub const fn provider_key_reference(&self) -> [u8; 16] {
        self.provider_key_reference
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 16] {
        self.transaction_id
    }

    #[must_use]
    pub const fn outcome(&self) -> &'static str {
        "committed"
    }
    pub const fn requesting_principal(&self) -> Option<positron_domain::identity::PrincipalId> {
        self.requesting_principal
    }
    pub const fn operation_id(&self) -> Option<crate::OperationId> {
        self.operation_id
    }
}

pub fn catalog_root_migration_audit_intent(
    stage: CatalogRootRotationStage,
    provider_key_reference: [u8; 16],
    epoch: u64,
    principal: positron_domain::identity::PrincipalId,
    operation: crate::OperationId,
) -> Result<positron_kernel::AuditIntent, IdentityFailure> {
    let legacy = root_rotation_bytes(stage, provider_key_reference, epoch, principal)?;
    let body = legacy
        .strip_prefix(ROOT_ROTATION_MAGIC)
        .ok_or(IdentityFailure)?;
    let mut bytes = Vec::with_capacity(ROOT_MIGRATION_MAGIC.len() + body.len() + 16);
    bytes.extend_from_slice(ROOT_MIGRATION_MAGIC);
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&operation.to_bytes());
    positron_kernel::AuditIntent::new(bytes).map_err(|_| IdentityFailure)
}

pub fn catalog_root_rotation_audit_intent(
    stage: CatalogRootRotationStage,
    provider_key_reference: [u8; 16],
    epoch: u64,
    administrator: positron_domain::identity::PrincipalId,
) -> Result<positron_kernel::AuditIntent, IdentityFailure> {
    positron_kernel::AuditIntent::new(root_rotation_bytes(
        stage,
        provider_key_reference,
        epoch,
        administrator,
    )?)
    .map_err(|_| IdentityFailure)
}

fn root_rotation_bytes(
    stage: CatalogRootRotationStage,
    provider_key_reference: [u8; 16],
    epoch: u64,
    administrator: positron_domain::identity::PrincipalId,
) -> Result<Vec<u8>, IdentityFailure> {
    if epoch == 0 || provider_key_reference == [0; 16] {
        return Err(IdentityFailure);
    }
    let stage = match stage {
        CatalogRootRotationStage::Started => b"started".as_slice(),
        CatalogRootRotationStage::Cutover => b"cutover".as_slice(),
        CatalogRootRotationStage::Verified => b"verified".as_slice(),
        CatalogRootRotationStage::RetirementPrepared => b"retirement-prepared".as_slice(),
        CatalogRootRotationStage::RetirementRefused => b"retirement-refused".as_slice(),
        CatalogRootRotationStage::Completed => b"completed".as_slice(),
        CatalogRootRotationStage::Cancelled => b"cancelled".as_slice(),
        CatalogRootRotationStage::Resumed => b"resumed".as_slice(),
        CatalogRootRotationStage::Restored => b"restored".as_slice(),
    };
    let mut bytes = Vec::with_capacity(ROOT_ROTATION_MAGIC.len() + stage.len() + 41);
    bytes.extend_from_slice(ROOT_ROTATION_MAGIC);
    bytes.extend_from_slice(stage);
    bytes.push(0);
    bytes.extend_from_slice(&provider_key_reference);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&administrator.to_bytes());
    Ok(bytes)
}
