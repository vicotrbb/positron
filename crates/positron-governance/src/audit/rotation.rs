use crate::identity::IdentityFailure;

use super::ROOT_ROTATION_MAGIC;

/// Closed stages durably published by one Catalog root rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogRootRotationStage {
    Started,
    Cutover,
    Verified,
    RetirementPrepared,
    RetirementRefused,
    Completed,
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
}

impl CatalogRootRotationAuditEntry {
    pub(super) fn decode_intent(
        position: u64,
        transaction_id: [u8; 16],
        intent: &[u8],
    ) -> Result<Self, IdentityFailure> {
        let remaining = intent
            .strip_prefix(ROOT_ROTATION_MAGIC)
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
        Ok(Self {
            position,
            stage,
            provider_key_reference,
            key_epoch,
            transaction_id,
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
}

pub fn catalog_root_rotation_audit_intent(
    stage: CatalogRootRotationStage,
    provider_key_reference: [u8; 16],
    epoch: u64,
    administrator: positron_domain::identity::PrincipalId,
) -> Result<positron_kernel::AuditIntent, IdentityFailure> {
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
    };
    let mut bytes = Vec::with_capacity(ROOT_ROTATION_MAGIC.len() + stage.len() + 41);
    bytes.extend_from_slice(ROOT_ROTATION_MAGIC);
    bytes.extend_from_slice(stage);
    bytes.push(0);
    bytes.extend_from_slice(&provider_key_reference);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&administrator.to_bytes());
    positron_kernel::AuditIntent::new(bytes).map_err(|_| IdentityFailure)
}
