use super::*;
pub(super) const TENANT_ROTATION_MAGIC: &[u8; 8] = b"POSTKR01";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantKeyRotationStage {
    Prepared,
    Progress,
    Cutover,
    Verified,
    Completed,
    RetirementRefused,
    Migrating,
}
impl TenantKeyRotationStage {
    fn code(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::Progress => 2,
            Self::Cutover => 3,
            Self::Verified => 4,
            Self::Completed => 5,
            Self::RetirementRefused => 6,
            Self::Migrating => 7,
        }
    }
    pub const fn action(self) -> &'static str {
        match self {
            Self::Prepared => "tenant.key-rotation.prepared",
            Self::Progress => "tenant.key-rotation.progress",
            Self::Cutover => "tenant.key-rotation.cutover",
            Self::Verified => "tenant.key-rotation.verified",
            Self::Completed => "tenant.key-rotation.completed",
            Self::RetirementRefused => "tenant.key-rotation.retirement-refused",
            Self::Migrating => "tenant.key-rotation.migration-progress",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantKeyRotationAuditEntry {
    position: u64,
    stage: TenantKeyRotationStage,
    tenant: TenantId,
    epoch: u64,
    actor: PrincipalId,
    transaction: [u8; 16],
}
impl TenantKeyRotationAuditEntry {
    pub(super) fn decode_intent(
        position: u64,
        transaction: [u8; 16],
        bytes: &[u8],
    ) -> Result<Self, IdentityFailure> {
        if bytes.len() != 49 || bytes.get(..8) != Some(TENANT_ROTATION_MAGIC.as_slice()) {
            return Err(IdentityFailure);
        }
        let stage = match bytes.get(8) {
            Some(1) => TenantKeyRotationStage::Prepared,
            Some(2) => TenantKeyRotationStage::Progress,
            Some(3) => TenantKeyRotationStage::Cutover,
            Some(4) => TenantKeyRotationStage::Verified,
            Some(5) => TenantKeyRotationStage::Completed,
            Some(6) => TenantKeyRotationStage::RetirementRefused,
            Some(7) => TenantKeyRotationStage::Migrating,
            _ => return Err(IdentityFailure),
        };
        let tenant = TenantId::from_bytes(
            bytes
                .get(9..25)
                .ok_or(IdentityFailure)?
                .try_into()
                .map_err(|_| IdentityFailure)?,
        )
        .map_err(|_| IdentityFailure)?;
        let epoch = u64::from_be_bytes(
            bytes
                .get(25..33)
                .ok_or(IdentityFailure)?
                .try_into()
                .map_err(|_| IdentityFailure)?,
        );
        let actor = PrincipalId::from_bytes(
            bytes
                .get(33..49)
                .ok_or(IdentityFailure)?
                .try_into()
                .map_err(|_| IdentityFailure)?,
        )
        .map_err(|_| IdentityFailure)?;
        if epoch == 0 {
            return Err(IdentityFailure);
        }
        Ok(Self {
            position,
            stage,
            tenant,
            epoch,
            actor,
            transaction,
        })
    }
    pub const fn position(&self) -> u64 {
        self.position
    }
    pub const fn action(&self) -> &'static str {
        self.stage.action()
    }
    pub const fn outcome(&self) -> &'static str {
        "committed"
    }
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    pub const fn actor(&self) -> PrincipalId {
        self.actor
    }
    pub const fn stage(&self) -> TenantKeyRotationStage {
        self.stage
    }
    pub const fn transaction_id(&self) -> [u8; 16] {
        self.transaction
    }
}
pub fn tenant_key_rotation_audit_intent(
    stage: TenantKeyRotationStage,
    tenant: TenantId,
    epoch: u64,
    actor: PrincipalId,
) -> Result<AuditIntent, IdentityFailure> {
    if epoch == 0 {
        return Err(IdentityFailure);
    }
    let mut bytes = Vec::with_capacity(49);
    bytes.extend_from_slice(TENANT_ROTATION_MAGIC);
    bytes.push(stage.code());
    bytes.extend_from_slice(&tenant.to_bytes());
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&actor.to_bytes());
    AuditIntent::new(bytes).map_err(|_| IdentityFailure)
}
