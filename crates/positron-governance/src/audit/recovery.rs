//! Secret-free immutable key-recovery workflow audit.
use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryBundleAction {
    Created,
    Verified,
    ReplacementVerified,
    RetirementPrepared,
    Retired,
    Imported,
    ImportPrepared,
    VerificationRejected,
}
impl RecoveryBundleAction {
    fn tag(self) -> u8 {
        match self {
            Self::Created => 1,
            Self::Verified => 2,
            Self::ReplacementVerified => 3,
            Self::RetirementPrepared => 4,
            Self::Retired => 5,
            Self::Imported => 6,
            Self::VerificationRejected => 7,
            Self::ImportPrepared => 8,
        }
    }
    fn from_tag(value: u8) -> Result<Self, IdentityFailure> {
        match value {
            1 => Ok(Self::Created),
            2 => Ok(Self::Verified),
            3 => Ok(Self::ReplacementVerified),
            4 => Ok(Self::RetirementPrepared),
            5 => Ok(Self::Retired),
            6 => Ok(Self::Imported),
            7 => Ok(Self::VerificationRejected),
            8 => Ok(Self::ImportPrepared),
            _ => Err(IdentityFailure),
        }
    }
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Created => "keys.recovery.create",
            Self::Verified => "keys.recovery.verify",
            Self::ReplacementVerified => "keys.recovery.rotation.verify",
            Self::RetirementPrepared => "keys.recovery.retirement.prepare",
            Self::Retired => "keys.recovery.retire",
            Self::Imported => "keys.recovery.import",
            Self::ImportPrepared => "keys.recovery.import.prepare",
            Self::VerificationRejected => "keys.recovery.verify",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryBundleAuditEntry {
    position: u64,
    actor: PrincipalId,
    action: RecoveryBundleAction,
    instance: [u8; 16],
    root_fingerprint: [u8; 32],
    bundle_digest: [u8; 32],
    time: u64,
}
impl RecoveryBundleAuditEntry {
    pub(super) fn decode(position: u64, bytes: &[u8]) -> Result<Self, IdentityFailure> {
        if bytes.len() != 113 || bytes.get(..8) != Some(b"POSRECA1") {
            return Err(IdentityFailure);
        }
        let take = |range: std::ops::Range<usize>| bytes.get(range).ok_or(IdentityFailure);
        let action = RecoveryBundleAction::from_tag(*bytes.get(8).ok_or(IdentityFailure)?)?;
        let actor = PrincipalId::from_bytes(take(9..25)?.try_into().map_err(|_| IdentityFailure)?)
            .map_err(|_| IdentityFailure)?;
        let instance = take(25..41)?.try_into().map_err(|_| IdentityFailure)?;
        let root_fingerprint = take(41..73)?.try_into().map_err(|_| IdentityFailure)?;
        let bundle_digest = take(73..105)?.try_into().map_err(|_| IdentityFailure)?;
        let time = u64::from_be_bytes(take(105..113)?.try_into().map_err(|_| IdentityFailure)?);
        if instance == [0; 16] || root_fingerprint == [0; 32] || time == 0 {
            return Err(IdentityFailure);
        }
        Ok(Self {
            position,
            actor,
            action,
            instance,
            root_fingerprint,
            bundle_digest,
            time,
        })
    }
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }
    #[must_use]
    pub const fn actor(&self) -> PrincipalId {
        self.actor
    }
    #[must_use]
    pub const fn operation(&self) -> RecoveryBundleAction {
        self.action
    }
    #[must_use]
    pub const fn bundle_digest(&self) -> [u8; 32] {
        self.bundle_digest
    }
}
pub fn recovery_bundle_audit_intent(
    actor: PrincipalId,
    action: RecoveryBundleAction,
    instance: [u8; 16],
    root_fingerprint: [u8; 32],
    bundle_digest: [u8; 32],
    time: u64,
) -> Result<positron_kernel::AuditIntent, IdentityFailure> {
    let mut bytes = Vec::with_capacity(113);
    bytes.extend_from_slice(b"POSRECA1");
    bytes.push(action.tag());
    bytes.extend_from_slice(&actor.to_bytes());
    bytes.extend_from_slice(&instance);
    bytes.extend_from_slice(&root_fingerprint);
    bytes.extend_from_slice(&bundle_digest);
    bytes.extend_from_slice(&time.to_be_bytes());
    RecoveryBundleAuditEntry::decode(1, &bytes)?;
    positron_kernel::AuditIntent::new(bytes).map_err(|_| IdentityFailure)
}
