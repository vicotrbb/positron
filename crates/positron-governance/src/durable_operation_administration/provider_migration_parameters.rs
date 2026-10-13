//! Bounded non-secret parameters owned atomically by the accepted operation.
use super::DurableOperationFailure;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyProviderMigrationAction {
    Prepare,
    Activate,
    Cancel,
    Resume,
    Verify,
    Retire,
}
impl KeyProviderMigrationAction {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Prepare => 1,
            Self::Activate => 2,
            Self::Cancel => 3,
            Self::Resume => 4,
            Self::Verify => 5,
            Self::Retire => 6,
        }
    }
    pub(super) fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::Prepare),
            2 => Ok(Self::Activate),
            3 => Ok(Self::Cancel),
            4 => Ok(Self::Resume),
            5 => Ok(Self::Verify),
            6 => Ok(Self::Retire),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct KeyProviderMigrationParameters {
    action: KeyProviderMigrationAction,
    reference: [u8; 2048],
    reference_len: u16,
    configuration_digest: [u8; 32],
}
impl std::fmt::Debug for KeyProviderMigrationParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyProviderMigrationParameters")
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}
impl KeyProviderMigrationParameters {
    pub fn new(
        action: KeyProviderMigrationAction,
        reference: Option<&str>,
        digest: Option<[u8; 32]>,
    ) -> Result<Self, DurableOperationFailure> {
        let needs_configuration = !matches!(
            action,
            KeyProviderMigrationAction::Cancel | KeyProviderMigrationAction::Resume
        );
        if needs_configuration != reference.is_some()
            || needs_configuration != digest.is_some()
            || digest.is_some_and(|digest| digest.iter().all(|byte| *byte == 0))
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let text = reference.unwrap_or("");
        if text.len() > 2048
            || (needs_configuration
                && (!text.starts_with('/')
                    || text.contains('\0')
                    || text.split('/').any(|part| matches!(part, "." | ".."))))
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let mut bytes = [0; 2048];
        bytes
            .get_mut(..text.len())
            .ok_or(DurableOperationFailure::InvalidInput)?
            .copy_from_slice(text.as_bytes());
        Ok(Self {
            action,
            reference: bytes,
            reference_len: u16::try_from(text.len())
                .map_err(|_| DurableOperationFailure::InvalidInput)?,
            configuration_digest: digest.unwrap_or([0; 32]),
        })
    }
    pub const fn action(self) -> KeyProviderMigrationAction {
        self.action
    }
    pub fn configuration_reference(&self) -> Option<&str> {
        if self.reference_len == 0 {
            return None;
        }
        std::str::from_utf8(self.reference.get(..usize::from(self.reference_len))?).ok()
    }
    pub const fn configuration_digest(self) -> Option<[u8; 32]> {
        if self.reference_len == 0 {
            None
        } else {
            Some(self.configuration_digest)
        }
    }
    pub fn intent_digest(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"positron.key-provider-migration.phase-request.v1\0");
        hash.update([self.action.code()]);
        hash.update(self.reference_len.to_be_bytes());
        hash.update(self.configuration_reference().unwrap_or("").as_bytes());
        hash.update(self.configuration_digest);
        hash.finalize().into()
    }
    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        bytes.push(self.action.code());
        bytes.extend_from_slice(&self.reference_len.to_be_bytes());
        bytes.extend_from_slice(self.configuration_reference().unwrap_or("").as_bytes());
        bytes.extend_from_slice(&self.configuration_digest);
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, DurableOperationFailure> {
        let mut offset = 0;
        let action =
            KeyProviderMigrationAction::from_code(super::codec::take_byte(bytes, &mut offset)?)?;
        let length = usize::from(u16::from_be_bytes(super::codec::take_array(
            bytes,
            &mut offset,
        )?));
        let end = offset
            .checked_add(length)
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let text = std::str::from_utf8(
            bytes
                .get(offset..end)
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
        offset = end;
        let digest: [u8; 32] = super::codec::take_array(bytes, &mut offset)?;
        if offset != bytes.len() || (length == 0 && digest != [0; 32]) {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        Self::new(
            action,
            (!text.is_empty()).then_some(text),
            (length > 0).then_some(digest),
        )
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_configuration_action_rejects_hidden_digest_bytes() {
        let mut bytes = vec![3, 0, 0];
        bytes.extend_from_slice(&[1; 32]);
        assert_eq!(
            KeyProviderMigrationParameters::decode(&bytes),
            Err(DurableOperationFailure::PersistenceUnavailable)
        );
    }
}
