//! Authenticated Catalog state is the sole active local-root epoch authority.
use super::*;
use positron_kernel::{BootstrapKeyIdentity, CatalogSnapshot};
pub(super) const MAGIC: &[u8; 8] = b"POSLROT1";
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Route {
    pub(super) epoch: u64,
    pub(super) identity: BootstrapKeyIdentity,
    pub(super) envelope: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct State {
    pub(super) instance: positron_kernel::InstanceId,
    pub(super) transaction: TransactionId,
    pub(super) anchor: BootstrapKeyIdentity,
    pub(super) active: Route,
    pub(super) successor: Option<Route>,
    pub(super) predecessor: Option<Route>,
    pub(super) retiring: bool,
}
impl State {
    pub(super) fn find(
        snapshot: &CatalogSnapshot,
    ) -> Result<Option<Self>, LocalKeyRotationFailure> {
        let mut found = None;
        for id in snapshot.object_identities() {
            let bytes = snapshot
                .object(id)
                .map_err(|_| LocalKeyRotationFailure::Storage)?
                .ok_or(LocalKeyRotationFailure::Authentication)?;
            if bytes.starts_with(MAGIC) {
                if found.is_some() {
                    return Err(LocalKeyRotationFailure::Authentication);
                }
                found = Some(Self::decode(bytes)?);
            }
        }
        Ok(found)
    }
    pub(super) fn status(&self) -> LocalKeyRotationStatus {
        LocalKeyRotationStatus {
            active_epoch: self.active.epoch,
            successor_epoch: self.successor.as_ref().map(|route| route.epoch),
            predecessor_epoch: self.predecessor.as_ref().map(|route| route.epoch),
            phase: if self.retiring {
                LocalKeyRotationPhase::Retiring
            } else if self.successor.is_some() {
                LocalKeyRotationPhase::Prepared
            } else if self.predecessor.is_some() {
                LocalKeyRotationPhase::Verifying
            } else {
                LocalKeyRotationPhase::Active
            },
        }
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, LocalKeyRotationFailure> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(3424)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.instance.to_bytes());
        bytes.extend_from_slice(&self.transaction.to_bytes());
        identity(&mut bytes, self.anchor);
        route(&mut bytes, &self.active)?;
        bytes.push(u8::from(self.successor.is_some()));
        if let Some(successor) = &self.successor {
            route(&mut bytes, successor)?;
        }
        bytes.push(u8::from(self.predecessor.is_some()));
        if let Some(predecessor) = &self.predecessor {
            route(&mut bytes, predecessor)?;
        }
        if self.retiring {
            bytes.push(1);
        }
        Ok(bytes)
    }
    fn validate(&self) -> Result<(), LocalKeyRotationFailure> {
        if self.active.epoch == 0
            || self.retiring && self.predecessor.is_none()
            || (self.successor.is_some() && self.predecessor.is_some())
            || self.predecessor.as_ref().is_some_and(|route| {
                route.epoch.checked_add(1) != Some(self.active.epoch)
                    || route.identity == self.active.identity
            })
            || self.successor.as_ref().is_some_and(|route| {
                self.active.epoch.checked_add(1) != Some(route.epoch)
                    || route.identity == self.active.identity
            })
        {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        Ok(())
    }
    fn decode(bytes: &[u8]) -> Result<Self, LocalKeyRotationFailure> {
        if bytes.len() > 3424 {
            return Err(LocalKeyRotationFailure::LimitExceeded);
        }
        let mut cursor = Cursor(bytes);
        if cursor.array::<8>()? != *MAGIC {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        let instance = positron_kernel::InstanceId::new(cursor.array()?)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let transaction = TransactionId::new(cursor.array()?)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let anchor = cursor.identity()?;
        let active = cursor.route()?;
        let successor = match cursor.array::<1>()? {
            [0] => None,
            [1] => Some(cursor.route()?),
            _ => return Err(LocalKeyRotationFailure::Authentication),
        };
        let predecessor = match cursor.array::<1>()? {
            [0] => None,
            [1] => Some(cursor.route()?),
            _ => return Err(LocalKeyRotationFailure::Authentication),
        };
        let retiring = match cursor.0 {
            [] => false,
            [1] => true,
            _ => return Err(LocalKeyRotationFailure::Authentication),
        };
        let state = Self {
            instance,
            transaction,
            anchor,
            active,
            successor,
            predecessor,
            retiring,
        };
        state.validate()?;
        if state.encode()? != bytes {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        Ok(state)
    }
}
fn identity(bytes: &mut Vec<u8>, value: BootstrapKeyIdentity) {
    bytes.extend_from_slice(&value.key_id());
    bytes.extend_from_slice(&value.fingerprint());
    bytes.extend_from_slice(&value.created_at_unix_seconds().to_be_bytes());
}
fn route(bytes: &mut Vec<u8>, value: &Route) -> Result<(), LocalKeyRotationFailure> {
    if value.envelope.is_empty() || value.envelope.len() > 1024 {
        return Err(LocalKeyRotationFailure::LimitExceeded);
    }
    positron_kernel::key_provider::KeyEnvelope::decode(&value.envelope)
        .map_err(|_| LocalKeyRotationFailure::Authentication)?;
    bytes.extend_from_slice(&value.epoch.to_be_bytes());
    identity(bytes, value.identity);
    let length =
        u16::try_from(value.envelope.len()).map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&value.envelope);
    Ok(())
}
struct Cursor<'a>(&'a [u8]);
impl Cursor<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], LocalKeyRotationFailure> {
        let (bytes, tail) = self
            .0
            .split_at_checked(N)
            .ok_or(LocalKeyRotationFailure::Authentication)?;
        self.0 = tail;
        bytes
            .try_into()
            .map_err(|_| LocalKeyRotationFailure::Authentication)
    }
    fn identity(&mut self) -> Result<BootstrapKeyIdentity, LocalKeyRotationFailure> {
        BootstrapKeyIdentity::from_parts(
            self.array()?,
            self.array()?,
            u64::from_be_bytes(self.array()?),
        )
        .map_err(|_| LocalKeyRotationFailure::Authentication)
    }
    fn route(&mut self) -> Result<Route, LocalKeyRotationFailure> {
        let epoch = u64::from_be_bytes(self.array()?);
        let identity = self.identity()?;
        let length = usize::from(u16::from_be_bytes(self.array()?));
        if length == 0 || length > 1024 {
            return Err(LocalKeyRotationFailure::LimitExceeded);
        }
        let (bytes, tail) = self
            .0
            .split_at_checked(length)
            .ok_or(LocalKeyRotationFailure::Authentication)?;
        self.0 = tail;
        Ok(Route {
            epoch,
            identity,
            envelope: bytes.to_vec(),
        })
    }
}
