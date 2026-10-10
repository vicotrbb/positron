//! Canonical progress carried by the existing EnvelopeVerification task owner.
use super::{MaintenanceCheckpoint, MaintenanceFailure};
use crate::{InstanceId, IntegrityScrubContinuation, SegmentScope};
use positron_domain::{
    identity::TenantId,
    routing::{SignalKind, VirtualShardId},
};
const MAGIC: &[u8; 8] = b"PEVCKP01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeVerificationCheckpoint {
    instance: InstanceId,
    tenant: TenantId,
    epoch: u64,
    source: [u8; 32],
    scope: Option<SegmentScope>,
    continuation: Option<IntegrityScrubContinuation>,
}
impl EnvelopeVerificationCheckpoint {
    pub fn new(
        instance: InstanceId,
        tenant: TenantId,
        epoch: u64,
        source: [u8; 32],
        scope: Option<SegmentScope>,
        continuation: Option<IntegrityScrubContinuation>,
    ) -> Result<Self, MaintenanceFailure> {
        if epoch < 2
            || source == [0; 32]
            || scope.is_some_and(|scope| scope.tenant_id() != tenant)
            || (scope.is_none() && continuation.is_some())
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self {
            instance,
            tenant,
            epoch,
            source,
            scope,
            continuation,
        })
    }
    pub const fn source_identity(self) -> [u8; 32] {
        self.source
    }
    pub const fn scope(self) -> Option<SegmentScope> {
        self.scope
    }
    pub const fn continuation(self) -> Option<IntegrityScrubContinuation> {
        self.continuation
    }
    /// Complete verification remains separate from managed reference retirement.
    pub const fn is_complete(self) -> bool {
        self.scope.is_none()
    }
    pub fn checkpoint(self, sequence: u64) -> Result<MaintenanceCheckpoint, MaintenanceFailure> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(143)
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.instance.to_bytes());
        bytes.extend_from_slice(&self.tenant.to_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.source);
        bytes.push(u8::from(self.scope.is_some()));
        if let Some(scope) = self.scope {
            bytes.push(match scope.signal_kind() {
                SignalKind::Logs => 1,
                SignalKind::Traces => 2,
            });
            bytes.extend_from_slice(&scope.shard_id().value().to_be_bytes());
            bytes.push(u8::from(self.continuation.is_some()));
            if let Some(cursor) = self.continuation {
                bytes.extend_from_slice(&cursor.encode());
            }
        }
        MaintenanceCheckpoint::new(sequence, 0, bytes)
    }
    pub fn from_checkpoint(
        checkpoint: &MaintenanceCheckpoint,
        instance: InstanceId,
        tenant: TenantId,
        epoch: u64,
    ) -> Result<Self, MaintenanceFailure> {
        if checkpoint.completed_inputs() != 0 || checkpoint.opaque_progress().len() > 143 {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let mut input = Input(checkpoint.opaque_progress());
        if input.take(8)? != MAGIC
            || input.array::<16>()? != instance.to_bytes()
            || input.array::<16>()? != tenant.to_bytes()
            || u64::from_be_bytes(input.array()?) != epoch
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let source = input.array()?;
        let (scope, continuation) = match input.array::<1>()? {
            [0] => (None, None),
            [1] => {
                let signal = match input.array::<1>()? {
                    [1] => SignalKind::Logs,
                    [2] => SignalKind::Traces,
                    _ => return Err(MaintenanceFailure::InvalidInput),
                };
                let shard = VirtualShardId::new(u32::from_be_bytes(input.array()?))
                    .map_err(|_| MaintenanceFailure::InvalidInput)?;
                let cursor = match input.array::<1>()? {
                    [0] => None,
                    [1] => {
                        let encoded = input.take(56)?;
                        let cursor = IntegrityScrubContinuation::decode(encoded)
                            .map_err(|_| MaintenanceFailure::InvalidInput)?;
                        if cursor.encode().as_slice() != encoded {
                            return Err(MaintenanceFailure::InvalidInput);
                        }
                        Some(cursor)
                    },
                    _ => return Err(MaintenanceFailure::InvalidInput),
                };
                (Some(SegmentScope::new(tenant, signal, shard)), cursor)
            },
            _ => return Err(MaintenanceFailure::InvalidInput),
        };
        if !input.0.is_empty() {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Self::new(instance, tenant, epoch, source, scope, continuation)
    }
}
struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], MaintenanceFailure> {
        let (head, tail) = self
            .0
            .split_at_checked(count)
            .ok_or(MaintenanceFailure::InvalidInput)?;
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], MaintenanceFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| MaintenanceFailure::InvalidInput)
    }
}
