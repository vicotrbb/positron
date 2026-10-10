//! Checked route preservation and exact physical predecessor custody removal.
use super::*;

/// Borrowed canonical predecessor route; ciphertext remains with its Catalog owner.
pub struct RootPredecessorEnvelope<'a> {
    identity: BootstrapKeyIdentity,
    epoch: u64,
    envelope: &'a [u8],
}

impl<'a> RootPredecessorEnvelope<'a> {
    pub fn new(
        identity: BootstrapKeyIdentity,
        epoch: u64,
        envelope: &'a [u8],
    ) -> Result<Self, BootstrapKeyFailure> {
        if epoch == 0 || envelope.is_empty() || envelope.len() > 1024 {
            return Err(BootstrapKeyFailure::InvalidInput);
        }
        Ok(Self {
            identity,
            epoch,
            envelope,
        })
    }
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug)]
pub enum RootCustodyPublicationFault {
    PredecessorDirectorySync,
    RoutePartialWrite,
    RouteFileSync,
    RouteDirectorySync,
}

impl RootRewrapSession<'_> {
    #[cfg(feature = "test-support")]
    pub fn with_custody_publication_fault<T>(
        fault: RootCustodyPublicationFault,
        action: impl FnOnce() -> T,
    ) -> T {
        use crate::data_protection::local_key::initialization_io::{
            InitializationFault, with_initialization_fault_after,
        };
        let (fault, preceding) = match fault {
            RootCustodyPublicationFault::PredecessorDirectorySync => {
                (InitializationFault::SynchronizeSecurityDirectory, 0)
            },
            RootCustodyPublicationFault::RoutePartialWrite => {
                (InitializationFault::PartialWrite(5), 0)
            },
            RootCustodyPublicationFault::RouteFileSync => {
                (InitializationFault::SynchronizeKeyFile, 0)
            },
            RootCustodyPublicationFault::RouteDirectorySync => {
                (InitializationFault::SynchronizeSecurityDirectory, 1)
            },
        };
        with_initialization_fault_after(fault, preceding, action)
    }
    pub fn verify_predecessor_custody(
        &self,
        access: &crate::BootstrapArtifactAccess,
        epoch: u64,
        identity: BootstrapKeyIdentity,
    ) -> Result<(), BootstrapKeyFailure> {
        let predecessor = if epoch == 1 {
            access.open_key()?
        } else {
            access.open_successor_key(epoch)?
        };
        if predecessor.identity() != identity {
            return Err(BootstrapKeyFailure::Authentication);
        }
        Ok(())
    }
    pub fn verify_retirement_routes(
        &self,
        access: &crate::BootstrapArtifactAccess,
        current: &BootstrapKeyCustody,
        instance: InstanceId,
        predecessor: &RootPredecessorEnvelope<'_>,
        resumed: bool,
    ) -> Result<(), BootstrapKeyFailure> {
        self.retirement_routes(access, current, instance, predecessor, resumed)
            .map(|_| ())
    }
    pub fn retire_predecessor_custody(
        &self,
        access: &crate::BootstrapArtifactAccess,
        current: &BootstrapKeyCustody,
        instance: InstanceId,
        predecessor: &RootPredecessorEnvelope<'_>,
        resumed: bool,
    ) -> Result<(), BootstrapKeyFailure> {
        let (previous, retained) =
            self.retirement_routes(access, current, instance, predecessor, resumed)?;
        access.retire_predecessor_key(predecessor.identity, predecessor.epoch, resumed)?;
        access.replace_recovered_system_envelope(&previous, &retained)
    }
    fn retirement_routes(
        &self,
        access: &crate::BootstrapArtifactAccess,
        current: &BootstrapKeyCustody,
        instance: InstanceId,
        predecessor: &RootPredecessorEnvelope<'_>,
        resumed: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), BootstrapKeyFailure> {
        let previous = access.read_system_key_envelope()?;
        let bridge = parse_bridge(&previous)?;
        let (active, epoch) = current.active_root_route()?;
        if predecessor.epoch.checked_add(1) != Some(epoch)
            || bridge.instance != instance
            || bridge.anchor != current.bootstrap_identity()
            || bridge.routes.len() != 2 && !(resumed && bridge.routes.len() == 1)
        {
            return Err(BootstrapKeyFailure::Authentication);
        }
        let expected = self.wrap_system(current, current, instance, epoch)?;
        let mut found = false;
        for route in &bridge.routes {
            if route.epoch == epoch && route.root == active && route.envelope == expected {
                found = true;
            } else if route.epoch != predecessor.epoch
                || route.root != predecessor.identity
                || route.envelope != predecessor.envelope
            {
                return Err(BootstrapKeyFailure::Authentication);
            }
        }
        if !found {
            return Err(BootstrapKeyFailure::Authentication);
        }
        let retained = current
            .root_recovery_envelope()?
            .ok_or(BootstrapKeyFailure::Authentication)?;
        Ok((previous, retained))
    }
}
