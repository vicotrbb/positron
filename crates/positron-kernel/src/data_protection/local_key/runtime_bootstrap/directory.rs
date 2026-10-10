//! Held-directory entry points for bootstrap key custody.

use std::fs::File;

use super::{BootstrapKeyCustody, BootstrapKeyFailure, map_local};
use crate::data_protection::local_key::bootstrap::initialize_local_key;
use crate::data_protection::local_key::persistence::open_existing_local_key_in;
use crate::data_protection::local_key::security_directory::FreshInitializationRootProof;

impl BootstrapKeyCustody {
    pub(crate) fn publish_recovered_in(&self, directory: &File) -> Result<(), BootstrapKeyFailure> {
        let super::RootCustody::Bootstrap(key) = &self.key else {
            return Err(BootstrapKeyFailure::Custody);
        };
        let epoch = self.active_root_epoch()?;
        let final_name = if epoch == 1 {
            "local-root-key.v1".to_owned()
        } else {
            format!("local-root-key.epoch-{epoch}.v1")
        };
        let staging_name = format!("{final_name}.new");
        super::super::bootstrap::publish_recovered_local_key(
            directory,
            key,
            &final_name,
            &staging_name,
        )
        .map_err(map_local)
    }

    pub(crate) fn initialize_in(directory: &File) -> Result<Self, BootstrapKeyFailure> {
        let proof =
            FreshInitializationRootProof::from_open_directory(directory).map_err(map_local)?;
        initialize_local_key(proof)
            .map(Self::from_verified)
            .map_err(map_local)
    }

    pub(crate) fn open_in(directory: &File) -> Result<Self, BootstrapKeyFailure> {
        open_existing_local_key_in(directory)
            .map(Self::from_verified)
            .map_err(map_local)
    }
}

impl BootstrapKeyCustody {
    pub(crate) fn initialize_epoch_in(
        directory: &File,
        epoch: u64,
    ) -> Result<Self, BootstrapKeyFailure> {
        use std::os::unix::fs::MetadataExt;
        if epoch < 2 {
            return Err(BootstrapKeyFailure::InvalidInput);
        }
        let metadata = directory
            .metadata()
            .map_err(|_| BootstrapKeyFailure::Custody)?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(BootstrapKeyFailure::Custody);
        }
        super::super::acl::verify_directory_acl(directory).map_err(map_local)?;
        let final_name = format!("local-root-key.epoch-{epoch}.v1");
        let staging_name = format!("{final_name}.new");
        super::super::bootstrap::initialize_named_local_key(
            directory,
            metadata.uid(),
            &final_name,
            &staging_name,
        )
        .map(Self::from_verified)
        .map_err(map_local)
    }
    pub(crate) fn open_epoch_in(directory: &File, epoch: u64) -> Result<Self, BootstrapKeyFailure> {
        if epoch < 2 {
            return Err(BootstrapKeyFailure::InvalidInput);
        }
        super::super::persistence::open_named_local_key_in(
            directory,
            &format!("local-root-key.epoch-{epoch}.v1"),
        )
        .map(Self::from_verified)
        .map_err(map_local)
    }
}
