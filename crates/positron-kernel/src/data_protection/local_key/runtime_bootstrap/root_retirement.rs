//! Exact file identity remains held until predecessor unlink and directory sync.
use super::{BootstrapKeyCustody, BootstrapKeyFailure, BootstrapKeyIdentity, map_local};
use std::fs::File;

impl BootstrapKeyCustody {
    pub(crate) fn retire_named_predecessor(
        directory: &File,
        name: &str,
        identity: BootstrapKeyIdentity,
    ) -> Result<(), BootstrapKeyFailure> {
        let (file, verified) =
            super::super::persistence::open_named_local_key_with_file(directory, name)
                .map_err(map_local)?;
        let custody = Self::from_verified(verified);
        if custody.identity() != identity {
            return Err(BootstrapKeyFailure::Authentication);
        }
        drop(custody);
        #[cfg(test)]
        super::super::bootstrap::initialization_event(
            super::super::bootstrap::LocalKeyInitializationEvent::PredecessorOpened,
        );
        let owner = directory
            .metadata()
            .map_err(|_| BootstrapKeyFailure::Custody)?;
        use std::os::unix::fs::MetadataExt;
        super::super::bootstrap::verify_named_key_file(directory, &file, owner.uid(), name)
            .map_err(map_local)?;
        super::super::acl::verify_file_acl(&file).map_err(map_local)?;
        rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::empty())
            .map_err(|_| BootstrapKeyFailure::Custody)?;
        Self::synchronize_root_envelope_directory(directory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_protection::local_key::{bootstrap, test_support::SecurityRoot};
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn substituted_entry_after_verified_open_is_not_unlinked()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = SecurityRoot::create()?;
        let foreign = SecurityRoot::create()?;
        let identity = BootstrapKeyCustody::initialize(&root.path)?.identity();
        drop(BootstrapKeyCustody::initialize(&foreign.path)?);
        let directory = File::open(&root.path)?;
        let predecessor = root.path.join("local-root-key.v1");
        let retained = root.path.join("retained-original.v1");
        let replacement = foreign.path.join("local-root-key.v1");
        let action_result = Rc::new(RefCell::new(None));
        let outcome = Rc::clone(&action_result);
        let result = bootstrap::with_initialization_event_action(
            move |event| {
                if event == bootstrap::LocalKeyInitializationEvent::PredecessorOpened {
                    let moved = std::fs::rename(&predecessor, &retained)
                        .and_then(|()| std::fs::rename(&replacement, &predecessor));
                    *outcome.borrow_mut() = Some(moved);
                }
            },
            || {
                BootstrapKeyCustody::retire_named_predecessor(
                    &directory,
                    "local-root-key.v1",
                    identity,
                )
            },
        );
        action_result
            .borrow_mut()
            .take()
            .ok_or("replacement action did not run")??;
        assert_eq!(result, Err(BootstrapKeyFailure::Custody));
        assert!(root.path.join("local-root-key.v1").exists());
        assert!(root.path.join("retained-original.v1").exists());
        Ok(())
    }
}
