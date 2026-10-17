//! Read-only admission inventory. Discovery cannot authorize deletion.
use crate::{HeadSlot, ObjectId, RepositoryFailure};
pub(crate) struct ControlInventory<'a> {
    allowed: &'a [ObjectId],
    seen: Vec<bool>,
    identity: bool,
    head: bool,
}
impl<'a> ControlInventory<'a> {
    pub(crate) fn new(allowed: &'a [ObjectId]) -> Result<Self, RepositoryFailure> {
        if allowed.len() > 1 || allowed.windows(2).any(|p| p.first() >= p.get(1)) {
            return Err(RepositoryFailure::LimitExceeded);
        }
        Ok(Self {
            allowed,
            seen: vec![false; allowed.len()],
            identity: false,
            head: false,
        })
    }
    pub(crate) fn has_object(&self, id: ObjectId) -> bool {
        self.allowed
            .binary_search(&id)
            .ok()
            .and_then(|i| self.seen.get(i))
            .copied()
            .unwrap_or(false)
    }
    pub(crate) fn has_head(&self) -> bool {
        self.head
    }
    pub(crate) fn finish(&self) -> Result<(), RepositoryFailure> {
        if self.identity {
            Ok(())
        } else {
            Err(RepositoryFailure::PreconditionFailed)
        }
    }
    pub(crate) fn observe(&mut self, name: &str) -> Result<(), RepositoryFailure> {
        let seen = if name == "identity" {
            &mut self.identity
        } else if name == HeadSlot::registry().name() {
            &mut self.head
        } else {
            let checksum = name
                .strip_prefix("o-")
                .ok_or(RepositoryFailure::PreconditionFailed)?;
            let id =
                ObjectId::from_checksum(crate::listing::native_cursor::checksum_name(checksum)?);
            let index = self
                .allowed
                .binary_search(&id)
                .map_err(|_| RepositoryFailure::PreconditionFailed)?;
            self.seen
                .get_mut(index)
                .ok_or(RepositoryFailure::CorruptState)?
        };
        if std::mem::replace(seen, true) {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_control_inventory_refuses_orphans_and_historical_duplicates() {
        let object = ObjectId::from_checksum([7; 32]);
        let allowed = [object];
        let mut inventory = ControlInventory::new(&allowed).expect("bounded control inventory");
        assert!(inventory.finish().is_err());
        inventory.observe("identity").expect("identity");
        inventory
            .observe(&object.name())
            .expect("authenticated control");
        inventory
            .observe(&HeadSlot::registry().name())
            .expect("exact head");
        assert!(inventory.has_object(object));
        assert!(inventory.has_head());
        assert_eq!(inventory.finish(), Ok(()));
        assert_eq!(
            inventory.observe(&object.name()),
            Err(RepositoryFailure::PreconditionFailed)
        );
        assert_eq!(
            inventory.observe("uncommitted-upload"),
            Err(RepositoryFailure::PreconditionFailed)
        );
        assert_eq!(
            inventory.observe(&ObjectId::from_checksum([8; 32]).name()),
            Err(RepositoryFailure::PreconditionFailed)
        );
    }
}
