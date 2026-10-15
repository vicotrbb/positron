use super::*;
impl BackupPublisher<'_> {
    /// Makes the signed candidate reachable from the authoritative Registry
    /// before uploading or reusing any encrypted data object. A reservation is
    /// deliberately absent from the published snapshot view.
    pub async fn reserve(
        &self,
        manifest: &BackupManifest,
        keys: &[BackupKeyEnvelope],
    ) -> Result<(), RepositoryFailure> {
        self.key_memory(keys, manifest)?;
        self.require_identity().await?;
        if manifest.repository != *self.identity || Self::key_context(keys)? != manifest.key_context
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let object = self.manifest_object(manifest)?;
        let receipt = BackupReceipt {
            snapshot: manifest.snapshot,
            manifest: object.id(),
            created: manifest.created,
            retain_until: manifest.retain_until,
        };
        let (version, current, current_id) = self.current().await?;
        let mut successor = current.unwrap_or(Generation {
            number: 0,
            previous: [0; 32],
            repository: self.identity.clone(),
            snapshots: Vec::new(),
            reservations: Vec::new(),
            claims: Vec::new(),
            keys: Vec::new(),
        });
        let mut referenced = manifest
            .objects
            .iter()
            .map(|object| object.object())
            .collect::<Vec<_>>();
        referenced.push(receipt.manifest);
        for key in keys {
            referenced.push(key.object()?.id());
        }
        referenced.sort_unstable();
        referenced.dedup();
        if successor.claims.iter().any(|claim| {
            claim.receipt.snapshot == receipt.snapshot
                || claim
                    .remaining
                    .iter()
                    .any(|object| referenced.binary_search(object).is_ok())
        }) {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        if let Some(existing) = successor
            .snapshots
            .iter()
            .chain(&successor.reservations)
            .find(|item| item.snapshot == receipt.snapshot)
        {
            return if *existing == receipt {
                Ok(())
            } else {
                Err(RepositoryFailure::PreconditionFailed)
            };
        }
        if successor
            .snapshots
            .len()
            .checked_add(successor.reservations.len())
            .and_then(|count| count.checked_add(successor.claims.len()))
            .is_none_or(|count| count >= MAX_REGISTERED_SNAPSHOTS)
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        self.repository.put_if_absent(object).await?;
        successor.number = successor
            .number
            .checked_add(1)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        successor.previous = current_id.unwrap_or([0; 32]);
        successor.reservations.push(receipt);
        successor.reservations.sort_by_key(|item| item.snapshot);
        for reference in key_references(keys)? {
            if let Some(existing) = successor.keys.iter_mut().find(|key| {
                key.context == reference.context
                    && key.tenant == reference.tenant
                    && key.epoch == reference.epoch
                    && key.fingerprint == reference.fingerprint
            }) {
                *existing = reference;
            } else {
                successor.keys.push(reference);
            }
        }
        successor
            .keys
            .sort_by_key(|key| (key.context, key.tenant, key.epoch, key.object));
        self.publish_generation(version, &successor).await
    }
    /// Prepares at most one protected key after the exact signed reservation
    /// makes every reference reachable. An unknown Put does not advance progress;
    /// retrying the same index repeats the content-addressed immutable write.
    pub async fn prepare_key_step(
        &self,
        manifest: &BackupManifest,
        keys: &[BackupKeyEnvelope],
        next_key: u32,
    ) -> Result<u32, RepositoryFailure> {
        self.key_memory(keys, manifest)?;
        let index = usize::try_from(next_key).map_err(|_| RepositoryFailure::InvalidInput)?;
        if index > keys.len() {
            return Err(RepositoryFailure::InvalidInput);
        }
        if manifest.repository != *self.identity || Self::key_context(keys)? != manifest.key_context
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        self.require_identity().await?;
        self.require_reserved(manifest).await?;
        let Some(key) = keys.get(index) else {
            return Ok(next_key);
        };
        self.repository.put_if_absent(key.object()?).await?;
        next_key
            .checked_add(1)
            .ok_or(RepositoryFailure::LimitExceeded)
    }
    pub(in crate::snapshot) async fn require_reserved(
        &self,
        manifest: &BackupManifest,
    ) -> Result<(), RepositoryFailure> {
        let (_, generation, _) = self.current().await?;
        let object = self.manifest_object(manifest)?;
        let expected = BackupReceipt {
            snapshot: manifest.snapshot,
            manifest: object.id(),
            created: manifest.created,
            retain_until: manifest.retain_until,
        };
        if generation.is_some_and(|generation| {
            generation
                .snapshots
                .iter()
                .chain(&generation.reservations)
                .any(|receipt| *receipt == expected)
        }) {
            Ok(())
        } else {
            Err(RepositoryFailure::PreconditionFailed)
        }
    }
}
