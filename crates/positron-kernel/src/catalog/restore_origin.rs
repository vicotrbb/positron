//! Authenticated imported prefix. Original audit records keep their native
//! per-record storage, so ordinary retention can reclaim their content.
use super::*;
pub(super) const MAX_ORIGIN_BYTES: usize = 3 * 1024 * 1024;
const MAX_PREFIX_RECORDS: usize = 65_536;

/// Constructed only by completed portable capture authentication. Installing
/// this origin stages metadata; it does not publish a bootable instance.
pub struct BackupRestoreOrigin {
    pub(super) instance: InstanceId,
    pub(super) manifest: [u8; 32],
    pub(super) intent: [u8; 32],
    pub(super) snapshot: CatalogSnapshot,
    pub(super) audit: Vec<GovernanceAuditRecord>,
    pub(super) checkpoint: Option<GovernanceAuditCheckpoint>,
}
impl BackupRestoreOrigin {
    /// Omits only native segment metadata and additive segment key routes of
    /// authenticated purge exclusions. Audit history remains source history.
    pub fn without_tenant_segments(
        self,
        tenants: &[positron_domain::identity::TenantId],
    ) -> Result<Self, CatalogFailure> {
        let mut objects = Vec::new();
        for bytes in self.snapshot.0.objects.values() {
            if crate::active_segment_ledger::restore_object_tenant(bytes)?
                .is_some_and(|tenant| tenants.contains(&tenant))
            {
                continue;
            }
            objects.push(CatalogObject::new(bytes.to_vec())?);
        }
        self.with_restored_objects(objects)
    }
    pub fn retains_segment_file(&self, file: BackupCaptureFile) -> Result<bool, CatalogFailure> {
        crate::active_segment_ledger::restore_file_is_reachable(&self.snapshot, file)
    }
    /// Identity of the actual target-origin transaction used by the Catalog Writer.
    pub fn transaction_id(&self) -> Result<TransactionId, CatalogFailure> {
        TransactionId::new(
            self.manifest
                .get(..16)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| fail(CatalogFailureCode::InvalidInput))?,
        )
    }
    pub fn snapshot(&self) -> &CatalogSnapshot {
        &self.snapshot
    }
    /// Applies transformations supplied by the owning product modules while
    /// retaining the authenticated source identity and original audit frontier.
    pub fn with_restored_objects(
        mut self,
        objects: Vec<CatalogObject>,
    ) -> Result<Self, CatalogFailure> {
        let proposal = CatalogProposal::new(
            TransactionId::new([1; 16])?,
            FormatEpoch::CATALOG_V2,
            objects,
        )?;
        let mut objects = BTreeMap::new();
        for object in proposal.objects {
            if objects
                .insert(object.identity, Arc::from(object.plaintext))
                .is_some()
            {
                return Err(fail(CatalogFailureCode::InvalidInput));
            }
        }
        self.snapshot = CatalogSnapshot(Arc::new(types::SnapshotData {
            identity: self.snapshot.identity(),
            number: self.snapshot.number(),
            format_epoch: Some(FormatEpoch::CATALOG_V2),
            objects,
            audit_frontier: self.snapshot.0.audit_frontier,
        }));
        Ok(self)
    }
}

pub(super) struct StoredOrigin {
    pub(super) instance: InstanceId,
    pub(super) manifest: [u8; 32],
    pub(super) intent: [u8; 32],
    pub(super) source: [u8; 32],
    pub(super) snapshot: CatalogSnapshot,
    pub(super) audit: Vec<(u64, [u8; 32])>,
}
impl Catalog<'_> {
    /// Authenticates an imported origin without creating or reconciling any
    /// native Catalog artifacts. Nonempty targets must pass this before opening
    /// a writable Catalog for an exact restore retry.
    pub fn inspect_restore_origin_intent(
        authority: &StorageKernelResourceAuthority,
        instance: InstanceId,
        secret: &CatalogSecret,
    ) -> Result<Option<[u8; 32]>, CatalogFailure> {
        let claim = RecoveryWorkClaim::system(RecoveryWorkKind::Repair, recovery_resource_claim())
            .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        let _grant = authority
            .recovery()
            .reserve(claim)
            .map_err(CatalogFailure::admission)?;
        let volume = authority
            .primary_data_volume()
            .ok_or_else(|| fail(CatalogFailureCode::ResourceAdmissionRefused))?;
        let storage = CatalogStorage::inspect(&volume._root)?;
        Ok(storage
            .read_restore_origin(secret, instance)?
            .map(|origin| origin.intent))
    }

    /// The authenticated original restore request binds source, physical roots,
    /// effective configuration, and the independent recovery pin on restart.
    pub fn restore_origin_intent(&self) -> Result<Option<[u8; 32]>, CatalogFailure> {
        let secret = self
            .secret
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        Ok(self
            .storage
            .read_restore_origin(&secret, self.instance)?
            .map(|origin| origin.intent))
    }

    /// Installs only authenticated metadata into an empty owned Catalog. The
    /// Runtime retains its offline bootstrap gate until data verification ends.
    pub fn install_restore_origin(
        &self,
        origin: BackupRestoreOrigin,
    ) -> Result<CatalogSnapshot, CatalogFailure> {
        if origin.instance != self.instance {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let _operation = self
            .operation
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        if state.current.number() != 0 {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let secret = self
            .secret
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let objects = origin
            .snapshot
            .0
            .objects
            .values()
            .map(|bytes| CatalogObject::new(bytes.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        let proposal =
            CatalogProposal::new(origin.transaction_id()?, FormatEpoch::CATALOG_V2, objects)?;
        let claim = RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            budget::commit_resource_claim(&proposal, None)?,
        )
        .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        let _reservation = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(CatalogFailure::admission)?;
        let transaction = self
            .storage
            .open_transaction(proposal.transaction, origin.manifest)?;
        let mut objects = BTreeMap::new();
        for object in proposal.objects {
            self.storage.publish_object(
                &transaction,
                &secret,
                self.instance,
                object.identity,
                FormatEpoch::CATALOG_V2,
                &object.plaintext,
            )?;
            objects.insert(object.identity, Arc::from(object.plaintext));
        }
        let mut hash = Sha256::new();
        hash.update(b"positron-restored-catalog-origin-v1\0");
        hash.update(origin.manifest);
        hash.update(origin.intent);
        hash.update(origin.snapshot.identity().to_bytes());
        for identity in objects.keys() {
            hash.update(identity.to_bytes());
        }
        let snapshot = CatalogSnapshot(Arc::new(types::SnapshotData {
            identity: CatalogGenerationId(hash.finalize().into()),
            number: origin.snapshot.number(),
            format_epoch: Some(FormatEpoch::CATALOG_V2),
            objects,
            audit_frontier: origin.snapshot.0.audit_frontier,
        }));
        for record in &origin.audit {
            self.storage.publish_audit(
                &transaction,
                &secret,
                self.instance,
                record,
                &codec::encode_audit(record),
            )?;
        }
        if let Some(checkpoint) = origin.checkpoint.as_ref() {
            self.storage
                .publish_audit_checkpoint(&secret, self.instance, checkpoint)?;
        }
        let stored = StoredOrigin {
            instance: self.instance,
            manifest: origin.manifest,
            intent: origin.intent,
            source: origin.snapshot.identity().to_bytes(),
            snapshot: snapshot.clone(),
            audit: origin
                .audit
                .iter()
                .map(|record| (record.position(), record.record_hash()))
                .collect(),
        };
        self.storage.publish_restore_origin(&secret, &stored)?;
        *state = recovery::recover(&self.storage, &secret, self.instance)?;
        Ok(snapshot)
    }
}
impl StoredOrigin {
    pub(super) fn encode(&self) -> Result<Vec<u8>, CatalogFailure> {
        if self.audit.len() > MAX_PREFIX_RECORDS {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        let mut bytes = b"POSBRO02".to_vec();
        bytes.extend_from_slice(&self.instance.to_bytes());
        bytes.extend_from_slice(&self.manifest);
        bytes.extend_from_slice(&self.intent);
        bytes.extend_from_slice(&self.source);
        bytes.extend_from_slice(&self.snapshot.identity().to_bytes());
        bytes.extend_from_slice(&self.snapshot.number().to_be_bytes());
        bytes.extend_from_slice(&self.snapshot.0.audit_frontier.position.to_be_bytes());
        bytes.extend_from_slice(&self.snapshot.0.audit_frontier.hash);
        bytes.extend_from_slice(&(self.snapshot.object_count() as u32).to_be_bytes());
        for identity in self.snapshot.object_identities() {
            bytes.extend_from_slice(&identity.to_bytes());
        }
        bytes.extend_from_slice(&(self.audit.len() as u32).to_be_bytes());
        for (position, hash) in &self.audit {
            bytes.extend_from_slice(&position.to_be_bytes());
            bytes.extend_from_slice(hash);
        }
        if bytes.len() > MAX_ORIGIN_BYTES {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        Ok(bytes)
    }
    pub(super) fn decode(
        storage: &CatalogStorage,
        secret: &CatalogSecret,
        instance: InstanceId,
        bytes: &[u8],
    ) -> Result<Self, CatalogFailure> {
        let mut decoder = Decoder(bytes);
        if decoder.take(8)? != b"POSBRO02" || decoder.array::<16>()? != instance.to_bytes() {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        let manifest = decoder.array()?;
        let intent = decoder.array()?;
        let source = decoder.array()?;
        let identity = CatalogGenerationId(decoder.array()?);
        let number = decoder.u64()?;
        let position = decoder.u64()?;
        let hash = decoder.array()?;
        if intent == [0; 32]
            || manifest == [0; 32]
            || source == [0; 32]
            || number == 0
            || number > storage::MAX_GENERATIONS as u64
        {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        let count = decoder.u32()? as usize;
        if count == 0 || count > MAX_CATALOG_OBJECTS {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        let mut objects = BTreeMap::new();
        let mut total = 0usize;
        for _ in 0..count {
            let object = CatalogObjectId(decoder.array()?);
            if objects
                .last_key_value()
                .is_some_and(|(last, _)| *last >= object)
            {
                return Err(fail(CatalogFailureCode::IntegrityCorruption));
            }
            let bytes = storage.read_object(secret, instance, object, FormatEpoch::CATALOG_V2)?;
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
            if total > MAX_CATALOG_TOTAL_BYTES {
                return Err(fail(CatalogFailureCode::LimitExceeded));
            }
            objects.insert(object, bytes);
        }
        let count = decoder.u32()? as usize;
        if count > MAX_PREFIX_RECORDS {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        let mut audit = Vec::new();
        audit
            .try_reserve_exact(count)
            .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        for _ in 0..count {
            let value = (decoder.u64()?, decoder.array()?);
            if value.0 == 0
                || value.1 == [0; 32]
                || audit
                    .last()
                    .is_some_and(|last: &(u64, [u8; 32])| last.0.checked_add(1) != Some(value.0))
            {
                return Err(fail(CatalogFailureCode::IntegrityCorruption));
            }
            audit.push(value);
        }
        if !decoder.0.is_empty() || audit.last().is_some_and(|last| *last != (position, hash)) {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        let mut expected = Sha256::new();
        expected.update(b"positron-restored-catalog-origin-v1\0");
        expected.update(manifest);
        expected.update(intent);
        expected.update(source);
        for object in objects.keys() {
            expected.update(object.to_bytes());
        }
        if <[u8; 32]>::from(expected.finalize()) != identity.to_bytes()
            || (position == 0 && (hash != [0; 32] || !audit.is_empty()))
        {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        Ok(Self {
            instance,
            manifest,
            intent,
            source,
            snapshot: CatalogSnapshot(Arc::new(types::SnapshotData {
                identity,
                number,
                format_epoch: Some(FormatEpoch::CATALOG_V2),
                objects,
                audit_frontier: types::AuditFrontier { position, hash },
            })),
            audit,
        })
    }
}
struct Decoder<'a>(&'a [u8]);
impl<'a> Decoder<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], CatalogFailure> {
        let (value, tail) = self
            .0
            .split_at_checked(length)
            .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?;
        self.0 = tail;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CatalogFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| fail(CatalogFailureCode::IntegrityCorruption))
    }
    fn u64(&mut self) -> Result<u64, CatalogFailure> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, CatalogFailure> {
        Ok(u32::from_be_bytes(self.array()?))
    }
}
fn fail(code: CatalogFailureCode) -> CatalogFailure {
    CatalogFailure::new(code)
}

/// Exercise the imported descriptor decoder behind native object authentication.
#[cfg(fuzzing)]
pub(super) fn fuzz_restore_origin(catalog: &Catalog<'_>, data: &[u8]) {
    let secret = catalog.secret.lock().expect("fuzz secret");
    let object = CatalogObject::new(b"restore-origin-fuzz-object".to_vec()).expect("object");
    let transaction = catalog
        .storage
        .open_transaction(
            TransactionId::new([0xf1; 16]).expect("transaction"),
            [0xf2; 32],
        )
        .expect("staging");
    catalog
        .storage
        .publish_object(
            &transaction,
            &secret,
            catalog.instance,
            object.identity(),
            FormatEpoch::CATALOG_V2,
            &object.plaintext,
        )
        .expect("authenticated object");
    let source = [0xf3; 32];
    let manifest = [0xf4; 32];
    let intent = [0xf5; 32];
    let mut hash = Sha256::new();
    hash.update(b"positron-restored-catalog-origin-v1\0");
    hash.update(manifest);
    hash.update(intent);
    hash.update(source);
    hash.update(object.identity().to_bytes());
    let mut objects = BTreeMap::new();
    objects.insert(object.identity(), Arc::from(object.plaintext));
    let origin = StoredOrigin {
        instance: catalog.instance,
        manifest,
        intent,
        source,
        snapshot: CatalogSnapshot(Arc::new(types::SnapshotData {
            identity: CatalogGenerationId(hash.finalize().into()),
            number: 1,
            format_epoch: Some(FormatEpoch::CATALOG_V2),
            objects,
            audit_frontier: types::AuditFrontier {
                position: 0,
                hash: [0; 32],
            },
        })),
        audit: Vec::new(),
    };
    let mut bytes = origin.encode().expect("valid origin");
    let restored = StoredOrigin::decode(&catalog.storage, &secret, catalog.instance, &bytes)
        .expect("valid authenticated descriptor");
    assert_eq!(restored.encode().expect("canonical descriptor"), bytes);
    for mutation in data.chunks(3).take(32) {
        if let [high, low, value] = mutation {
            let offset = usize::from(u16::from_be_bytes([*high, *low])) % bytes.len();
            if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= value;
            }
        }
    }
    let _ = StoredOrigin::decode(&catalog.storage, &secret, catalog.instance, &bytes);
    let _ = StoredOrigin::decode(
        &catalog.storage,
        &secret,
        catalog.instance,
        &bytes[..bytes.len().saturating_sub(1)],
    );
}
