use super::{AzureBlobRepository, deletion::Proof, protocol};
use crate::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderMap, HeaderValue, Method};
use sha2::{Digest, Sha256};
pub(super) struct Record {
    plan: UploadPlan,
    bytes: Vec<u8>,
    selector: [u8; 16],
}
impl Record {
    fn decode(
        mut bytes: Vec<u8>,
        target: [u8; 32],
        custody: &positron_kernel::RepositoryUploadAuthenticator,
        id: UploadId,
    ) -> Result<Self, RepositoryFailure> {
        fn field<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], RepositoryFailure> {
            bytes
                .get(start..start + N)
                .and_then(|s| s.try_into().ok())
                .ok_or(RepositoryFailure::CorruptState)
        }
        if bytes.len() < 136
            || bytes.len() > MAX_OBJECT_BYTES as usize + 136
            || bytes.get(..8) != Some(b"POSAZU01")
        {
            return Err(RepositoryFailure::CorruptState);
        }
        let end = bytes.len() - 40;
        let authentication = positron_kernel::ControlTokenAuthentication::new(
            u64::from_be_bytes(field(&bytes, end)?),
            field(&bytes, end + 8)?,
        )
        .map_err(|_| RepositoryFailure::CorruptState)?;
        custody
            .verify(
                Sha256::digest(bytes.get(..end).ok_or(RepositoryFailure::CorruptState)?).into(),
                authentication,
            )
            .map_err(|_| RepositoryFailure::ChecksumMismatch)?;
        if field::<32>(&bytes, 8)? != target {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let plan = UploadPlan::new(
            ObjectId::from_checksum(field(&bytes, 40)?),
            u64::from_be_bytes(field(&bytes, 72)?),
        )?;
        let selector = field(&bytes, 80)?;
        if plan.id() != id || selector == [0; 16] || end - 96 > plan.size as usize {
            return Err(RepositoryFailure::CorruptState);
        }
        bytes.copy_within(96..end, 0);
        bytes.truncate(end - 96);
        if bytes.len() as u64 == plan.size
            && <[u8; 32]>::from(Sha256::digest(&bytes)) != plan.object.checksum()
        {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        Ok(Record {
            plan,
            selector,
            bytes,
        })
    }
    fn state(&self) -> UploadState {
        UploadState {
            plan: self.plan,
            written: self.bytes.len() as u64,
            checksum: Sha256::digest(&self.bytes).into(),
        }
    }
}
impl AzureBlobRepository {
    fn encode_record(&self, record: &Record) -> Result<Vec<u8>, RepositoryFailure> {
        let mut bytes = Vec::with_capacity(record.bytes.len() + 200);
        bytes.extend_from_slice(b"POSAZU01");
        bytes.extend_from_slice(&self.target.commitment());
        bytes.extend_from_slice(&record.plan.object.checksum());
        bytes.extend_from_slice(&record.plan.size.to_be_bytes());
        bytes.extend_from_slice(&record.selector);
        bytes.extend_from_slice(&record.bytes);
        let digest = Sha256::digest(&bytes).into();
        let authentication = self
            .upload_authenticator()?
            .authenticate(digest)
            .map_err(|_| RepositoryFailure::StorageUnavailable)?;
        bytes.extend_from_slice(&authentication.epoch().to_be_bytes());
        bytes.extend_from_slice(&authentication.tag());
        Ok(bytes)
    }
    pub(super) fn decode_record(
        &self,
        bytes: Vec<u8>,
        id: UploadId,
    ) -> Result<Record, RepositoryFailure> {
        Record::decode(
            bytes,
            self.target.commitment(),
            self.upload_authenticator()?,
            id,
        )
    }
    async fn read_record(
        &self,
        id: UploadId,
    ) -> Result<Option<(Record, String)>, RepositoryFailure> {
        match self
            .read_key(&self.key(&id.name()), "", MAX_OBJECT_BYTES as usize + 65536)
            .await
        {
            Ok((bytes, meta)) => Ok(Some((self.decode_record(bytes, id)?, meta.etag))),
            Err(RepositoryFailure::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn staging_key(&self, record: &Record) -> String {
        let selector = record
            .selector
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        self.key(&format!("m-{selector}"))
    }
    async fn write_record(
        &self,
        record: &Record,
        etag: Option<&str>,
    ) -> Result<String, RepositoryFailure> {
        self.write_key(
            &self.key(&record.plan.id().name()),
            self.encode_record(record)?,
            etag,
        )
        .await
    }
    async fn native_upload(&self, record: &Record) -> Result<(), RepositoryFailure> {
        let key = self.staging_key(record);
        match self.read_key(&key, "", MAX_OBJECT_BYTES as usize).await {
            Ok((bytes, _)) => {
                return if bytes == record.bytes {
                    Ok(())
                } else {
                    Err(RepositoryFailure::ChecksumMismatch)
                };
            },
            Err(RepositoryFailure::NotFound) => {},
            Err(e) => return Err(e),
        }
        let mut blocks = Vec::new();
        for (index, chunk) in record.bytes.chunks(MAX_RANGE_BYTES as usize).enumerate() {
            let mut id = Vec::from((index as u64).to_be_bytes());
            id.extend_from_slice(&Sha256::digest(chunk));
            blocks.push((STANDARD.encode(id), chunk));
        }
        let response = self
            .request(
                Method::GET,
                format!("{}?comp=blocklist&blocklisttype=all", self.url(&key)),
                HeaderMap::new(),
                Vec::new(),
                131072,
            )
            .await?;
        let mut existing = Vec::new();
        if response.status.is_success() {
            let root = protocol::xml(&response.body)?;
            if root.name != "BlockList" {
                return Err(RepositoryFailure::CorruptState);
            }
            for group in &root.children {
                if !matches!(group.name.as_str(), "CommittedBlocks" | "UncommittedBlocks") {
                    return Err(RepositoryFailure::CorruptState);
                }
                for block in &group.children {
                    if block.name != "Block" {
                        return Err(RepositoryFailure::CorruptState);
                    }
                    let name = &block.required("Name")?.text;
                    let size = block
                        .required("Size")?
                        .text
                        .parse::<usize>()
                        .map_err(|_| RepositoryFailure::CorruptState)?;
                    if !blocks
                        .iter()
                        .any(|(id, bytes)| id == name && bytes.len() == size)
                        || existing.contains(name)
                    {
                        return Err(RepositoryFailure::CorruptState);
                    }
                    existing.push(name.clone());
                }
            }
        } else if response.status.as_u16() != 404 {
            return Err(protocol::failure(&response, false));
        }
        for (id, chunk) in &blocks {
            if existing.contains(id) {
                continue;
            }
            let mut headers = HeaderMap::new();
            headers.insert(
                "content-md5",
                HeaderValue::from_str(&protocol::md5(chunk))
                    .map_err(|_| RepositoryFailure::InvalidInput)?,
            );
            let reply = self
                .checked(
                    Method::PUT,
                    format!(
                        "{}?comp=block&blockid={}",
                        self.url(&key),
                        protocol::escape(id)
                    ),
                    headers,
                    chunk.to_vec(),
                    131072,
                )
                .await?;
            if protocol::header(&reply.headers, "content-md5")? != protocol::md5(chunk) {
                return Err(RepositoryFailure::ChecksumMismatch);
            }
        }
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>");
        for (id, _) in &blocks {
            xml.push_str(&format!("<Latest>{id}</Latest>"))
        }
        xml.push_str("</BlockList>");
        let mut headers = Self::condition(None)?;
        headers.insert(
            "content-md5",
            HeaderValue::from_str(&protocol::md5(xml.as_bytes()))
                .map_err(|_| RepositoryFailure::InvalidInput)?,
        );
        headers.insert(
            "x-ms-blob-content-md5",
            HeaderValue::from_str(&protocol::md5(&record.bytes))
                .map_err(|_| RepositoryFailure::InvalidInput)?,
        );
        match self
            .checked(
                Method::PUT,
                format!("{}?comp=blocklist", self.url(&key)),
                headers,
                xml.into_bytes(),
                131072,
            )
            .await
        {
            Ok(_)
            | Err(RepositoryFailure::OutcomeUnknown | RepositoryFailure::PreconditionFailed) => {},
            Err(e) => return Err(e),
        }
        let (bytes, _) = self.read_key(&key, "", MAX_OBJECT_BYTES as usize).await?;
        if bytes != record.bytes {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        Ok(())
    }
    async fn cleanup_upload(&self, id: UploadId) -> Result<DeleteOutcome, RepositoryFailure> {
        let mut marker = None;
        let mut records = Vec::new();
        for _ in 0..4 {
            let page = self
                .inventory(&self.key(&id.name()), marker.as_deref(), 64, true)
                .await?;
            for item in page.items {
                if item.name != self.key(&id.name()) {
                    continue;
                }
                if item.deleted {
                    return Err(RepositoryFailure::OutcomeUnknown);
                }
                match self
                    .read_key(
                        &item.name,
                        &item.selector,
                        MAX_OBJECT_BYTES as usize + 65536,
                    )
                    .await
                {
                    Ok((bytes, _)) => {
                        let mut record = self.decode_record(bytes, id)?;
                        record.bytes = Vec::new();
                        records.push(record)
                    },
                    Err(RepositoryFailure::NotFound) => {},
                    Err(e) => return Err(e),
                }
            }
            marker = page.next;
            if marker.is_none() {
                break;
            }
        }
        if marker.is_some() {
            return Err(RepositoryFailure::LimitExceeded);
        }
        if let Some((mut record, _)) = self.read_record(id).await? {
            record.bytes = Vec::new();
            records.push(record)
        }
        let mut selectors = Vec::new();
        for record in &records {
            if selectors.contains(&record.selector) {
                continue;
            }
            selectors.push(record.selector);
            let key = self.staging_key(record);
            match self.read_key(&key, "", MAX_OBJECT_BYTES as usize).await {
                Ok((bytes, _)) => {
                    if bytes.len() as u64 != record.plan.size
                        || <[u8; 32]>::from(Sha256::digest(&bytes)) != record.plan.object.checksum()
                    {
                        return Err(RepositoryFailure::ChecksumMismatch);
                    }
                    self.purge_key(&key, Proof::Object(record.plan.object))
                        .await?;
                },
                Err(RepositoryFailure::NotFound) => {
                    match self
                        .checked(
                            Method::DELETE,
                            self.url(&key),
                            HeaderMap::new(),
                            Vec::new(),
                            131072,
                        )
                        .await
                    {
                        Ok(_) | Err(RepositoryFailure::NotFound) => {},
                        Err(e) => return Err(e),
                    }
                    let reply = self
                        .request(
                            Method::GET,
                            format!("{}?comp=blocklist&blocklisttype=all", self.url(&key)),
                            HeaderMap::new(),
                            Vec::new(),
                            131072,
                        )
                        .await?;
                    if reply.status.as_u16() != 404 {
                        return Err(RepositoryFailure::OutcomeUnknown);
                    }
                    let page = self.inventory(&key, None, 1, true).await?;
                    if !page.items.is_empty() || page.next.is_some() {
                        return Err(RepositoryFailure::OutcomeUnknown);
                    }
                },
                Err(e) => return Err(e),
            }
        }
        self.purge_key(&self.key(&id.name()), Proof::Upload(id))
            .await
    }
    async fn finish(&self, record: Record) -> Result<PutOutcome, RepositoryFailure> {
        let id = record.plan.object;
        match self.read_object(id).await {
            Ok((bytes, _)) => {
                if bytes.len() as u64 != record.plan.size {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
                self.cleanup_upload(record.plan.id()).await?;
                return Ok(PutOutcome::AlreadyPresent);
            },
            Err(RepositoryFailure::NotFound) => {},
            Err(e) => return Err(e),
        }
        self.native_upload(&record).await?;
        match self
            .write_key(&self.key(&id.name()), record.bytes.clone(), None)
            .await
        {
            Ok(_) => {},
            Err(RepositoryFailure::OutcomeUnknown | RepositoryFailure::PreconditionFailed) => {
                self.read_object(id).await?;
            },
            Err(e) => return Err(e),
        }
        self.cleanup_upload(record.plan.id()).await?;
        Ok(PutOutcome::Created)
    }
    pub async fn begin_upload(&self, plan: UploadPlan) -> Result<UploadState, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        match self.read_object(plan.object).await {
            Ok((bytes, _)) => {
                if bytes.len() as u64 != plan.size {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
                self.cleanup_upload(plan.id()).await?;
                return Ok(UploadState {
                    plan,
                    written: plan.size,
                    checksum: plan.object.checksum(),
                });
            },
            Err(RepositoryFailure::NotFound) => {},
            Err(e) => return Err(e),
        }
        if let Some((record, _)) = self.read_record(plan.id()).await? {
            let state = record.state();
            if state.complete() {
                self.finish(record).await?;
            }
            return Ok(state);
        }
        let mut selector = [0; 16];
        getrandom::fill(&mut selector).map_err(|_| RepositoryFailure::StorageUnavailable)?;
        if selector == [0; 16] {
            return Err(RepositoryFailure::StorageUnavailable);
        }
        let record = Record {
            plan,
            selector,
            bytes: Vec::new(),
        };
        match self.write_record(&record, None).await {
            Ok(_) => Ok(record.state()),
            Err(RepositoryFailure::OutcomeUnknown | RepositoryFailure::PreconditionFailed) => self
                .read_record(plan.id())
                .await?
                .map(|(r, _)| r.state())
                .ok_or(RepositoryFailure::OutcomeUnknown),
            Err(e) => Err(e),
        }
    }
    pub async fn inspect_upload(
        &self,
        id: UploadId,
    ) -> Result<Option<UploadState>, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        self.read_record(id)
            .await
            .map(|v| v.map(|(r, _)| r.state()))
    }
    pub async fn resume_upload(
        &self,
        part: UploadPart,
    ) -> Result<UploadOutcome, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        let Some((mut record, etag)) = self.read_record(part.state.id()).await? else {
            let (bytes, _) = self.read_object(part.state.object()).await?;
            if bytes.len() as u64 != part.state.total_size() {
                return Err(RepositoryFailure::ChecksumMismatch);
            }
            return Ok(UploadOutcome::Complete(PutOutcome::AlreadyPresent));
        };
        if record.plan != part.state.plan {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let start = part.state.written as usize;
        let end = start
            .checked_add(part.bytes.len())
            .ok_or(RepositoryFailure::LimitExceeded)?;
        if <[u8; 32]>::from(Sha256::digest(
            record
                .bytes
                .get(..start)
                .ok_or(RepositoryFailure::PreconditionFailed)?,
        )) != part.state.checksum
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        if end <= record.bytes.len() {
            if record.bytes.get(start..end) != Some(part.bytes.as_slice()) {
                return Err(RepositoryFailure::PreconditionFailed);
            }
        } else {
            if start != record.bytes.len() {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            record.bytes.extend_from_slice(&part.bytes);
            if record.state().complete() && record.state().checksum != record.plan.object.checksum()
            {
                return Err(RepositoryFailure::ChecksumMismatch);
            }
            self.write_record(&record, Some(&etag)).await?;
        }
        let state = record.state();
        if state.complete() {
            self.finish(record).await.map(UploadOutcome::Complete)
        } else {
            Ok(UploadOutcome::Pending(state))
        }
    }
    pub async fn abort_upload(&self, id: UploadId) -> Result<DeleteOutcome, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        self.cleanup_upload(id).await
    }
}

#[cfg(fuzzing)]
pub(super) fn fuzz_frame(data: &[u8]) {
    let custody = positron_kernel::RepositoryUploadAuthenticator::new(
        positron_kernel::CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
        positron_kernel::InstanceId::new([2; 16]).expect("fixed instance"),
    );
    let id = UploadId([1; 32]);
    let _ = Record::decode(data.to_vec(), [1; 32], &custody, id);
    if data.len() <= 131073 {
        let payload = if data.is_empty() {
            b"seed".as_slice()
        } else {
            data
        };
        let checksum: [u8; 32] = Sha256::digest(payload).into();
        let control = data.first().copied().unwrap_or(0);
        let size = payload.len() as u64 + u64::from(control & 3);
        if let Ok(plan) = UploadPlan::new(ObjectId::from_checksum(checksum), size) {
            let mut frame = b"POSAZU01".to_vec();
            frame.extend_from_slice(&[1; 32]);
            frame.extend_from_slice(&checksum);
            frame.extend_from_slice(&size.to_be_bytes());
            frame.extend_from_slice(&[if control & 8 == 0 { 9 } else { 0 }; 16]);
            frame.extend_from_slice(payload);
            if control & 4 != 0 {
                if let Some(value) = frame.get_mut(8) {
                    *value ^= 1;
                }
            }
            if let Ok(auth) = custody.authenticate(Sha256::digest(&frame).into()) {
                frame.extend_from_slice(&auth.epoch().to_be_bytes());
                frame.extend_from_slice(&auth.tag());
                let _ = Record::decode(frame, [1; 32], &custody, plan.id());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn custody() -> positron_kernel::RepositoryUploadAuthenticator {
        positron_kernel::RepositoryUploadAuthenticator::new(
            positron_kernel::CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
            positron_kernel::InstanceId::new([2; 16]).expect("instance"),
        )
    }
    fn frame(bytes: &[u8], plan: UploadPlan) -> Vec<u8> {
        let mut frame = b"POSAZU01".to_vec();
        frame.extend_from_slice(&[1; 32]);
        frame.extend_from_slice(&plan.object.checksum());
        frame.extend_from_slice(&plan.size.to_be_bytes());
        frame.extend_from_slice(&[9; 16]);
        frame.extend_from_slice(bytes);
        let auth = custody()
            .authenticate(Sha256::digest(&frame).into())
            .expect("auth");
        frame.extend_from_slice(&auth.epoch().to_be_bytes());
        frame.extend_from_slice(&auth.tag());
        frame
    }
    #[test]
    fn persisted_upload_binds_target_plan_payload_and_kernel_custody() {
        let bytes = b"encrypted input";
        let object = ImmutableObject::new(bytes.to_vec()).expect("object");
        let plan = UploadPlan::new(object.id(), bytes.len() as u64).expect("plan");
        let encoded = frame(bytes, plan);
        let record =
            Record::decode(encoded.clone(), [1; 32], &custody(), plan.id()).expect("frame");
        assert!(record.state().complete());
        assert_eq!(record.bytes, bytes);
        assert_eq!(
            Record::decode(encoded.clone(), [2; 32], &custody(), plan.id()).err(),
            Some(RepositoryFailure::IdentityMismatch)
        );
        assert_eq!(
            Record::decode(encoded.clone(), [1; 32], &custody(), UploadId([8; 32])).err(),
            Some(RepositoryFailure::CorruptState)
        );
        let mut altered = encoded;
        *altered.last_mut().expect("MAC") ^= 1;
        assert_eq!(
            Record::decode(altered, [1; 32], &custody(), plan.id()).err(),
            Some(RepositoryFailure::ChecksumMismatch)
        );
        assert_eq!(
            Record::decode(
                frame(b"wrong ciphertext", plan),
                [1; 32],
                &custody(),
                plan.id()
            )
            .err(),
            Some(RepositoryFailure::CorruptState)
        );
        let wrong_payload = vec![0; bytes.len()];
        assert_eq!(
            Record::decode(frame(&wrong_payload, plan), [1; 32], &custody(), plan.id()).err(),
            Some(RepositoryFailure::ChecksumMismatch)
        );
    }
}
