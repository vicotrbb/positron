use super::Record;
use crate::google_cloud_storage::{GoogleCloudStorageRepository, protocol};
use crate::*;
use http::{HeaderMap, HeaderValue, Method};
impl GoogleCloudStorageRepository {
    pub(in crate::google_cloud_storage) fn staging_key(&self, record: &Record) -> String {
        let nonce = record
            .selector
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        self.key(&format!("m-{nonce}"))
    }
    pub(in crate::google_cloud_storage) async fn native_upload(
        &self,
        record: &mut Record,
        generation: &mut u64,
    ) -> Result<(), RepositoryFailure> {
        let key = self.staging_key(record);
        match self.read_key(&key, None, MAX_OBJECT_BYTES as usize).await {
            Ok((bytes, _)) => {
                if bytes.as_slice() != record.bytes.as_slice() {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
                return Ok(());
            },
            Err(RepositoryFailure::NotFound) => {},
            Err(e) => return Err(e),
        }
        if record.session.is_none() {
            if record.requested {
                return Err(RepositoryFailure::OutcomeUnknown);
            }
            record.requested = true;
            *generation = self.write_record(record, *generation).await?;
            self.faults.at(
                crate::google_cloud_storage::GoogleCloudStorageFaultPoint::BeforeNativeCreate,
            )?;
            let body = serde_json::to_vec(&serde_json::json!({"name":key}))
                .map_err(|_| RepositoryFailure::CorruptState)?;
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            headers.insert(
                "x-upload-content-length",
                HeaderValue::from_str(&record.plan.size.to_string())
                    .map_err(|_| RepositoryFailure::InvalidInput)?,
            );
            headers.insert(
                "x-upload-content-type",
                HeaderValue::from_static("application/octet-stream"),
            );
            let url = format!(
                "https://storage.googleapis.com/upload/storage/v1/b/{}/o?uploadType=resumable&ifGenerationMatch=0",
                self.target.bucket()
            );
            let reply = self
                .checked(Method::POST, url, headers, body, 131072)
                .await?;
            let session = reply
                .headers
                .get(http::header::LOCATION)
                .and_then(|h| h.to_str().ok())
                .ok_or(RepositoryFailure::OutcomeUnknown)?;
            protocol::session(session, self.target.bucket())?;
            self.faults
                .at(crate::google_cloud_storage::GoogleCloudStorageFaultPoint::AfterNativeCreate)?;
            record.session = Some(
                self.upload_authenticator
                    .seal_session(session.as_bytes())
                    .map_err(|_| RepositoryFailure::StorageUnavailable)?,
            );
            *generation = self.write_record(record, *generation).await?;
        }
        let sealed = record
            .session
            .as_ref()
            .ok_or(RepositoryFailure::OutcomeUnknown)?;
        let plaintext = self
            .upload_authenticator
            .open_session(sealed)
            .map_err(|_| RepositoryFailure::ChecksumMismatch)?;
        let session =
            std::str::from_utf8(&plaintext).map_err(|_| RepositoryFailure::CorruptState)?;
        protocol::session(session, self.target.bucket())?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes */{}", record.plan.size))
                .map_err(|_| RepositoryFailure::InvalidInput)?,
        );
        let status = self
            .request(Method::PUT, session.to_owned(), headers, Vec::new(), 131072)
            .await?;
        let mut offset = match status.status.as_u16() {
            200 | 201 => record.plan.size,
            308 => protocol::uploaded(
                status
                    .headers
                    .get(http::header::RANGE)
                    .and_then(|v| v.to_str().ok()),
                record.plan.size,
            )?,
            404 | 410 => return Err(RepositoryFailure::OutcomeUnknown),
            _ => {
                return Err(crate::google_cloud_storage::http::response_failure(
                    &status, true,
                ));
            },
        };
        for _ in 0..16 {
            if offset == record.plan.size {
                break;
            }
            let end = (offset + 4 * 1024 * 1024).min(record.plan.size);
            let bytes = record
                .bytes
                .get(offset as usize..end as usize)
                .ok_or(RepositoryFailure::CorruptState)?
                .to_vec();
            let mut headers = Self::data_headers();
            headers.insert(
                http::header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {offset}-{}/{}", end - 1, record.plan.size))
                    .map_err(|_| RepositoryFailure::InvalidInput)?,
            );
            let reply = self
                .request(Method::PUT, session.to_owned(), headers, bytes, 131072)
                .await?;
            let next = match reply.status.as_u16() {
                200 | 201 => record.plan.size,
                308 => protocol::uploaded(
                    reply
                        .headers
                        .get(http::header::RANGE)
                        .and_then(|v| v.to_str().ok()),
                    record.plan.size,
                )?,
                _ => {
                    return Err(crate::google_cloud_storage::http::response_failure(
                        &reply, true,
                    ));
                },
            };
            if next <= offset || next > end {
                return Err(RepositoryFailure::CorruptState);
            }
            offset = next;
        }
        if offset != record.plan.size {
            return Err(RepositoryFailure::LimitExceeded);
        }
        self.faults
            .at(crate::google_cloud_storage::GoogleCloudStorageFaultPoint::AfterNativeComplete)?;
        let (bytes, _) = self.read_key(&key, None, MAX_OBJECT_BYTES as usize).await?;
        if bytes != record.bytes {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        Ok(())
    }
    pub(in crate::google_cloud_storage) async fn cancel_session(
        &self,
        record: &Record,
    ) -> Result<(), RepositoryFailure> {
        let Some(sealed) = &record.session else {
            return if record.requested {
                Err(RepositoryFailure::OutcomeUnknown)
            } else {
                Ok(())
            };
        };
        let plaintext = self
            .upload_authenticator
            .open_session(sealed)
            .map_err(|_| RepositoryFailure::ChecksumMismatch)?;
        let session =
            std::str::from_utf8(&plaintext).map_err(|_| RepositoryFailure::CorruptState)?;
        protocol::session(session, self.target.bucket())?;
        let reply = self
            .request(
                Method::DELETE,
                session.to_owned(),
                HeaderMap::new(),
                Vec::new(),
                131072,
            )
            .await?;
        match reply.status.as_u16() {
            200 | 204 | 404 | 410 | 499 => Ok(()),
            _ => Err(crate::google_cloud_storage::http::response_failure(
                &reply, true,
            )),
        }
    }
}
