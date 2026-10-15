use super::{AwsS3Repository, failure};
pub(super) use crate::listing::native_cursor::State;
use crate::listing::native_cursor::checksum_name;
use crate::{ListEntry, ListKind, ListPage, ListRequest, ObjectId, RepositoryFailure, UploadId};
use tracing::instrument::WithSubscriber;
impl AwsS3Repository {
    pub async fn list(&self, request: ListRequest) -> Result<ListPage, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        let token = self
            .listing
            .try_lock()
            .map_err(|_| RepositoryFailure::Busy)?
            .take(self.identity.repository_id(), &request)?;
        let prefix = format!(
            "{}{}",
            self.target.prefix(),
            match request.kind {
                ListKind::Objects => "o-",
                ListKind::Uploads => "u-",
            }
        );
        let response = self
            .client
            .list_objects_v2()
            .bucket(self.target.bucket())
            .prefix(&prefix)
            .expected_bucket_owner(self.target.expected_owner())
            .max_keys(i32::from(request.limit))
            .set_continuation_token(token)
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        if response.contents().len() > usize::from(request.limit) {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut entries = Vec::with_capacity(response.contents().len());
        for object in response.contents() {
            let suffix = object
                .key()
                .and_then(|key| key.strip_prefix(&prefix))
                .ok_or(RepositoryFailure::CorruptState)?;
            let checksum = checksum_name(suffix)?;
            entries.push(match request.kind {
                ListKind::Objects => ListEntry::Object(ObjectId::from_checksum(checksum)),
                ListKind::Uploads => ListEntry::Upload(UploadId(checksum)),
            });
        }
        let next_token = match response.is_truncated() {
            Some(false) => None,
            Some(true) => Some(
                response
                    .next_continuation_token()
                    .filter(|token| !token.is_empty() && token.len() <= 4096)
                    .ok_or(RepositoryFailure::CorruptState)?
                    .to_owned(),
            ),
            None => return Err(RepositoryFailure::CorruptState),
        };
        let mut state = self
            .listing
            .try_lock()
            .map_err(|_| RepositoryFailure::Busy)?;
        state.consume(self.identity.repository_id(), &request)?;
        let next = next_token
            .map(|token| state.store(self.identity.repository_id(), request.kind, token))
            .transpose()?;
        Ok(ListPage { entries, next })
    }
}
