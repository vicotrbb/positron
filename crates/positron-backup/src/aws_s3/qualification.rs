//! Read-only preparation/preservation checks for explicitly authorized real tests.
use super::{AwsS3Repository, failure};
use crate::RepositoryFailure;
use sha2::{Digest, Sha256};
use tracing::instrument::WithSubscriber;
impl AwsS3Repository {
    /// Requires an externally prepared, authorized prefix with hidden history,
    /// no current objects/uploads/Identity, and at most sixteen native entries.
    /// Returns a scoped digest to compare exact version/marker preservation.
    pub async fn qualification_hidden_history_snapshot(
        &self,
    ) -> Result<[u8; 32], RepositoryFailure> {
        let _operation = self.enter()?;
        self.check_bucket().await?;
        let objects = self
            .client
            .list_objects_v2()
            .bucket(self.target.bucket())
            .prefix(self.target.prefix())
            .max_keys(1)
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        let uploads = self
            .client
            .list_multipart_uploads()
            .bucket(self.target.bucket())
            .prefix(self.target.prefix())
            .max_uploads(1)
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        super::identity::validate_empty_prefix(
            objects.contents().len(),
            objects.is_truncated(),
            uploads.uploads().len(),
            uploads.is_truncated(),
        )?;
        let history = self
            .client
            .list_object_versions()
            .bucket(self.target.bucket())
            .prefix(self.target.prefix())
            .max_keys(16)
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        history_snapshot(&history, self.target.prefix(), &self.identity_key())
    }
}
fn history_snapshot(
    history: &aws_sdk_s3::operation::list_object_versions::ListObjectVersionsOutput,
    prefix: &str,
    identity_key: &str,
) -> Result<[u8; 32], RepositoryFailure> {
    match history.is_truncated() {
        Some(false) => {},
        Some(true) => return Err(RepositoryFailure::LimitExceeded),
        None => return Err(RepositoryFailure::CorruptState),
    }
    if history.versions().is_empty() || history.delete_markers().is_empty() {
        return Err(RepositoryFailure::InvalidInput);
    }
    let mut rows = Vec::new();
    let entries = history
        .versions()
        .iter()
        .map(|value| (value.key(), value.version_id(), false))
        .chain(
            history
                .delete_markers()
                .iter()
                .map(|value| (value.key(), value.version_id(), true)),
        );
    for (key, id, marker) in entries {
        if rows.len() == 16 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let key = key
            .filter(|key| {
                key.len() <= 1024
                    && key.starts_with(prefix)
                    && *key != identity_key
                    && !key.chars().any(char::is_control)
            })
            .ok_or(RepositoryFailure::InvalidInput)?;
        let id = id
            .filter(|id| !id.is_empty() && id.len() <= 4096 && !id.chars().any(char::is_control))
            .ok_or(RepositoryFailure::CorruptState)?;
        rows.push((key.to_owned(), id.to_owned(), marker));
    }
    rows.sort_unstable();
    let mut digest = Sha256::new();
    digest.update(b"positron-qualified-hidden-history-v1");
    digest.update(prefix.as_bytes());
    for (key, id, marker) in rows {
        digest.update(
            u64::try_from(key.len())
                .map_err(|_| RepositoryFailure::LimitExceeded)?
                .to_be_bytes(),
        );
        digest.update(key.as_bytes());
        digest.update(
            u64::try_from(id.len())
                .map_err(|_| RepositoryFailure::LimitExceeded)?
                .to_be_bytes(),
        );
        digest.update(id.as_bytes());
        digest.update([u8::from(marker)]);
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::{
        operation::list_object_versions::ListObjectVersionsOutput,
        types::{DeleteMarkerEntry, ObjectVersion},
    };
    #[test]
    fn hidden_history_snapshot_requires_complete_bounded_foreign_rows() {
        let fixture = ListObjectVersionsOutput::builder()
            .is_truncated(false)
            .versions(
                ObjectVersion::builder()
                    .key("owned/foreign")
                    .version_id("original")
                    .build(),
            )
            .delete_markers(
                DeleteMarkerEntry::builder()
                    .key("owned/foreign")
                    .version_id("marker")
                    .build(),
            )
            .build();
        let original = history_snapshot(&fixture, "owned/", "owned/identity").expect("fixture");
        let changed = ListObjectVersionsOutput::builder()
            .is_truncated(false)
            .versions(
                ObjectVersion::builder()
                    .key("owned/foreign")
                    .version_id("replacement")
                    .build(),
            )
            .delete_markers(
                DeleteMarkerEntry::builder()
                    .key("owned/foreign")
                    .version_id("marker")
                    .build(),
            )
            .build();
        assert_ne!(
            history_snapshot(&changed, "owned/", "owned/identity").expect("changed"),
            original
        );
        assert!(
            history_snapshot(
                &ListObjectVersionsOutput::builder()
                    .is_truncated(true)
                    .build(),
                "owned/",
                "owned/identity"
            )
            .is_err()
        );
        assert!(history_snapshot(&fixture, "other/", "other/identity").is_err());
        assert!(history_snapshot(&fixture, "owned/", "owned/foreign").is_err());
    }
}
