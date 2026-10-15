use super::{AwsS3Repository, failure, validate_bucket_region};
use crate::{RepositoryFailure, RepositoryIdentity};
use tokio::io::AsyncReadExt;
use tracing::instrument::WithSubscriber;

impl AwsS3Repository {
    pub(super) async fn check_bucket(&self) -> Result<(), RepositoryFailure> {
        let observed = self
            .client
            .head_bucket()
            .bucket(self.target.bucket())
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        validate_bucket_region(&self.target, observed.bucket_region())
    }
    pub(super) fn identity_key(&self) -> String {
        format!("{}identity", self.target.prefix())
    }
    pub(super) async fn read_identity(&self) -> Result<RepositoryIdentity, RepositoryFailure> {
        let observed = self
            .client
            .get_object()
            .bucket(self.target.bucket())
            .key(self.identity_key())
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        if observed
            .content_length()
            .is_some_and(|length| length != 108)
        {
            return Err(RepositoryFailure::CorruptState);
        }
        let mut bytes = Vec::with_capacity(109);
        observed
            .body
            .into_async_read()
            .take(109)
            .read_to_end(&mut bytes)
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|_| RepositoryFailure::StorageUnavailable)?;
        let identity = RepositoryIdentity::decode(&bytes)?;
        if identity != self.identity {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        Ok(identity)
    }
    /// Verifies the native bucket owner and immutable target binding.
    pub async fn attach(&self) -> Result<RepositoryIdentity, RepositoryFailure> {
        let _operation = self.enter()?;
        self.check_bucket().await?;
        self.read_identity().await
    }
    /// Publishes Identity once in an operator-owned empty prefix. Conditional
    /// publication is authoritative; discovery never authorizes replacement.
    pub async fn initialize(&self) -> Result<RepositoryIdentity, RepositoryFailure> {
        let _operation = self.enter()?;
        self.check_bucket().await?;
        match self.read_identity().await {
            Ok(identity) => return Ok(identity),
            Err(RepositoryFailure::NotFound) => {},
            Err(error) => return Err(error),
        }
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
        validate_empty_prefix(
            objects.contents().len(),
            objects.is_truncated(),
            uploads.uploads().len(),
            uploads.is_truncated(),
        )?;
        // Current object listing cannot see versions hidden by delete markers.
        // One complete empty page proves emptiness; any history refuses adoption.
        let history = self
            .client
            .list_object_versions()
            .bucket(self.target.bucket())
            .prefix(self.target.prefix())
            .max_keys(1)
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        validate_empty_history(&history)?;
        let result = self
            .client
            .put_object()
            .bucket(self.target.bucket())
            .key(self.identity_key())
            .expected_bucket_owner(self.target.expected_owner())
            .if_none_match("*")
            .checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Sha256)
            .body(aws_sdk_s3::primitives::ByteStream::from(
                self.identity.encode(),
            ))
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map(|_| ())
            .map_err(|error| failure::sdk(error, true));
        match result {
            Ok(())
            | Err(RepositoryFailure::PreconditionFailed | RepositoryFailure::OutcomeUnknown) => {
                reconcile_publication(result, self.read_identity().await)
            },
            Err(error) => Err(error),
        }
    }
}

/// A missing observation cannot disprove an acknowledged or uncertain write.
fn reconcile_publication(
    publication: Result<(), RepositoryFailure>,
    observed: Result<RepositoryIdentity, RepositoryFailure>,
) -> Result<RepositoryIdentity, RepositoryFailure> {
    match (publication, observed) {
        (
            Ok(()) | Err(RepositoryFailure::OutcomeUnknown),
            Err(
                RepositoryFailure::NotFound
                | RepositoryFailure::StorageUnavailable
                | RepositoryFailure::Interrupted
                | RepositoryFailure::LimitExceeded,
            ),
        ) => Err(RepositoryFailure::OutcomeUnknown),
        (Err(RepositoryFailure::PreconditionFailed), Err(RepositoryFailure::NotFound)) => {
            Err(RepositoryFailure::Busy)
        },
        (
            Ok(()) | Err(RepositoryFailure::OutcomeUnknown | RepositoryFailure::PreconditionFailed),
            observed,
        ) => observed,
        (Err(failure), _) => Err(failure),
    }
}

pub(super) fn validate_empty_prefix(
    objects: usize,
    object_truncated: Option<bool>,
    uploads: usize,
    upload_truncated: Option<bool>,
) -> Result<(), RepositoryFailure> {
    match (object_truncated, upload_truncated) {
        (Some(false), Some(false)) if objects == 0 && uploads == 0 => Ok(()),
        (None, _) | (_, None) => Err(RepositoryFailure::CorruptState),
        _ => Err(RepositoryFailure::ForeignPrefix),
    }
}

fn validate_empty_history(
    history: &aws_sdk_s3::operation::list_object_versions::ListObjectVersionsOutput,
) -> Result<(), RepositoryFailure> {
    if !history.versions().is_empty() || !history.delete_markers().is_empty() {
        return Err(RepositoryFailure::ForeignPrefix);
    }
    match history.is_truncated() {
        Some(false) => Ok(()),
        Some(true) => Err(RepositoryFailure::ForeignPrefix),
        None => Err(RepositoryFailure::CorruptState),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uncertain_identity_publication_requires_exact_recovery_evidence() {
        assert_eq!(
            super::reconcile_publication(
                Err(RepositoryFailure::OutcomeUnknown),
                Err(RepositoryFailure::NotFound)
            ),
            Err(RepositoryFailure::OutcomeUnknown)
        );
        assert_eq!(
            super::reconcile_publication(Ok(()), Err(RepositoryFailure::NotFound)),
            Err(RepositoryFailure::OutcomeUnknown)
        );
        assert_eq!(
            super::reconcile_publication(
                Err(RepositoryFailure::PreconditionFailed),
                Err(RepositoryFailure::NotFound)
            ),
            Err(RepositoryFailure::Busy)
        );
        let target = crate::AwsS3Target::new(
            "positron-example",
            "us-east-1",
            "https://s3.us-east-1.amazonaws.com",
            "123456789012",
            "owned/",
        )
        .expect("target");
        let identity =
            RepositoryIdentity::aws_s3([1; 16], [2; 16], [3; 32], &target).expect("identity");
        assert_eq!(
            super::reconcile_publication(
                Err(RepositoryFailure::OutcomeUnknown),
                Ok(identity.clone())
            ),
            Ok(identity)
        );
        assert_eq!(
            super::reconcile_publication(
                Err(RepositoryFailure::OutcomeUnknown),
                Err(RepositoryFailure::IdentityMismatch)
            ),
            Err(RepositoryFailure::IdentityMismatch)
        );
    }
}

#[cfg(test)]
mod listing_tests {
    use super::*;
    #[test]
    fn hidden_foreign_versions_and_delete_markers_refuse_identity_publication() {
        use aws_sdk_s3::{
            operation::list_object_versions::ListObjectVersionsOutput,
            types::{DeleteMarkerEntry, ObjectVersion},
        };
        // The old current-only preflight admits this snapshot.
        assert_eq!(
            validate_empty_prefix(0, Some(false), 0, Some(false)),
            Ok(())
        );
        let hidden_version = ListObjectVersionsOutput::builder()
            .is_truncated(false)
            .versions(
                ObjectVersion::builder()
                    .key("owned/foreign")
                    .version_id("historical")
                    .build(),
            )
            .build();
        assert_eq!(
            validate_empty_history(&hidden_version),
            Err(RepositoryFailure::ForeignPrefix)
        );
        let marker = ListObjectVersionsOutput::builder()
            .is_truncated(false)
            .delete_markers(
                DeleteMarkerEntry::builder()
                    .key("owned/foreign")
                    .version_id("marker")
                    .build(),
            )
            .build();
        assert_eq!(
            validate_empty_history(&marker),
            Err(RepositoryFailure::ForeignPrefix)
        );
        assert_eq!(
            validate_empty_history(&ListObjectVersionsOutput::builder().build()),
            Err(RepositoryFailure::CorruptState)
        );
        assert_eq!(
            validate_empty_history(
                &ListObjectVersionsOutput::builder()
                    .is_truncated(true)
                    .build()
            ),
            Err(RepositoryFailure::ForeignPrefix)
        );
        assert_eq!(
            validate_empty_history(
                &ListObjectVersionsOutput::builder()
                    .is_truncated(false)
                    .build()
            ),
            Ok(())
        );
    }
    #[test]
    fn incomplete_prefix_observations_cannot_authorize_initialization() {
        assert_eq!(
            validate_empty_prefix(0, None, 0, Some(false)),
            Err(RepositoryFailure::CorruptState)
        );
        assert_eq!(
            validate_empty_prefix(0, Some(false), 0, None),
            Err(RepositoryFailure::CorruptState)
        );
        assert_eq!(
            validate_empty_prefix(0, Some(true), 0, Some(false)),
            Err(RepositoryFailure::ForeignPrefix)
        );
        assert_eq!(
            validate_empty_prefix(1, Some(false), 0, Some(false)),
            Err(RepositoryFailure::ForeignPrefix)
        );
        assert_eq!(
            validate_empty_prefix(0, Some(false), 0, Some(false)),
            Ok(())
        );
    }
}
