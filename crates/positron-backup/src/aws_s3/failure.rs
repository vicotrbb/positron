use crate::RepositoryFailure;

pub(super) fn classify(
    status: u16,
    code: Option<&str>,
    retry: Option<&str>,
    mutating: bool,
) -> RepositoryFailure {
    // These are native service metadata codes, never formatted error messages.
    match (status, code) {
        (301 | 307, _) | (_, Some("PermanentRedirect" | "AuthorizationHeaderMalformed")) => {
            RepositoryFailure::IdentityMismatch
        },
        (401 | 403, _)
        | (_, Some("AccessDenied" | "InvalidAccessKeyId" | "ExpiredToken" | "InvalidToken")) => {
            RepositoryFailure::PermissionDenied
        },
        (_, Some("NoSuchBucket")) => RepositoryFailure::StorageUnavailable,
        (404, _) => RepositoryFailure::NotFound,
        (412, _) => RepositoryFailure::PreconditionFailed,
        (409, Some("ConditionalRequestConflict")) => RepositoryFailure::Busy,
        (_, Some("BadDigest" | "InvalidDigest")) => RepositoryFailure::ChecksumMismatch,
        (429, _) | (_, Some("SlowDown" | "Throttling" | "ThrottlingException")) => {
            RepositoryFailure::Throttled {
                retry_after_millis: retry
                    .and_then(|value| value.parse::<u64>().ok())
                    .map(|seconds| seconds.saturating_mul(1000).clamp(100, 60000) as u32)
                    .unwrap_or(500),
            }
        },
        (400, _) => RepositoryFailure::InvalidInput,
        _ if mutating => RepositoryFailure::OutcomeUnknown,
        _ => RepositoryFailure::StorageUnavailable,
    }
}
pub(super) fn sdk<E: aws_sdk_s3::error::ProvideErrorMetadata + std::error::Error + 'static>(
    error: aws_sdk_s3::error::SdkError<E>,
    mutating: bool,
) -> RepositoryFailure {
    if !mutating {
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        for _ in 0..8 {
            let Some(cause) = source else {
                break;
            };
            if cause.is::<http_body_util::LengthLimitError>()
                || cause.downcast_ref::<RepositoryFailure>()
                    == Some(&RepositoryFailure::LimitExceeded)
            {
                return RepositoryFailure::LimitExceeded;
            }
            source = cause.source();
        }
    }
    let status = error
        .raw_response()
        .map(|response| response.status().as_u16())
        .unwrap_or(0);
    let code = error.as_service_error().and_then(|error| error.code());
    let retry = error
        .raw_response()
        .and_then(|response| response.headers().get("retry-after"));
    classify(status, code, retry, mutating)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_failure_classes_preserve_unknown_publication_and_bounded_throttling() {
        assert_eq!(
            classify(403, Some("AccessDenied"), None, false),
            RepositoryFailure::PermissionDenied
        );
        assert_eq!(
            classify(404, Some("NoSuchKey"), None, false),
            RepositoryFailure::NotFound
        );
        assert_eq!(
            classify(404, Some("NoSuchBucket"), None, false),
            RepositoryFailure::StorageUnavailable
        );
        assert_eq!(
            classify(412, Some("PreconditionFailed"), None, true),
            RepositoryFailure::PreconditionFailed
        );
        assert_eq!(
            classify(409, Some("ConditionalRequestConflict"), None, true),
            RepositoryFailure::Busy
        );
        assert_eq!(
            classify(503, Some("SlowDown"), Some("999999"), false),
            RepositoryFailure::Throttled {
                retry_after_millis: 60000
            }
        );
        assert_eq!(
            classify(503, Some("SlowDown"), Some("secret response"), false),
            RepositoryFailure::Throttled {
                retry_after_millis: 500
            }
        );
        assert_eq!(
            classify(400, Some("BadDigest"), None, true),
            RepositoryFailure::ChecksumMismatch
        );
        assert_eq!(
            classify(500, None, None, true),
            RepositoryFailure::OutcomeUnknown
        );
        assert_eq!(
            classify(500, None, None, false),
            RepositoryFailure::StorageUnavailable
        );
        assert_eq!(
            classify(301, Some("PermanentRedirect"), None, false),
            RepositoryFailure::IdentityMismatch
        );
    }
}
