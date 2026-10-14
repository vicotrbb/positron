//! Native input/format boundaries only; no AWS transport or service substitute.
use crate::{AwsS3Target, RepositoryIdentity};
pub fn fuzz_aws_s3_repository(data: &[u8]) {
    if data.len() > 8192 {
        return;
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(target) = AwsS3Target::decode_locator(text) {
            let canonical =
                AwsS3Target::decode_locator(&target.encode_locator()).expect("accepted target");
            assert_eq!(canonical.commitment(), target.commitment());
        }
    }
    if let Ok(identity) = RepositoryIdentity::decode(data) {
        assert_eq!(
            RepositoryIdentity::decode(&identity.encode()).expect("accepted identity"),
            identity
        );
    }
    super::upload::fuzz_record(data);
}
