//! Managed-code interruption windows; these do not simulate AWS responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsS3FaultPoint {
    BeforeRecordPublication,
    AfterRecordPublication,
    BeforeNativeCreation,
    AfterNativeCreation,
    BeforeNativeCompletion,
    AfterNativeCompletion,
    BeforeObjectPublication,
    AfterObjectPublication,
    BeforeRegistryPublication,
    AfterRegistryPublication,
    BeforeDeletion,
    AfterDeletion,
}
#[cfg(feature = "test-support")]
pub type AwsS3Fault = crate::fault::Fault<AwsS3FaultPoint>;
#[cfg(feature = "test-support")]
pub type AwsS3FaultEffect = crate::fault::FaultEffect;
pub(super) type Controller = crate::fault::Controller<AwsS3FaultPoint>;
