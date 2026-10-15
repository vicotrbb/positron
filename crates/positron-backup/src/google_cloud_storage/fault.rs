#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoogleCloudStorageFaultPoint {
    BeforeRequest,
    BeforeNativeCreate,
    AfterNativeCreate,
    AfterNativeComplete,
    BeforeFinalPublication,
    AfterDeletion,
    AfterVersionDeletion,
}
#[cfg(feature = "test-support")]
pub type GoogleCloudStorageFault = crate::fault::Fault<GoogleCloudStorageFaultPoint>;
#[cfg(feature = "test-support")]
pub use crate::fault::FaultEffect as GoogleCloudStorageFaultEffect;
pub(super) type Controller = crate::fault::Controller<GoogleCloudStorageFaultPoint>;
