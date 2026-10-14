#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalFaultPoint {
    BeforeObjectPublication,
    AfterObjectPublication,
    BeforeUploadPublication,
    AfterUploadPublication,
    BeforeRegistryPublication,
    AfterRegistryPublication,
    BeforeDeletion,
    AfterDeletion,
}
#[cfg(feature = "test-support")]
pub type LocalFaultEffect = crate::fault::FaultEffect;
#[cfg(feature = "test-support")]
pub type LocalFault = crate::fault::Fault<LocalFaultPoint>;
pub(super) type Controller = crate::fault::Controller<LocalFaultPoint>;
