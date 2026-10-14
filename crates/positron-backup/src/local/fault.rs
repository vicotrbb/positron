use crate::RepositoryFailure;
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalFaultEffect {
    Interrupted,
    OutcomeUnknown,
    Throttled { retry_after_millis: u32 },
}
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalFault {
    point: LocalFaultPoint,
    effect: LocalFaultEffect,
    remaining: u32,
}
#[cfg(feature = "test-support")]
impl LocalFault {
    pub const fn new(
        point: LocalFaultPoint,
        effect: LocalFaultEffect,
        preceding_occurrences: u32,
    ) -> Self {
        Self {
            point,
            effect,
            remaining: preceding_occurrences,
        }
    }
}
#[derive(Clone, Default)]
pub(super) struct Controller {
    #[cfg(feature = "test-support")]
    schedule: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<LocalFault>>>,
}
impl Controller {
    #[cfg(feature = "test-support")]
    pub(super) fn new(schedule: Vec<LocalFault>) -> Result<Self, RepositoryFailure> {
        if schedule.len() > 32 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        Ok(Self {
            schedule: std::sync::Arc::new(std::sync::Mutex::new(schedule.into())),
        })
    }
    pub(super) fn at(&self, point: LocalFaultPoint) -> Result<(), RepositoryFailure> {
        #[cfg(feature = "test-support")]
        {
            let mut schedule = self
                .schedule
                .try_lock()
                .map_err(|_| RepositoryFailure::Busy)?;
            if let Some(fault) = schedule.front_mut()
                && fault.point == point
            {
                if fault.remaining > 0 {
                    fault.remaining -= 1;
                    return Ok(());
                }
                let effect = fault.effect;
                schedule.pop_front();
                return Err(match effect {
                    LocalFaultEffect::Interrupted => RepositoryFailure::Interrupted,
                    LocalFaultEffect::OutcomeUnknown => RepositoryFailure::OutcomeUnknown,
                    LocalFaultEffect::Throttled { retry_after_millis } => {
                        RepositoryFailure::Throttled { retry_after_millis }
                    },
                });
            }
        }
        #[cfg(not(feature = "test-support"))]
        let _point = point;
        Ok(())
    }
}
