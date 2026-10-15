//! One bounded, owner-scoped diagnostic schedule shared by native adapters.
use crate::RepositoryFailure;
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultEffect {
    Interrupted,
    OutcomeUnknown,
    Throttled { retry_after_millis: u32 },
}
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fault<P> {
    point: P,
    effect: FaultEffect,
    remaining: u32,
}
#[cfg(feature = "test-support")]
impl<P> Fault<P> {
    pub const fn new(point: P, effect: FaultEffect, preceding_occurrences: u32) -> Self {
        Self {
            point,
            effect,
            remaining: preceding_occurrences,
        }
    }
}
#[derive(Clone)]
pub(crate) struct Controller<P> {
    #[cfg(feature = "test-support")]
    schedule: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<Fault<P>>>>,
    point: std::marker::PhantomData<fn() -> P>,
}
impl<P> Default for Controller<P> {
    fn default() -> Self {
        Self {
            #[cfg(feature = "test-support")]
            schedule: Default::default(),
            point: std::marker::PhantomData,
        }
    }
}
impl<P: Eq> Controller<P> {
    #[cfg(feature = "test-support")]
    pub(crate) fn new(schedule: Vec<Fault<P>>) -> Result<Self, RepositoryFailure> {
        if schedule.len() > 32 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        Ok(Self {
            schedule: std::sync::Arc::new(std::sync::Mutex::new(schedule.into())),
            point: std::marker::PhantomData,
        })
    }
    pub(crate) fn at(&self, point: P) -> Result<(), RepositoryFailure> {
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
                    FaultEffect::Interrupted => RepositoryFailure::Interrupted,
                    FaultEffect::OutcomeUnknown => RepositoryFailure::OutcomeUnknown,
                    FaultEffect::Throttled { retry_after_millis } => {
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
