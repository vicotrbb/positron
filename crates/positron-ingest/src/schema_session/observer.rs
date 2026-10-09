use std::cell::Cell;

use positron_kernel::AppendCancellation;
use positron_signals::{ScanCancellation, ScanObservationFailureCode, ScanObserver};

pub(crate) struct SchemaBuildObserver<'a> {
    limit: Cell<u64>,
    consumed: Cell<u64>,
    cancellation: Option<CancellationRef<'a>>,
}

enum CancellationRef<'a> {
    Append(&'a AppendCancellation),
    Scan(&'a dyn ScanCancellation),
}

impl<'a> SchemaBuildObserver<'a> {
    pub(crate) fn new(limit: u64, cancellation: Option<&'a AppendCancellation>) -> Self {
        Self {
            limit: Cell::new(limit),
            consumed: Cell::new(0),
            cancellation: cancellation.map(CancellationRef::Append),
        }
    }

    pub(crate) const fn new_scan(limit: u64, cancellation: &'a dyn ScanCancellation) -> Self {
        Self {
            limit: Cell::new(limit),
            consumed: Cell::new(0),
            cancellation: Some(CancellationRef::Scan(cancellation)),
        }
    }

    #[cfg(test)]
    pub(crate) const fn consumed(&self) -> u64 {
        self.consumed.get()
    }

    pub(crate) fn increase_limit(&self, additional: u64) -> Result<(), ScanObservationFailureCode> {
        let limit = self
            .limit
            .get()
            .checked_add(additional)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        self.limit.set(limit);
        Ok(())
    }
}

impl ScanObserver for SchemaBuildObserver<'_> {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let cancelled = match self.cancellation {
            Some(CancellationRef::Append(cancellation)) => cancellation.is_cancelled(),
            Some(CancellationRef::Scan(cancellation)) => cancellation.is_cancelled(),
            None => false,
        };
        if cancelled {
            return Err(ScanObservationFailureCode::Cancelled);
        }
        let consumed = self
            .consumed
            .get()
            .checked_add(units)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        if consumed > self.limit.get() {
            Err(ScanObservationFailureCode::BudgetExhausted)
        } else {
            self.consumed.set(consumed);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Cancellation(AtomicBool);

    impl ScanCancellation for Cancellation {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn cumulative_work_is_preserved_when_a_decoded_delta_extends_the_bound() {
        let cancellation = Cancellation(AtomicBool::new(false));
        let observer = SchemaBuildObserver::new_scan(33, &cancellation);
        assert_eq!(observer.observe_work(32), Ok(()));
        assert_eq!(observer.increase_limit(2), Ok(()));
        assert_eq!(observer.observe_work(3), Ok(()));
        assert_eq!(observer.consumed(), 35);
        assert_eq!(
            observer.observe_work(1),
            Err(ScanObservationFailureCode::BudgetExhausted)
        );
        assert_eq!(observer.consumed(), 35);
        cancellation.0.store(true, Ordering::Relaxed);
        assert_eq!(
            observer.observe_work(0),
            Err(ScanObservationFailureCode::Cancelled)
        );
    }

    #[test]
    fn cumulative_work_and_ceiling_overflow_fail_closed() {
        let cancellation = Cancellation(AtomicBool::new(false));
        let observer = SchemaBuildObserver::new_scan(u64::MAX, &cancellation);
        assert_eq!(
            observer.increase_limit(1),
            Err(ScanObservationFailureCode::BudgetExhausted)
        );
        assert_eq!(observer.observe_work(u64::MAX), Ok(()));
        assert_eq!(
            observer.observe_work(1),
            Err(ScanObservationFailureCode::BudgetExhausted)
        );
        assert_eq!(observer.consumed(), u64::MAX);
    }
}
