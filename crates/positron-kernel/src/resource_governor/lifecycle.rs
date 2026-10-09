//! Bounded lifecycle and shutdown reconciliation.

use super::accounting::{AccountingSnapshot, GovernorInner};
use super::failure::GovernorFailure;
use super::model::ResourceDimension;
use super::policy::OrdinaryPool;
use super::{DiskPressureState, WorkClass};

/// Single authoritative governor lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernorLifecycle {
    Open,
    ShuttingDown,
    Fenced,
}

/// The accounting lock and read-only contention diagnostics share this one
/// lifecycle value. Transitions remain serialized by the accounting lock.
#[derive(Clone, Debug)]
pub(super) struct LifecycleState(std::sync::Arc<std::sync::atomic::AtomicU8>);

impl LifecycleState {
    pub(super) fn new() -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)))
    }
    pub(super) fn get(&self) -> GovernorLifecycle {
        match self.0.load(std::sync::atomic::Ordering::Acquire) {
            0 => GovernorLifecycle::Open,
            1 => GovernorLifecycle::ShuttingDown,
            _ => GovernorLifecycle::Fenced,
        }
    }
    pub(super) fn set(&self, lifecycle: GovernorLifecycle) {
        let value = match lifecycle {
            GovernorLifecycle::Open => 0,
            GovernorLifecycle::ShuttingDown => 1,
            GovernorLifecycle::Fenced => 2,
        };
        self.0.store(value, std::sync::atomic::Ordering::Release);
    }
}

impl super::ResourceGovernor<'_> {
    /// Reads the single canonical lifecycle without waiting for control work.
    /// A pending fence or poisoned accounting lock is already unavailable.
    #[must_use]
    pub fn lifecycle(&self) -> GovernorLifecycle {
        if self.inner.state.is_poisoned()
            || self
                .inner
                .drop_ledger
                .pending_fence
                .load(std::sync::atomic::Ordering::Acquire)
        {
            GovernorLifecycle::Fenced
        } else {
            self.inner.lifecycle.get()
        }
    }
}

/// Exact result of an explicit release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseOutcome {
    Released,
    AlreadyInactive,
}

/// Fixed-cardinality shutdown reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownReconciliation {
    pub(super) snapshot: super::ResourceSnapshot,
}

macro_rules! reconciliation_accessors {
    () => {
        #[must_use]
        pub const fn lifecycle(self) -> GovernorLifecycle {
            self.snapshot.lifecycle()
        }

        #[must_use]
        pub const fn outstanding_total(self) -> u32 {
            self.snapshot.outstanding_total()
        }

        #[must_use]
        pub const fn outstanding_ordinary(self) -> u32 {
            self.snapshot.outstanding_ordinary()
        }

        #[must_use]
        pub const fn outstanding_recovery(self) -> u32 {
            self.snapshot.outstanding_recovery()
        }

        #[must_use]
        pub const fn outstanding_uninterruptible(self) -> u32 {
            self.snapshot.outstanding_uninterruptible()
        }

        #[must_use]
        pub const fn outstanding_for(self, class: WorkClass) -> u32 {
            self.snapshot.outstanding_for(class)
        }

        #[must_use]
        pub const fn maximum_outstanding(self) -> u32 {
            self.snapshot.maximum_outstanding_reservations()
        }

        #[must_use]
        pub const fn rejection_count(self) -> u64 {
            self.snapshot.rejection_count()
        }

        #[must_use]
        pub const fn rejection_count_for(self, reason: super::AdmissionFailureCode) -> u64 {
            self.snapshot.rejection_count_for(reason)
        }

        #[must_use]
        pub const fn throttle_count_for(self, reason: super::AdmissionFailureCode) -> u64 {
            self.snapshot.throttle_count_for(reason)
        }

        #[must_use]
        pub const fn complete(self) -> bool {
            self.snapshot.complete()
        }

        #[must_use]
        pub const fn usage(self, dimension: ResourceDimension) -> u64 {
            self.snapshot.usage(dimension)
        }

        #[must_use]
        pub const fn reserve_consumption(self, dimension: ResourceDimension) -> u64 {
            self.snapshot.reserve_consumption(dimension)
        }

        #[must_use]
        pub const fn pool_capacity(self, pool: OrdinaryPool, dimension: ResourceDimension) -> u64 {
            self.snapshot.pool_capacity(pool, dimension)
        }

        #[must_use]
        pub const fn pool_usage(self, pool: OrdinaryPool, dimension: ResourceDimension) -> u64 {
            self.snapshot.pool_usage(pool, dimension)
        }

        #[must_use]
        pub const fn disk_pressure(self) -> DiskPressureState {
            self.snapshot.disk_pressure()
        }

        #[must_use]
        pub const fn pressure_transition_count(self) -> u64 {
            self.snapshot.pressure_transition_count()
        }

        #[must_use]
        pub const fn effective_capacity(self, dimension: ResourceDimension) -> u64 {
            self.snapshot.effective_capacity(dimension)
        }

        #[must_use]
        pub const fn ordinary_capacity(self, dimension: ResourceDimension) -> u64 {
            self.snapshot.ordinary_capacity(dimension)
        }

        #[must_use]
        pub const fn recovery_reserve_capacity(self, dimension: ResourceDimension) -> u64 {
            self.snapshot.recovery_reserve_capacity(dimension)
        }

        #[must_use]
        pub const fn usable_disk_bytes(self) -> u64 {
            self.snapshot.usable_disk_bytes()
        }
    };
}

impl ShutdownReconciliation {
    reconciliation_accessors!();
}

impl GovernorInner {
    pub(super) fn begin_shutdown(&self) -> Result<AccountingSnapshot, GovernorFailure> {
        let state = self.try_lock_for_control()?;
        match state.lifecycle.get() {
            GovernorLifecycle::Open => state.lifecycle.set(GovernorLifecycle::ShuttingDown),
            GovernorLifecycle::ShuttingDown => {},
            GovernorLifecycle::Fenced => return Err(GovernorFailure::InternalFenced),
        }
        self.snapshot_from(&state)
    }
}

pub(super) const fn class_index(class: WorkClass) -> usize {
    match class {
        WorkClass::DurabilityRecovery => 0,
        WorkClass::SecurityLifecycle => 1,
        WorkClass::Ingest => 2,
        WorkClass::InteractiveQueryTail => 3,
        WorkClass::OrdinaryMaintenanceBackup => 4,
    }
}

pub(super) const WORK_CLASS_COUNT: u32 = 5;

pub(super) fn empty_class_counts() -> [u32; 5] {
    [0; 5]
}
