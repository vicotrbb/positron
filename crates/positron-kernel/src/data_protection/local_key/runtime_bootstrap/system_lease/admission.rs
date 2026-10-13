//! No custody lock is held during live provider revalidation.
use super::*;
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum KeyAdmission {
    Data,
    Control,
    Confirmation,
}

impl SystemLease {
    pub(in crate::data_protection::local_key::runtime_bootstrap) fn system_key(
        owner: &Arc<Mutex<Self>>,
        instance: InstanceId,
    ) -> Result<SecretKeyBytes, BootstrapKeyFailure> {
        Self::admit_key(owner, instance, KeyAdmission::Data)
    }
    pub(super) fn admit_key(
        owner: &Arc<Mutex<Self>>,
        instance: InstanceId,
        use_kind: KeyAdmission,
    ) -> Result<SecretKeyBytes, BootstrapKeyFailure> {
        let (mut cache, context, envelope, identity, epoch, revision, notification) = {
            let mut lease = owner.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
            if lease.context.instance != instance.to_bytes() {
                return Err(BootstrapKeyFailure::Authentication);
            }
            if lease.admission == LeaseAdmission::Closed
                || use_kind == KeyAdmission::Data && lease.admission != LeaseAdmission::Ready
            {
                return Err(BootstrapKeyFailure::Custody);
            }
            let initial_revision = lease.revision;
            let available = Arc::clone(&lease.available);
            // Existing caller reservations bound concurrent admissions. Waiting
            // releases custody's mutex and has the native receipt's finite bound.
            let deadline = std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(20))
                .ok_or(BootstrapKeyFailure::LimitExceeded)?;
            while lease.cache.is_none() {
                #[cfg(any(test, feature = "test-support"))]
                admission_action();
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(BootstrapKeyFailure::Custody);
                }
                let (current, _) = available
                    .wait_timeout(lease, remaining)
                    .map_err(|_| BootstrapKeyFailure::Custody)?;
                lease = current;
                if lease.revision != initial_revision
                    || lease.admission == LeaseAdmission::Closed
                    || use_kind == KeyAdmission::Data && lease.admission != LeaseAdmission::Ready
                {
                    return Err(BootstrapKeyFailure::Custody);
                }
            }
            let cache = lease.cache.take().ok_or(BootstrapKeyFailure::Custody)?;
            (
                cache,
                lease.context,
                lease.envelope.clone(),
                lease.identity,
                lease.epoch,
                lease.revision,
                available,
            )
        };
        struct NotifyOnDrop(Arc<std::sync::Condvar>);
        impl Drop for NotifyOnDrop {
            fn drop(&mut self) {
                self.0.notify_all();
            }
        }
        let _notification = NotifyOnDrop(notification);
        #[cfg(any(test, feature = "test-support"))]
        admission_action();
        let result = cache
            .custody_system_key(&envelope, context)
            .map_err(|_| BootstrapKeyFailure::Custody);
        let mut lease = owner.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
        let same_route = lease.identity == identity
            && lease.epoch == epoch
            && lease.context == context
            && lease.envelope == envelope;
        if !same_route || lease.admission == LeaseAdmission::Closed || lease.cache.is_some() {
            return Err(BootstrapKeyFailure::Custody);
        }
        if lease.revision != revision {
            cache.invalidate(
                crate::key_provider::KeyScope::System,
                crate::key_provider::CacheInvalidation::Rotation,
            );
            lease.cache = Some(cache);
            return Err(BootstrapKeyFailure::Custody);
        }
        if use_kind == KeyAdmission::Control && lease.admission == LeaseAdmission::RotationUncertain
        {
            cache.invalidate(
                crate::key_provider::KeyScope::System,
                crate::key_provider::CacheInvalidation::Rotation,
            );
        }
        lease.cache = Some(cache);
        result
    }
}

#[cfg(any(test, feature = "test-support"))]
thread_local! { static ACTION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) }; }
#[cfg(any(test, feature = "test-support"))]
fn admission_action() {
    let action = ACTION.with(|action| action.borrow_mut().take());
    if let Some(action) = action {
        action();
    }
}
#[cfg(any(test, feature = "test-support"))]
impl crate::RootRewrapSession<'_> {
    pub fn with_key_admission_action<T>(
        action: impl FnOnce() + 'static,
        operation: impl FnOnce() -> T,
    ) -> T {
        struct Restore(Option<Box<dyn FnOnce()>>);
        impl Drop for Restore {
            fn drop(&mut self) {
                ACTION.with(|action| *action.borrow_mut() = self.0.take());
            }
        }
        let previous = ACTION.with(|slot| slot.borrow_mut().replace(Box::new(action)));
        let _restore = Restore(previous);
        operation()
    }
}
