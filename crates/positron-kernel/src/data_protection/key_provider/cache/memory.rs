use super::{KeyProviderFailure, SecretKek, SecretKeyBytes};
use zeroize::Zeroize;
// Dedicated allocations keep independently evicted entries off shared pages.
// 64 KiB alignment covers the supported Unix/Windows page sizes. A larger or
// incompatible native page fails closed instead of silently weakening locking.
pub(super) const BLOCK_BYTES: usize = 65_536;
#[repr(align(65536))]
struct Block([u8; BLOCK_BYTES]);
pub(super) struct LockedKek {
    block: Box<Block>,
    lock: Option<region::LockGuard>,
}
impl LockedKek {
    pub(super) fn new(key: SecretKek) -> Result<Self, KeyProviderFailure> {
        #[cfg(test)]
        if LOCK_FAILURE.with(std::cell::Cell::get) {
            return Err(KeyProviderFailure::MemoryProtection);
        }
        let page = region::page::size();
        if page == 0 || !BLOCK_BYTES.is_multiple_of(page) {
            return Err(KeyProviderFailure::MemoryProtection);
        }
        let mut block = Box::new(Block([0; BLOCK_BYTES]));
        let lock = region::lock(block.0.as_ptr(), BLOCK_BYTES)
            .map_err(|_| KeyProviderFailure::MemoryProtection)?;
        block
            .0
            .get_mut(..32)
            .ok_or(KeyProviderFailure::MemoryProtection)?
            .copy_from_slice(key.0.expose_to_backend());
        Ok(Self {
            block,
            lock: Some(lock),
        })
    }
    pub(super) fn temporary_key(&self) -> Result<SecretKeyBytes, KeyProviderFailure> {
        let mut key = SecretKeyBytes::from_owned(Box::new([0; 32]));
        key.expose_to_backend_mut().copy_from_slice(
            self.block
                .0
                .get(..32)
                .ok_or(KeyProviderFailure::MemoryProtection)?,
        );
        Ok(key)
    }
}
impl Drop for LockedKek {
    fn drop(&mut self) {
        self.block.0.zeroize();
        #[cfg(test)]
        RELEASE.with(|state| {
            let (count, zeroized) = state.get();
            state.set((
                count + 1,
                zeroized && self.block.0.iter().all(|byte| *byte == 0),
            ));
        });
        drop(self.lock.take());
    }
}

#[cfg(test)]
thread_local! {
    static LOCK_FAILURE:std::cell::Cell<bool>=const {std::cell::Cell::new(false)};
    static RELEASE:std::cell::Cell<(usize,bool)>=const {std::cell::Cell::new((0,true))};
}
#[cfg(test)]
struct Reset {
    lock: bool,
    release: (usize, bool),
}
#[cfg(test)]
impl Drop for Reset {
    fn drop(&mut self) {
        LOCK_FAILURE.with(|state| state.set(self.lock));
        RELEASE.with(|state| state.set(self.release));
    }
}
#[cfg(test)]
pub(in crate::data_protection) fn with_cache_lock_failure<T>(operation: impl FnOnce() -> T) -> T {
    let _reset = Reset {
        lock: LOCK_FAILURE.with(|state| state.replace(true)),
        release: RELEASE.with(std::cell::Cell::get),
    };
    operation()
}
#[cfg(test)]
pub(in crate::data_protection) fn observe_cache_release<T>(
    operation: impl FnOnce() -> T,
) -> (T, usize, bool) {
    let _reset = Reset {
        lock: LOCK_FAILURE.with(std::cell::Cell::get),
        release: RELEASE.with(|state| state.replace((0, true))),
    };
    let value = operation();
    let (count, zeroized) = RELEASE.with(std::cell::Cell::get);
    (value, count, zeroized)
}
