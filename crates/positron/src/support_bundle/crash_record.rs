//! Binary adapter for the kernel-owned crash store.

#[cfg(test)]
use std::{
    path::Path,
    time::{Duration, SystemTime},
};

#[allow(dead_code)]
pub(crate) type SanitizedCrashRecord = positron_kernel::CrashRecord;

#[cfg(test)]
pub(crate) struct CrashRecordStore {
    _volume: positron_kernel::OwnedPrimaryDataVolume,
    store: positron_kernel::CrashRecordStore,
}

#[cfg(test)]
impl CrashRecordStore {
    pub(crate) fn under_data_directory(path: &Path) -> Result<Self, ()> {
        let volume = positron_kernel::PrimaryDataVolume::acquire(
            path,
            positron_kernel::MountQualification::LocalHost,
        )
        .map_err(|_| ())?;
        let store = positron_kernel::CrashRecordStore::from_volume(&volume).map_err(|_| ())?;
        Ok(Self {
            _volume: volume,
            store,
        })
    }
    #[allow(dead_code)]
    pub(crate) fn persist(&self, record: &SanitizedCrashRecord) -> Result<(), ()> {
        self.store.persist(record).map_err(|_| ())
    }
    pub(crate) fn read_recent(
        &self,
        window: Duration,
        maximum_files: usize,
        maximum_bytes: usize,
        now: SystemTime,
    ) -> Result<positron_kernel::CrashReadout, ()> {
        self.store
            .read_recent(window, maximum_files, maximum_bytes, now)
            .map_err(|_| ())
    }
}
