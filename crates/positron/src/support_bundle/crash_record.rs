//! Binary adapter for the kernel-owned crash store.

#[cfg(test)]
use positron_kernel::MountQualification;
#[cfg(test)]
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
#[cfg(test)]
use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime},
};

#[allow(dead_code)]
pub(crate) type SanitizedCrashRecord = positron_kernel::CrashRecord;

#[cfg(test)]
pub(crate) struct CrashRecordStore {
    store: positron_kernel::CrashRecordStore,
}

#[cfg(test)]
impl CrashRecordStore {
    pub(crate) fn under_test_root(root: &Path) -> Result<Self, ()> {
        let data = data_directory(root);
        let secrets = root.join("secrets");
        fs::create_dir_all(&data).map_err(|_| ())?;
        fs::create_dir_all(&secrets).map_err(|_| ())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).map_err(|_| ())?;
        }
        let paths =
            BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost).map_err(|_| ())?;
        drop(
            InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
                .map_err(|_| ())?,
        );
        let instance = InstanceBootstrap::reopen(&paths).map_err(|_| ())?;
        let store = instance.crash_records().map_err(|_| ())?;
        Ok(Self { store })
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

#[cfg(test)]
pub(crate) fn data_directory(root: &Path) -> std::path::PathBuf {
    root.join("data")
}
