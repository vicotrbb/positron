//! Real persisted Maintenance admission for Backup control integration tests.
#[path = "../shared/native_authority.rs"]
pub(super) mod native_authority;
use positron_kernel::*;
use std::sync::Arc;
/// Keeps the admitted task and authority alive for the entire test operation.
pub async fn admitted<F, Fut>(memory_bytes: u64, case: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(Arc<NativeAwsResources>) -> Fut,
    Fut: Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    let peak = ResourceAmounts::new([memory_bytes, 1, 1, 0, 1, 0, 1, 1, 1, 8, 16384]);
    let directory = TemporaryDirectory::new()?;
    let authority = native_authority::authority(directory.path(), peak)?;
    let instance = InstanceId::new([2; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([202; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"native repository fixture".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RepositoryOperationBinding::new([203; 16], [204; 32]).map_err(|_| "binding")?;
    coordinator
        .submit_repository_operation_with_resources_and_persist(
            &catalog,
            binding,
            MaintenancePreconditions::new(catalog.pin()?.number(), 1)
                .map_err(|_| "preconditions")?,
            peak,
            1,
        )
        .map_err(|_| "submission")?;
    let mut execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            2,
            false,
            Some(MaintenanceTaskClass::RepositoryVerification),
        )
        .map_err(|_| "dispatch")?
        .ok_or("admission")?;
    let resources = execution
        .transfer_repository_resources(binding)
        .map_err(|_| "handoff")?;
    let result = case(resources).await;
    execution
        .complete_and_persist(&coordinator, &catalog, result.is_ok())
        .map_err(|_| "terminal publication")?;
    result
}
/// A real live grant of the wrong work kind must not authorize control I/O.
#[allow(dead_code)] // Shared helper; only the control-resource negative test needs this grant.
pub fn diagnostics<F>(case: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(&NativeAwsResources) -> Result<(), Box<dyn std::error::Error>>,
{
    let directory = TemporaryDirectory::new()?;
    let authority = native_authority::authority(directory.path(), ResourceAmounts::new([1; 11]))?;
    let reservation =
        authority
            .governor()
            .reserve(positron_kernel::WorkClaim::system_diagnostics(
                ResourceAmounts::new([1; 11]),
            )?)?;
    let resources = NativeAwsResources::new(reservation.transfer());
    case(&resources)
}

// Unlike the optional provider fixtures, snapshot tests also run without the
// test-support feature. Keep their temporary directory dependency-free.
struct TemporaryDirectory(std::path::PathBuf);
impl TemporaryDirectory {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "positron-snapshot-admission-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path)?;
        let directory = Self(path);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
