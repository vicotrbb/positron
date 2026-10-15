use positron_kernel::*;
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
/// Run a native protocol integration case through persisted Maintenance admission.
pub async fn admitted<F, Fut>(required: ResourceAmounts, case: F) -> TestResult<()>
where
    F: FnOnce(std::sync::Arc<NativeAwsResources>) -> Fut,
    Fut: std::future::Future<Output = TestResult<()>>,
{
    let directory = tempfile::tempdir()?;
    let mut amounts = ResourceDimension::ALL.map(|d| required.get(d));
    if let Some(value) = amounts.get_mut(4) {
        *value = 1;
    }
    if let Some(value) = amounts.get_mut(10) {
        *value = 16384;
    }
    let peak = ResourceAmounts::new(amounts);
    let authority = super::native_authority::authority(directory.path(), peak)?;
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
