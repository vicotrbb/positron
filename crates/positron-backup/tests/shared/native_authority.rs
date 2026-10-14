//! Real native qualifications use the existing Kernel admission owner.
use positron_kernel::*;
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
pub fn authority(
    path: &std::path::Path,
    maintenance: ResourceAmounts,
) -> TestResult<StorageKernelResourceAuthority> {
    let volume = PrimaryDataVolume::acquire(path, MountQualification::LocalHost)?;
    let one = ResourceAmounts::new([1; 11]);
    let two = ResourceAmounts::new([2; 11]);
    let three = ResourceAmounts::new([3; 11]);
    // This published Kernel peak covers Catalog open/recovery and replacement
    // publication. One extra unit preserves system and single-tenant recovery
    // progress required by the Governor. Both Repair and DurabilityCompletion
    // use this peak; the other five protected pools total nine units.
    let claim = integrity_scrub_resource_claim();
    let durability = ResourceAmounts::new(
        ResourceDimension::ALL.map(|dimension| claim.get(dimension).max(1) + 1),
    );
    let recovery = ResourceAmounts::new(
        ResourceDimension::ALL.map(|dimension| 2 * durability.get(dimension) + 9),
    );
    let pool = ResourceAmounts::new([
        536_870_912,
        128,
        32,
        100,
        128,
        32,
        128,
        128,
        128,
        128,
        1_048_576,
    ]);
    let cardinality = InventoryCardinalityLimits::new(1, 8)?;
    let overhead = cardinality.governor_bootstrap_overhead(1)?;
    let registered = [
        ResourceDimension::QueueSlots,
        ResourceDimension::TaskSlots,
        ResourceDimension::BufferCacheBytes,
        ResourceDimension::BatchItems,
        ResourceDimension::LeaseSlots,
        ResourceDimension::RetrySlots,
        ResourceDimension::IoPermits,
    ]
    .map(|dimension| {
        recovery.get(dimension)
            + pool.get(dimension)
            + maintenance.get(dimension).max(1)
            + 4
            + overhead.get(dimension)
    });
    let observed =
        ObservedResourceEnvironment::observe(&volume, RegisteredResourceBounds::new(registered)?)?;
    let detected = observed.detected_capacity();
    let capacity =
        ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| detected.amount(dimension)));
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(capacity)?,
        RecoveryReserve::new(recovery)?,
        cardinality,
        DiskPressureThresholds::new(disk / 10, disk / 5, disk / 3, disk / 2)?,
    )
    .map_err(|e| format!("qualification inventory: {e:?}"))?;
    // Qualification executes only instance-owned work; no synthetic tenant
    // partition may consume the Catalog's protected system recovery capacity.
    let policy = GovernorPolicy::system_only(OrdinaryPoolPolicy::new(
        pool,
        two,
        one,
        ResourceAmounts::new(ResourceDimension::ALL.map(|d| maintenance.get(d).max(1))),
    )?);
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        ResourceGovernorConfiguration::new(
            inventory,
            policy,
            RecoveryPoolCapacities::new(durability, two, three, two, durability, one, one)
                .map_err(|e| format!("qualification recovery pools: {e:?}"))?,
        )
        .map_err(|e| format!("qualification governor configuration: {e:?}"))?,
    )
    .map_err(|e| format!("qualification authority: {e:?}"))?)
}
