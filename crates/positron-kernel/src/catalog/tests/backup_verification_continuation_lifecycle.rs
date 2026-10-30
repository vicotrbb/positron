use super::*;

pub(super) struct Fixture<'a, 'authority> {
    pub catalog: Catalog<'authority>,
    pub authority: &'authority StorageKernelResourceAuthority,
    pub instance: InstanceId,
    pub coordinator: &'a MaintenanceCoordinator,
    pub execution: &'a mut MaintenanceExecution<'authority>,
    pub owner: RepositoryOperationBinding,
    pub binding: BackupVerificationBinding,
    pub index: &'a [u8],
    pub progress: &'a BackupVerificationProgress,
}

fn publish(
    fixture: &mut Fixture<'_, '_>,
    reference: BackupVerificationReference,
) -> Result<(), Box<dyn std::error::Error>> {
    let (sequence, _) = fixture
        .owner
        .current_backup_progress(fixture.coordinator, fixture.execution)
        .map_err(|failure| format!("current: {failure:?}"))?;
    fixture
        .execution
        .checkpoint_and_persist(
            fixture.coordinator,
            &fixture.catalog,
            fixture
                .owner
                .backup_verification_checkpoint(
                    sequence.checked_add(1).ok_or("sequence")?,
                    b"existing handler progress",
                    reference,
                )
                .map_err(|failure| format!("checkpoint: {failure:?}"))?,
        )
        .map_err(|failure| format!("publish: {failure:?}"))?;
    Ok(())
}

pub(super) fn check<'authority>(
    mut fixture: Fixture<'_, 'authority>,
    mut current: BackupVerificationReference,
) -> Result<Catalog<'authority>, Box<dyn std::error::Error>> {
    for _ in 0..4 {
        publish(&mut fixture, current)?;
        let stale = current;
        current = fixture.catalog.persist_backup_verification_continuation(
            fixture.coordinator,
            fixture.execution,
            fixture.binding,
            Some(current),
            fixture.index,
            fixture.progress,
        )?;
        publish(&mut fixture, current)?;
        assert!(
            fixture
                .catalog
                .persist_backup_verification_continuation(
                    fixture.coordinator,
                    fixture.execution,
                    fixture.binding,
                    Some(stale),
                    fixture.index,
                    fixture.progress
                )
                .is_err(),
            "an older same-owner reference cannot prune the current checkpoint artifact"
        );
        assert!(
            fixture
                .catalog
                .resume_backup_verification_continuation(
                    fixture.binding,
                    current,
                    fixture.index,
                    fixture.execution.task().reservations()
                )
                .is_ok()
        );
        assert!(
            generation_count(&fixture.catalog, fixture.binding.operation)? <= 2,
            "committed progress cannot retain cumulative full-state generations"
        );
    }
    let candidate = fixture.catalog.persist_backup_verification_continuation(
        fixture.coordinator,
        fixture.execution,
        fixture.binding,
        Some(current),
        fixture.index,
        fixture.progress,
    )?;
    let (sequence, _) = fixture
        .owner
        .current_backup_progress(fixture.coordinator, fixture.execution)
        .map_err(|failure| format!("current: {failure:?}"))?;
    let proposed = fixture
        .owner
        .backup_verification_checkpoint(
            sequence.checked_add(1).ok_or("sequence")?,
            b"existing handler progress",
            candidate,
        )
        .map_err(|failure| format!("checkpoint: {failure:?}"))?;
    let failed = with_catalog_publication_fault_after(
        CatalogPublicationFault::PartialObjectWrite,
        0,
        || {
            fixture.execution.checkpoint_and_persist(
                fixture.coordinator,
                &fixture.catalog,
                proposed,
            )
        },
    );
    assert!(
        failed.is_err(),
        "the checkpoint publication fault must be exercised"
    );
    assert!(
        fixture
            .catalog
            .resume_backup_verification_continuation(
                fixture.binding,
                current,
                fixture.index,
                fixture.execution.task().reservations()
            )
            .is_ok(),
        "failed checkpoint publication retains its exact predecessor"
    );
    drop(fixture.catalog);
    fixture.catalog = Catalog::open(
        fixture.authority,
        fixture.instance,
        CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32])),
    )?;
    assert_eq!(
        fixture
            .owner
            .current_backup_verification_reference(fixture.coordinator, fixture.execution)
            .map_err(|failure| format!("reference: {failure:?}"))?,
        Some(current)
    );
    let (sequence, _) = fixture
        .owner
        .current_backup_progress(fixture.coordinator, fixture.execution)
        .map_err(|failure| format!("current: {failure:?}"))?;
    fixture
        .execution
        .checkpoint_and_persist(
            fixture.coordinator,
            &fixture.catalog,
            fixture
                .owner
                .backup_checkpoint(
                    sequence.checked_add(1).ok_or("sequence")?,
                    b"terminal cleanup",
                )
                .map_err(|failure| format!("cleanup checkpoint: {failure:?}"))?,
        )
        .map_err(|failure| format!("cleanup publication: {failure:?}"))?;
    for value in 1..=40 {
        let mut file = continuation_file(
            &fixture.catalog,
            fixture.binding.operation,
            [value; 32],
            true,
        )?;
        std::io::Write::write_all(&mut file, b"unreferenced prepared output")?;
    }
    assert!(
        !fixture.catalog.release_backup_verification_continuation(
            fixture.coordinator,
            fixture.execution,
            fixture.owner
        )?,
        "one cleanup turn removes at most 32 files"
    );
    assert!(fixture.catalog.has_backup_capture_references()?);
    assert!(
        ActiveSegmentLedger::guard_local_root_retirement(fixture.authority, &fixture.catalog)
            .is_err()
    );
    for turn in 0..3 {
        if fixture.catalog.release_backup_verification_continuation(
            fixture.coordinator,
            fixture.execution,
            fixture.owner,
        )? {
            assert!(fixture.catalog.release_backup_verification_continuation(
                fixture.coordinator,
                fixture.execution,
                fixture.owner
            )?);
            fixture
                .execution
                .complete_and_persist(fixture.coordinator, &fixture.catalog, true)
                .map_err(|failure| format!("complete cleaned owner: {failure:?}"))?;
            return Ok(fixture.catalog);
        }
        assert!(
            turn < 2,
            "bounded local terminal cleanup must converge without a repository"
        );
    }
    Err("cleanup did not finish".into())
}

pub(super) fn generation_count(
    catalog: &Catalog<'_>,
    operation: [u8; 16],
) -> Result<usize, Box<dyn std::error::Error>> {
    let name = operation
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path = format!("backup-captures/{name}");
    let directory = std::fs::File::from(rustix::fs::openat(
        catalog.export_output_root()?,
        path.as_str(),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?);
    let mut entries = rustix::fs::Dir::read_from(&directory)?;
    let mut count = 0;
    while let Some(entry) = entries.read() {
        if entry?.file_name().to_bytes().starts_with(b"f-") {
            count += 1;
        }
    }
    Ok(count)
}
