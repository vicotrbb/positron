use super::*;

#[test]
fn committed_terminal_batch_replays_after_cold_reopen_and_rejects_changed_truth()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish(volume)?;
    let instance = InstanceId::new([0x91; 16])?;
    let catalog = open_export_catalog(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let binding = ExportOutputBinding::new(
        TenantId::from_bytes([0x41; 16])?,
        [0x94; 16],
        [0x95; 32],
        [0x96; 32],
        7,
        9,
        SnapshotLeaseId::new([0x97; 16])?,
        100,
        3700,
    )?;
    let mut output = ExportOutput::create(&catalog, binding)?;
    let reservation = output.reserve_next_batch(&catalog)?;
    let receipt = output.append_terminal_batch_reserved(
        &catalog,
        101,
        0,
        [0x98; 32],
        b"final-result",
        b"complete-terminal-truth",
        reservation,
    )?;
    let identity = output.identity();
    let payload = fs::read(payload_path(&root, identity))?;
    let terminal = fs::read(terminal_path(&root, identity))?;
    drop(catalog);
    let catalog = open_export_catalog(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let mut output = ExportOutput::reopen(&catalog, identity)?;
    let generation = catalog.pin()?.number();
    let reservation = output.reserve_next_batch(&catalog)?;
    assert_eq!(
        output.append_terminal_batch_reserved(
            &catalog,
            102,
            0,
            [0x98; 32],
            b"final-result",
            b"complete-terminal-truth",
            reservation
        )?,
        receipt
    );
    let reservation = output.reserve_next_batch(&catalog)?;
    assert!(
        matches!(output.append_terminal_batch_reserved(&catalog, 102, 0, [0x98; 32],
        b"final-result", b"different-terminal-truth", reservation),
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::IdempotencyConflict)
    );
    assert!(
        matches!(output.append_batch(&catalog, 102, 0, [0x98; 32], b"final-result", None),
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::IdempotencyConflict)
    );
    assert_eq!(output.latest_receipt(), Some(receipt));
    assert_eq!(output.batch_count(), 1);
    assert_eq!(output.read_batch(&catalog, 102, 0)?, b"final-result");
    assert_eq!(
        output.read_terminal_evidence(&catalog, 102)?.as_deref(),
        Some(b"complete-terminal-truth".as_slice())
    );
    assert_eq!(fs::read(payload_path(&root, identity))?, payload);
    assert_eq!(fs::read(terminal_path(&root, identity))?, terminal);
    assert_eq!(
        catalog.pin()?.number(),
        generation,
        "exact replay and refused conflicts must not publish another descriptor"
    );
    Ok(())
}

#[test]
fn empty_terminal_output_replays_after_reopen_and_preserves_manifest_after_expiry()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish(volume)?;
    let instance = InstanceId::new([0xa1; 16])?;
    let catalog = open_export_catalog(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let binding = ExportOutputBinding::new(
        TenantId::from_bytes([0x41; 16])?,
        [0xa4; 16],
        [0xa5; 32],
        [0xa6; 32],
        7,
        9,
        SnapshotLeaseId::new([0xa7; 16])?,
        100,
        3700,
    )?;
    let mut output = ExportOutput::create(&catalog, binding)?;
    output.write_terminal_evidence(&catalog, 101, b"empty-complete-terminal")?;
    output.write_manifest(&catalog, 101, b"signed-empty-manifest")?;
    let identity = output.identity();
    let terminal = fs::read(terminal_path(&root, identity))?;
    let manifest = fs::read(manifest_path(&root, identity))?;
    drop(catalog);
    let catalog = open_export_catalog(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let mut output = ExportOutput::reopen(&catalog, identity)?;
    let generation = catalog.pin()?.number();
    output.write_terminal_evidence(&catalog, 102, b"empty-complete-terminal")?;
    assert!(
        matches!(output.write_terminal_evidence(&catalog, 102, b"changed-empty-terminal"),
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::IdempotencyConflict)
    );
    assert_eq!(output.batch_count(), 0);
    assert_eq!(output.latest_receipt(), None);
    assert_eq!(output.latest_checkpoint(&catalog, 102)?, None);
    assert_eq!(
        output.read_terminal_evidence(&catalog, 102)?.as_deref(),
        Some(b"empty-complete-terminal".as_slice())
    );
    assert_eq!(
        output.read_manifest(&catalog, 3701)?.as_deref(),
        Some(b"signed-empty-manifest".as_slice())
    );
    assert!(
        matches!(output.write_terminal_evidence(&catalog, 3701, b"empty-complete-terminal"),
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::Expired)
    );
    assert_eq!(fs::read(terminal_path(&root, identity))?, terminal);
    assert_eq!(fs::read(manifest_path(&root, identity))?, manifest);
    assert_eq!(catalog.pin()?.number(), generation);
    Ok(())
}
