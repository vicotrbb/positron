//! Backup format claims remain independent of the captured persistent Catalog epoch.
use positron_backup::{
    BackupCatalogIdentity, BackupFormatEpoch, BackupManifest, BackupObject, BackupRetention,
    RepositoryIdentity,
};
#[test]
fn native_backup_format_is_independent_of_the_captured_catalog_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir();
    let repository = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &root)?;
    for catalog_epoch in [1, 2] {
        let catalog = BackupCatalogIdentity::new(1, [4; 32], catalog_epoch, 1, [5; 32])?;
        let legacy = BackupManifest::new(
            [6; 16],
            repository.clone(),
            catalog,
            BackupRetention::new(1, 2)?,
            [7; 32],
            vec![BackupObject::new([5; 32], 1, 0, [8; 32], 1)?],
        )?;
        assert_eq!(legacy.format_epoch(), catalog_epoch);
        assert_eq!(
            legacy.backup_format_epoch(),
            BackupFormatEpoch::LegacyPublication
        );
        assert!(
            !legacy
                .backup_format_epoch()
                .supports_independent_verification()
        );
        let catalog = catalog.with_capture_binding([9; 16], [10; 32])?;
        let captured = BackupManifest::new(
            [6; 16],
            repository.clone(),
            catalog,
            BackupRetention::new(1, 2)?,
            [7; 32],
            vec![BackupObject::new([5; 32], 1, 0, [8; 32], 1)?],
        )?;
        assert_eq!(captured.format_epoch(), catalog_epoch);
        assert_eq!(
            captured.backup_format_epoch(),
            BackupFormatEpoch::NATIVE_WRITER
        );
        assert!(
            captured
                .backup_format_epoch()
                .supports_independent_verification()
        );
    }
    assert_eq!(BackupFormatEpoch::from_value(99), None);
    Ok(())
}
