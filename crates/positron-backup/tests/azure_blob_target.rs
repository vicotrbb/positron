use positron_backup::{AzureBlobTarget, RepositoryFailure, RepositoryIdentity};
#[test]
fn exact_native_azure_target_is_bounded_and_redacted() {
    let target =
        AzureBlobTarget::new("positronbackup", "backups", "instance/owned/").expect("target");
    assert_eq!(target.api_version(), "2023-11-03");
    assert_eq!(
        AzureBlobTarget::decode_locator(&target.encode_locator()),
        Ok(target.clone())
    );
    let identity =
        RepositoryIdentity::azure_blob([1; 16], [2; 16], [3; 32], &target).expect("identity");
    assert_eq!(identity.provider_kind(), "azureBlob");
    assert!(!format!("{target:?}").contains("positronbackup"));
    for (account, container, prefix) in [
        ("bad.account", "backups", "owned/"),
        ("Account", "backups", "owned/"),
        ("okaccount", "Bad", "owned/"),
        ("okaccount", "bad--name", "owned/"),
        ("okaccount", "backups", "../owned/"),
        ("okaccount", "backups", "owned//"),
    ] {
        assert_eq!(
            AzureBlobTarget::new(account, container, prefix).err(),
            Some(RepositoryFailure::InvalidInput)
        );
    }
}
